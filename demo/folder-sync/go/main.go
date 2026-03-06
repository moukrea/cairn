// cairn-folder-sync: P2P folder synchronization demo (Go)
//
// Usage:
//
//	cairn-folder-sync --dir ./sync-folder --pair-qr
//	cairn-folder-sync --dir ./sync-folder --pair-pin
//	cairn-folder-sync --dir ./sync-folder --pair-link
//	cairn-folder-sync --dir ./sync-folder --enter-pin XXXX-XXXX
//	cairn-folder-sync --dir ./sync-folder --from-link <uri>
//	cairn-folder-sync --dir ./sync-folder --server-hub
//	cairn-folder-sync --verbose
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fsnotify/fsnotify"
	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

func main() {
	dir := flag.String("dir", ".", "Directory to synchronize")
	pairQR := flag.Bool("pair-qr", false, "Display QR code for pairing (initiator)")
	pairPin := flag.Bool("pair-pin", false, "Display PIN code for pairing (initiator)")
	pairLink := flag.Bool("pair-link", false, "Display pairing link URI (initiator)")
	enterPin := flag.String("enter-pin", "", "Enter PIN code (responder)")
	scanQR := flag.Bool("scan-qr", false, "Scan QR code (responder)")
	fromLink := flag.String("from-link", "", "Accept pairing link (responder)")
	mesh := flag.Bool("mesh", false, "Enable mesh routing for multi-device sync")
	serverHub := flag.Bool("server-hub", false, "Run as always-on sync hub")
	signal_ := flag.String("signal", "", "Signaling server URL")
	turn := flag.String("turn", "", "TURN relay URL")
	verbose := flag.Bool("verbose", false, "Enable structured logging")
	flag.Parse()

	_ = scanQR
	_ = signal_
	_ = turn

	if *verbose {
		fmt.Fprintln(os.Stderr, "Verbose logging enabled")
	}

	// Validate and create sync directory
	syncDir, err := filepath.Abs(*dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid directory: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(syncDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create sync directory: %v\n", err)
		os.Exit(1)
	}

	// Build options for cairn node
	var opts []cairn.Option
	if *mesh {
		opts = append(opts, cairn.WithMeshConfig(cairn.MeshConfig{
			Enabled:       true,
			MaxHops:       3,
			RelayWilling:  true,
			RelayCapacity: 10,
		}))
	}

	// Create cairn node
	var node *cairn.Node
	if *serverHub {
		node, err = cairn.CreateServer(opts...)
	} else {
		node, err = cairn.Create(opts...)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create node: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "cairn-folder-sync started. Watching: %s\n", syncDir)

	ctx := context.Background()

	// Determine pairing mechanism and pair
	var peerID cairn.PeerID
	if *pairQR {
		fmt.Fprintln(os.Stderr, "Generating QR code for pairing...")
		_, err := node.PairGenerateQR(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "QR generation failed: %v\n", err)
			os.Exit(1)
		}
		// Wait for pairing via events
		peerID = waitForPairing(node)
	} else if *pairPin {
		fmt.Fprintln(os.Stderr, "Generating PIN code...")
		pin, err := node.PairGeneratePin(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PIN generation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "PIN: %s\n", pin)
		peerID = waitForPairing(node)
	} else if *pairLink {
		fmt.Fprintln(os.Stderr, "Generating pairing link...")
		link, err := node.PairGenerateLink(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Link generation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Link: %s\n", link)
		peerID = waitForPairing(node)
	} else if *enterPin != "" {
		peerID, err = node.PairEnterPin(ctx, *enterPin)
		if err != nil {
			displayError(err)
			os.Exit(1)
		}
	} else if *fromLink != "" {
		peerID, err = node.PairFromLink(ctx, *fromLink)
		if err != nil {
			displayError(err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintln(os.Stderr, "No pairing method specified. Use --pair-qr, --pair-pin, or --pair-link")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Paired with: %s\n", peerID)

	session, err := node.Connect(ctx, peerID)
	if err != nil {
		displayError(err)
		os.Exit(1)
	}

	syncChannel, err := session.OpenChannel(ctx, "sync")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open sync channel: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Sync session established.")

	// Initialize sync state
	state := NewSyncState(syncDir, defaultChunkSize)

	// Initial directory scan
	localFiles, err := state.ScanDirectory()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to scan directory: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Found %d files to sync\n", len(localFiles))

	// Send file metadata to peer
	for _, meta := range localFiles {
		metaBytes, err := json.Marshal(meta)
		if err != nil {
			continue
		}
		if err := session.Send(ctx, syncChannel, metaBytes); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to send metadata: %v\n", err)
		}
	}

	// Create send helper
	sendFn := func(data []byte) error {
		return session.Send(ctx, syncChannel, data)
	}

	// Listen for incoming events in a goroutine
	go func() {
		for event := range node.Events() {
			switch ev := event.(type) {
			case cairn.MessageReceivedEvent:
				if ev.Channel == "sync" {
					if err := HandleSyncMessage(ev.Data, syncDir, state, sendFn); err != nil {
						fmt.Fprintf(os.Stderr, "Sync error: %v\n", err)
					}
				}
			case cairn.StateChangedEvent:
				fmt.Fprintf(os.Stderr, "--- Connection state: %v ---\n", ev.State)
			}
		}
	}()

	// Watch directory for changes
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create file watcher: %v\n", err)
		os.Exit(1)
	}
	defer watcher.Close()

	if err := addWatchRecursive(watcher, syncDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to watch directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Watching for changes... (Ctrl+C to stop)")

	// Handle file system events in a goroutine
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) == 0 {
					continue
				}

				relPath, err := filepath.Rel(syncDir, event.Name)
				if err != nil || strings.HasPrefix(filepath.Base(relPath), ".") {
					continue
				}

				info, err := os.Stat(event.Name)
				if err != nil || info.IsDir() {
					continue
				}

				fmt.Fprintf(os.Stderr, "[change] %s\n", relPath)
				meta := state.ComputeFileMeta(event.Name, syncDir)
				if meta != nil {
					metaBytes, err := json.Marshal(meta)
					if err == nil {
						if err := session.Send(ctx, syncChannel, metaBytes); err != nil {
							fmt.Fprintf(os.Stderr, "Failed to send change: %v\n", err)
						}
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Fprintf(os.Stderr, "Watcher error: %v\n", err)
			}
		}
	}()

	// Wait for interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Fprintln(os.Stderr, "\nShutting down...")
	session.Close()
	node.Close()
}

// waitForPairing blocks until a PairingCompleteEvent is received.
func waitForPairing(node *cairn.Node) cairn.PeerID {
	for event := range node.Events() {
		if ev, ok := event.(cairn.PairingCompleteEvent); ok {
			return ev.PeerID
		}
	}
	fmt.Fprintln(os.Stderr, "Pairing event channel closed unexpectedly")
	os.Exit(1)
	return cairn.PeerID{}
}

// addWatchRecursive adds a directory and all subdirectories to the watcher.
func addWatchRecursive(watcher *fsnotify.Watcher, dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if len(info.Name()) > 0 && info.Name()[0] == '.' && path != dir {
				return filepath.SkipDir
			}
			return watcher.Add(path)
		}
		return nil
	})
}

func displayError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	if strings.Contains(err.Error(), "TransportExhausted") {
		fmt.Fprintln(os.Stderr, "Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay to resolve.")
	}
}
