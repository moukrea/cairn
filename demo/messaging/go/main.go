// cairn-chat: P2P messaging demo (Go)
//
// Usage:
//   cairn-chat --pair-qr              Display QR code for pairing
//   cairn-chat --pair-pin             Display PIN code
//   cairn-chat --pair-link            Display pairing link URI
//   cairn-chat --enter-pin XXXX-XXXX  Enter PIN code
//   cairn-chat --from-link <uri>      Accept pairing link
//   cairn-chat --verbose              Enable structured logging
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	cairn "github.com/moukrea/cairn/packages/go/cairn-p2p"
)

func main() {
	pairQR := flag.Bool("pair-qr", false, "Display QR code for pairing (initiator)")
	pairPin := flag.Bool("pair-pin", false, "Display PIN code for pairing (initiator)")
	pairLink := flag.Bool("pair-link", false, "Display pairing link URI (initiator)")
	enterPin := flag.String("enter-pin", "", "Enter PIN code (responder)")
	fromLink := flag.String("from-link", "", "Accept pairing link (responder)")
	serverMode := flag.Bool("server-mode", false, "Run as server-mode peer")
	sendMsg := flag.String("send", "", "Send a message (non-interactive)")
	peerID := flag.String("peer", "", "Target peer ID for --send")
	forward := flag.Bool("forward", false, "Forward via server-mode peer")
	signal := flag.String("signal", "", "Signaling server URL")
	turn := flag.String("turn", "", "TURN relay URL")
	verbose := flag.Bool("verbose", false, "Enable structured logging")
	flag.Parse()

	_ = forward
	_ = signal
	_ = turn

	if *verbose {
		fmt.Fprintln(os.Stderr, "Verbose logging enabled")
	}

	// Initialize cairn node
	config := cairn.DefaultConfig()
	var node *cairn.Node
	var err error

	if *serverMode {
		node, err = cairn.CreateServer(config)
	} else {
		node, err = cairn.Create(config)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create node: %v\n", err)
		os.Exit(1)
	}

	if err := node.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start node: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "cairn-chat started. Peer ID: %s\n", node.PeerID())

	// Determine pairing mechanism
	var mechanism string
	if *pairQR {
		fmt.Fprintln(os.Stderr, "Generating QR code for pairing...")
		mechanism = "qr"
	} else if *pairPin {
		fmt.Fprintln(os.Stderr, "Generating PIN code...")
		mechanism = "pin"
	} else if *pairLink {
		fmt.Fprintln(os.Stderr, "Generating pairing link...")
		mechanism = "link"
	} else if *enterPin != "" {
		mechanism = "pin"
	} else if *fromLink != "" {
		mechanism = "link"
	} else {
		fmt.Fprintln(os.Stderr, "No pairing method specified. Use --pair-qr, --pair-pin, or --pair-link")
		os.Exit(1)
	}

	paired, err := node.Pair(mechanism)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Pairing failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Paired with: %s\n", paired)

	session, err := node.Connect(paired)
	if err != nil {
		displayError(err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Session established.")

	// Non-interactive send mode
	if *sendMsg != "" {
		if err := session.Send("chat", []byte(*sendMsg)); err != nil {
			fmt.Fprintf(os.Stderr, "Send failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[sent] %s\n", *sendMsg)
		session.Close()
		return
	}

	_ = peerID

	// Listen for incoming messages
	peerStatus := "online"
	go func() {
		for event := range node.Events() {
			switch event.Type {
			case "PeerDisconnected":
				peerStatus = "offline"
				fmt.Fprintln(os.Stderr, "--- Connection state: Disconnected ---")
			case "PeerConnected":
				peerStatus = "online"
				fmt.Fprintln(os.Stderr, "--- Connection state: Connected ---")
			case "MessageReceived":
				if event.Channel == "chat" {
					fmt.Printf("\r%s: %s\n", "peer", string(event.Data))
					displayPrompt(peerStatus)
				} else if event.Channel == "presence" {
					if string(event.Data) == "typing" {
						fmt.Print("\r[typing...] ")
					}
				}
			}
		}
	}()

	// Interactive chat loop
	displayPrompt(peerStatus)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			displayPrompt(peerStatus)
			continue
		}

		if line == "/quit" || line == "/exit" {
			break
		}

		if line == "/status" {
			fmt.Fprintf(os.Stderr, "Peer: %s | Connected: %v\n", paired, session.IsConnected())
			displayPrompt(peerStatus)
			continue
		}

		// Send typing indicator then message
		_ = session.Send("presence", []byte("typing"))
		if err := session.Send("chat", []byte(line)); err != nil {
			fmt.Fprintf(os.Stderr, "Send error: %v\n", err)
		}
		displayPrompt(peerStatus)
	}

	session.Close()
	node.Stop()
}

func displayPrompt(status string) {
	fmt.Printf("[%s] peer> ", status)
}

func displayError(err error) {
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	if strings.Contains(err.Error(), "TransportExhausted") {
		fmt.Fprintln(os.Stderr, "Hint: Both peers may be behind symmetric NATs. Deploy a TURN relay to resolve.")
	}
}
