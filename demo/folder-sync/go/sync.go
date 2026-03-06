package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	defaultChunkSize    = 65536 // 64 KB
	rollingHashWindow   = 64
	rollingHashModulus  = 65521
)

// FileMeta holds metadata for a file in the sync directory.
type FileMeta struct {
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	Modified     int64  `json:"modified"`
	Hash         string `json:"hash"`
	PeerIDPrefix string `json:"peer_id_prefix"`
}

// ChunkData holds a chunk of file data for transfer.
type ChunkData struct {
	FilePath   string `json:"file_path"`
	FileHash   string `json:"file_hash"`
	ChunkIndex int    `json:"chunk_index"`
	ChunkCount int    `json:"chunk_count"`
	ChunkDataB64 string `json:"chunk_data"`
}

// DeltaBlock holds a changed region for delta sync.
type DeltaBlock struct {
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	DataB64 string `json:"data"`
}

// SyncState tracks local file state and chunk reception progress.
type SyncState struct {
	mu            sync.Mutex
	syncDir       string
	files         map[string]*FileMeta
	chunkProgress map[string]int
	chunkSize     int
}

// NewSyncState creates a new SyncState.
func NewSyncState(syncDir string, chunkSize int) *SyncState {
	return &SyncState{
		syncDir:       syncDir,
		files:         make(map[string]*FileMeta),
		chunkProgress: make(map[string]int),
		chunkSize:     chunkSize,
	}
}

// ScanDirectory scans the sync directory and computes metadata for all files.
func (s *SyncState) ScanDirectory() ([]*FileMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.files = make(map[string]*FileMeta)
	var result []*FileMeta

	if _, err := os.Stat(s.syncDir); os.IsNotExist(err) {
		return result, nil
	}

	err := filepath.Walk(s.syncDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		name := info.Name()
		if len(name) > 0 && name[0] == '.' {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(s.syncDir, path)
		if err != nil {
			return err
		}

		hash, err := computeFileHash(path)
		if err != nil {
			return err
		}

		meta := &FileMeta{
			Path:     relPath,
			Size:     info.Size(),
			Modified: info.ModTime().Unix(),
			Hash:     hash,
		}
		s.files[relPath] = meta
		result = append(result, meta)
		return nil
	})

	return result, err
}

// ComputeFileMeta computes metadata for a single file.
func (s *SyncState) ComputeFileMeta(fullPath, baseDir string) *FileMeta {
	info, err := os.Stat(fullPath)
	if err != nil || info.IsDir() {
		return nil
	}

	relPath, err := filepath.Rel(baseDir, fullPath)
	if err != nil {
		return nil
	}

	hash, err := computeFileHash(fullPath)
	if err != nil {
		return nil
	}

	meta := &FileMeta{
		Path:     relPath,
		Size:     info.Size(),
		Modified: info.ModTime().Unix(),
		Hash:     hash,
	}

	s.mu.Lock()
	s.files[relPath] = meta
	s.mu.Unlock()

	return meta
}

// GetFileMeta returns metadata for a specific file.
func (s *SyncState) GetFileMeta(relPath string) *FileMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.files[relPath]
}

// LastReceivedChunk returns the last received chunk index for resume.
func (s *SyncState) LastReceivedChunk(relPath string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chunkProgress[relPath]
}

// RecordChunk records reception of a chunk.
func (s *SyncState) RecordChunk(relPath string, index int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chunkProgress[relPath] = index + 1
}

// MarkComplete marks a file as fully received.
func (s *SyncState) MarkComplete(relPath, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.chunkProgress, relPath)
	if meta, ok := s.files[relPath]; ok {
		meta.Hash = hash
	}
}

// SplitFile splits a file into chunks for transfer.
func (s *SyncState) SplitFile(fullPath, relPath string) ([]ChunkData, error) {
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, err
	}

	fileHash := computeHash(data)
	chunkCount := (len(data) + s.chunkSize - 1) / s.chunkSize
	if chunkCount == 0 {
		chunkCount = 1
	}

	chunks := make([]ChunkData, 0, chunkCount)
	for i := 0; i < chunkCount; i++ {
		start := i * s.chunkSize
		end := start + s.chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunks = append(chunks, ChunkData{
			FilePath:     relPath,
			FileHash:     fileHash,
			ChunkIndex:   i,
			ChunkCount:   chunkCount,
			ChunkDataB64: base64.StdEncoding.EncodeToString(data[start:end]),
		})
	}

	return chunks, nil
}

// WriteChunk writes a received chunk to disk.
func (s *SyncState) WriteChunk(destPath string, chunkIndex int, data []byte) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	offset := int64(chunkIndex) * int64(s.chunkSize)
	if _, err := f.WriteAt(data, offset); err != nil {
		return err
	}
	return nil
}

// ResolveConflictPath generates the conflict file path.
func ResolveConflictPath(relPath, peerIDPrefix string, timestamp int64) string {
	dir := filepath.Dir(relPath)
	base := filepath.Base(relPath)
	if peerIDPrefix == "" {
		peerIDPrefix = "unknown"
	}
	conflictName := fmt.Sprintf("%s.conflict.%s.%d", base, peerIDPrefix, timestamp)
	return filepath.Join(dir, conflictName)
}

// HandleSyncMessage processes an incoming sync message.
func HandleSyncMessage(data []byte, syncDir string, state *SyncState, sendFn func([]byte) error) error {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil // ignore non-JSON
	}

	// File metadata message (has "path", "hash", "size")
	if _, hasPath := msg["path"]; hasPath {
		if _, hasHash := msg["hash"]; hasHash {
			var meta FileMeta
			if err := json.Unmarshal(data, &meta); err != nil {
				return nil
			}

			fmt.Fprintf(os.Stderr, "[sync] Received metadata: %s (%d bytes)\n", meta.Path, meta.Size)

			localMeta := state.GetFileMeta(meta.Path)
			if localMeta != nil && localMeta.Hash != meta.Hash && localMeta.Modified != meta.Modified {
				conflictPath := ResolveConflictPath(meta.Path, meta.PeerIDPrefix, meta.Modified)
				fmt.Fprintf(os.Stderr, "[conflict] %s — preserved as %s\n", meta.Path, conflictPath)
			}

			request := map[string]interface{}{
				"type":      "chunk_request",
				"file_path": meta.Path,
				"file_hash": meta.Hash,
				"from_chunk": state.LastReceivedChunk(meta.Path),
			}
			reqBytes, err := json.Marshal(request)
			if err != nil {
				return err
			}
			return sendFn(reqBytes)
		}
	}

	// Chunk data message (has "file_path", "chunk_index", "chunk_data")
	if _, hasFilePath := msg["file_path"]; hasFilePath {
		if _, hasChunkIdx := msg["chunk_index"]; hasChunkIdx {
			if _, hasChunkData := msg["chunk_data"]; hasChunkData {
				var chunk ChunkData
				if err := json.Unmarshal(data, &chunk); err != nil {
					return nil
				}

				chunkBytes, err := base64.StdEncoding.DecodeString(chunk.ChunkDataB64)
				if err != nil {
					return err
				}

				destPath := filepath.Join(syncDir, chunk.FilePath)
				if err := state.WriteChunk(destPath, chunk.ChunkIndex, chunkBytes); err != nil {
					return err
				}
				state.RecordChunk(chunk.FilePath, chunk.ChunkIndex)

				if chunk.ChunkIndex+1 == chunk.ChunkCount {
					fmt.Fprintf(os.Stderr, "[sync] Completed: %s\n", chunk.FilePath)
					state.MarkComplete(chunk.FilePath, chunk.FileHash)

					ack := map[string]interface{}{
						"type":      "chunk_ack",
						"file_path": chunk.FilePath,
						"file_hash": chunk.FileHash,
					}
					ackBytes, err := json.Marshal(ack)
					if err != nil {
						return err
					}
					return sendFn(ackBytes)
				}
				return nil
			}
		}
	}

	// Chunk request message
	if raw, hasType := msg["type"]; hasType {
		var msgType string
		if err := json.Unmarshal(raw, &msgType); err == nil && msgType == "chunk_request" {
			var req struct {
				FilePath  string `json:"file_path"`
				FileHash  string `json:"file_hash"`
				FromChunk int    `json:"from_chunk"`
			}
			if err := json.Unmarshal(data, &req); err != nil {
				return nil
			}

			filePath := filepath.Join(syncDir, req.FilePath)
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return nil
			}

			chunks, err := state.SplitFile(filePath, req.FilePath)
			if err != nil {
				return err
			}

			for i := req.FromChunk; i < len(chunks); i++ {
				chunkBytes, err := json.Marshal(chunks[i])
				if err != nil {
					return err
				}
				if err := sendFn(chunkBytes); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// computeFileHash computes SHA-256 hash of a file on disk.
func computeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// computeHash computes SHA-256 hash of a byte slice.
func computeHash(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// rollingHash computes a simple Adler-32 variant rolling hash.
func rollingHash(data []byte) uint32 {
	var a, b uint32 = 1, 0
	for _, v := range data {
		a = (a + uint32(v)) % rollingHashModulus
		b = (b + a) % rollingHashModulus
	}
	return (b << 16) | a
}
