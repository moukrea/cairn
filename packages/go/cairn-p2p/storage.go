package cairn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/pbkdf2"
)

// PairedPeerInfo holds stored information about a paired peer.
type PairedPeerInfo struct {
	PeerID        PeerID
	PublicKey     ed25519.PublicKey
	PairingSecret []byte
	PairedAt      int64
}

// SessionState holds the serialized state of a session for persistence.
type SessionState struct {
	Data []byte
}

// RendezvousState holds the serialized rendezvous state for a peer.
type RendezvousState struct {
	Data []byte
}

// StorageBackend provides persistent storage for identities, peer info,
// sessions, and rendezvous state. Implementations must be safe for
// concurrent use.
type StorageBackend interface {
	StoreIdentity(key ed25519.PrivateKey) error
	LoadIdentity() (ed25519.PrivateKey, error)
	StorePeer(peerID PeerID, info PairedPeerInfo) error
	LoadPeer(peerID PeerID) (PairedPeerInfo, error)
	DeletePeer(peerID PeerID) error
	ListPeers() ([]PeerID, error)
	StoreSession(id string, state SessionState) error
	LoadSession(id string) (SessionState, error)
	DeleteSession(id string) error
	StoreRendezvous(peerID PeerID, state RendezvousState) error
	LoadRendezvous(peerID PeerID) (RendezvousState, error)
}

// DiscoveryBackend provides a pluggable peer discovery mechanism.
type DiscoveryBackend interface {
	Publish(rendezvousID string) error
	Query(rendezvousID string) ([]string, error)
}

// PairingMethod identifies a pairing mechanism.
type PairingMethod int

const (
	PairingQR PairingMethod = iota
	PairingPin
	PairingLink
	PairingPSK
)

// --- Filesystem Storage Backend ---

const (
	// fsDirPermission is the permission for the storage directory.
	fsDirPermission = 0700

	// fsFilePermission is the permission for individual files.
	fsFilePermission = 0600

	// fsPBKDF2Iterations is the number of PBKDF2 iterations for key derivation.
	fsPBKDF2Iterations = 600_000

	// fsSaltSize is the size of the random salt in bytes.
	fsSaltSize = 32

	// fsNonceSize is the AES-256-GCM nonce size (12 bytes).
	fsNonceSize = 12
)

// fsEncryptedFile is the on-disk format for encrypted files.
type fsEncryptedFile struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// FilesystemStore implements StorageBackend by storing data as JSON files
// in a directory, optionally encrypted at rest with AES-256-GCM using a
// PBKDF2-derived key.
type FilesystemStore struct {
	mu       sync.RWMutex
	dir      string
	password []byte // if nil, files are stored unencrypted
}

// NewFilesystemStore creates a new filesystem-backed storage backend.
// dir is the directory to store files in. If password is non-nil, all
// files are encrypted at rest using AES-256-GCM with a PBKDF2-derived key.
func NewFilesystemStore(dir string, password []byte) (*FilesystemStore, error) {
	if err := os.MkdirAll(dir, fsDirPermission); err != nil {
		return nil, fmt.Errorf("fs store: create dir: %w", err)
	}
	// Create subdirectories
	for _, sub := range []string{"peers", "sessions", "rendezvous"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), fsDirPermission); err != nil {
			return nil, fmt.Errorf("fs store: create subdir %s: %w", sub, err)
		}
	}

	var pwd []byte
	if len(password) > 0 {
		pwd = make([]byte, len(password))
		copy(pwd, password)
	}

	return &FilesystemStore{
		dir:      dir,
		password: pwd,
	}, nil
}

// encrypt encrypts data with AES-256-GCM using a PBKDF2-derived key.
func (fs *FilesystemStore) encrypt(plaintext []byte) ([]byte, error) {
	if fs.password == nil {
		return plaintext, nil
	}

	salt := make([]byte, fsSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("fs store: generate salt: %w", err)
	}

	key := pbkdf2.Key(fs.password, salt, fsPBKDF2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("fs store: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("fs store: create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("fs store: generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	enc := fsEncryptedFile{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}
	return json.Marshal(enc)
}

// decrypt decrypts data encrypted with encrypt().
func (fs *FilesystemStore) decrypt(data []byte) ([]byte, error) {
	if fs.password == nil {
		return data, nil
	}

	var enc fsEncryptedFile
	if err := json.Unmarshal(data, &enc); err != nil {
		return nil, fmt.Errorf("fs store: decrypt unmarshal: %w", err)
	}

	key := pbkdf2.Key(fs.password, enc.Salt, fsPBKDF2Iterations, 32, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("fs store: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("fs store: create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, enc.Nonce, enc.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("fs store: decrypt: %w", err)
	}
	return plaintext, nil
}

// writeFile writes data to a file, encrypting if a password is set.
func (fs *FilesystemStore) writeFile(path string, data []byte) error {
	encrypted, err := fs.encrypt(data)
	if err != nil {
		return err
	}

	// Write atomically via temp file
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encrypted, fsFilePermission); err != nil {
		return fmt.Errorf("fs store: write: %w", err)
	}
	return os.Rename(tmp, path)
}

// readFile reads and decrypts a file.
func (fs *FilesystemStore) readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return fs.decrypt(data)
}

// --- Identity ---

// identityFile is the JSON format for the identity file.
type identityFile struct {
	PrivateKey []byte `json:"private_key"`
}

func (fs *FilesystemStore) identityPath() string {
	return filepath.Join(fs.dir, "identity.json")
}

// StoreIdentity persists the Ed25519 identity key.
func (fs *FilesystemStore) StoreIdentity(key ed25519.PrivateKey) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := json.Marshal(identityFile{PrivateKey: key})
	if err != nil {
		return err
	}
	return fs.writeFile(fs.identityPath(), data)
}

// LoadIdentity loads the Ed25519 identity key from disk.
func (fs *FilesystemStore) LoadIdentity() (ed25519.PrivateKey, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	data, err := fs.readFile(fs.identityPath())
	if err != nil {
		return nil, err
	}

	var id identityFile
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, err
	}
	return ed25519.PrivateKey(id.PrivateKey), nil
}

// --- Peers ---

// peerFile is the JSON format for peer info files.
type peerFile struct {
	PeerID        PeerID           `json:"peer_id"`
	PublicKey     []byte           `json:"public_key"`
	PairingSecret []byte          `json:"pairing_secret"`
	PairedAt      int64            `json:"paired_at"`
}

func (fs *FilesystemStore) peerPath(peerID PeerID) string {
	return filepath.Join(fs.dir, "peers", fmt.Sprintf("%x.json", peerID[:8]))
}

// StorePeer persists information about a paired peer.
func (fs *FilesystemStore) StorePeer(peerID PeerID, info PairedPeerInfo) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := json.Marshal(peerFile{
		PeerID:        info.PeerID,
		PublicKey:     info.PublicKey,
		PairingSecret: info.PairingSecret,
		PairedAt:      info.PairedAt,
	})
	if err != nil {
		return err
	}
	return fs.writeFile(fs.peerPath(peerID), data)
}

// LoadPeer loads paired peer information from disk.
func (fs *FilesystemStore) LoadPeer(peerID PeerID) (PairedPeerInfo, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	data, err := fs.readFile(fs.peerPath(peerID))
	if err != nil {
		return PairedPeerInfo{}, err
	}

	var pf peerFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return PairedPeerInfo{}, err
	}
	return PairedPeerInfo{
		PeerID:        pf.PeerID,
		PublicKey:     pf.PublicKey,
		PairingSecret: pf.PairingSecret,
		PairedAt:      pf.PairedAt,
	}, nil
}

// DeletePeer removes a paired peer's data from disk.
func (fs *FilesystemStore) DeletePeer(peerID PeerID) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return os.Remove(fs.peerPath(peerID))
}

// ListPeers returns all stored peer IDs.
func (fs *FilesystemStore) ListPeers() ([]PeerID, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entries, err := os.ReadDir(filepath.Join(fs.dir, "peers"))
	if err != nil {
		return nil, err
	}

	var peers []PeerID
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(fs.dir, "peers", entry.Name())
		data, err := fs.readFile(path)
		if err != nil {
			continue
		}
		var pf peerFile
		if err := json.Unmarshal(data, &pf); err != nil {
			continue
		}
		peers = append(peers, pf.PeerID)
	}
	return peers, nil
}

// --- Sessions ---

// sessionFile is the JSON format for session state files.
type sessionFile struct {
	Data []byte `json:"data"`
}

func (fs *FilesystemStore) sessionPath(id string) string {
	// Sanitize session ID for filename
	h := sha256.Sum256([]byte(id))
	return filepath.Join(fs.dir, "sessions", fmt.Sprintf("%x.json", h[:8]))
}

// StoreSession persists session state (e.g., Double Ratchet state).
func (fs *FilesystemStore) StoreSession(id string, state SessionState) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := json.Marshal(sessionFile{Data: state.Data})
	if err != nil {
		return err
	}
	return fs.writeFile(fs.sessionPath(id), data)
}

// LoadSession loads session state from disk.
func (fs *FilesystemStore) LoadSession(id string) (SessionState, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	data, err := fs.readFile(fs.sessionPath(id))
	if err != nil {
		return SessionState{}, err
	}

	var sf sessionFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return SessionState{}, err
	}
	return SessionState{Data: sf.Data}, nil
}

// DeleteSession removes session state from disk.
func (fs *FilesystemStore) DeleteSession(id string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return os.Remove(fs.sessionPath(id))
}

// --- Rendezvous ---

// rendezvousFile is the JSON format for rendezvous state files.
type rendezvousFile struct {
	Data []byte `json:"data"`
}

func (fs *FilesystemStore) rendezvousPath(peerID PeerID) string {
	return filepath.Join(fs.dir, "rendezvous", fmt.Sprintf("%x.json", peerID[:8]))
}

// StoreRendezvous persists rendezvous state for a peer.
func (fs *FilesystemStore) StoreRendezvous(peerID PeerID, state RendezvousState) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := json.Marshal(rendezvousFile{Data: state.Data})
	if err != nil {
		return err
	}
	return fs.writeFile(fs.rendezvousPath(peerID), data)
}

// LoadRendezvous loads rendezvous state from disk.
func (fs *FilesystemStore) LoadRendezvous(peerID PeerID) (RendezvousState, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	data, err := fs.readFile(fs.rendezvousPath(peerID))
	if err != nil {
		return RendezvousState{}, err
	}

	var rf rendezvousFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return RendezvousState{}, err
	}
	return RendezvousState{Data: rf.Data}, nil
}
