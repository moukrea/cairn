package cairn

import "crypto/ed25519"

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
