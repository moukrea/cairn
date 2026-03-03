package crypto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// KDF info constants for the Double Ratchet (must match Rust).
var (
	RatchetRootKdfInfo    = []byte("cairn-root-chain-v1")
	RatchetChainKdfInfo   = []byte("cairn-chain-advance-v1")
	RatchetMessageKdfInfo = []byte("cairn-msg-encrypt-v1")
)

// RatchetConfig holds configuration for the Double Ratchet.
type RatchetConfig struct {
	Cipher  CipherSuite
	MaxSkip int
}

// DefaultRatchetConfig returns the default ratchet configuration.
func DefaultRatchetConfig() RatchetConfig {
	return RatchetConfig{
		Cipher:  CipherAes256Gcm,
		MaxSkip: 100,
	}
}

// RatchetHeader is sent alongside each Double Ratchet encrypted message.
type RatchetHeader struct {
	DHPublic     [32]byte `json:"dh_public"`
	PrevChainLen uint32   `json:"prev_chain_len"`
	MsgNum       uint32   `json:"msg_num"`
}

// skippedKeyID is the key for the skipped message keys map.
type skippedKeyID struct {
	dhPublic [32]byte
	msgNum   uint32
}

// ratchetState is the internal state of the Double Ratchet, serializable for persistence.
type ratchetState struct {
	DHSelfSecret [32]byte           `json:"dh_self_secret"`
	DHSelfPublic [32]byte           `json:"dh_self_public"`
	DHRemote     *[32]byte          `json:"dh_remote,omitempty"`
	RootKey      [32]byte           `json:"root_key"`
	ChainKeySend *[32]byte          `json:"chain_key_send,omitempty"`
	ChainKeyRecv *[32]byte          `json:"chain_key_recv,omitempty"`
	MsgNumSend   uint32             `json:"msg_num_send"`
	MsgNumRecv   uint32             `json:"msg_num_recv"`
	PrevChainLen uint32             `json:"prev_chain_len"`
	SkippedKeys  []skippedKeyEntry  `json:"skipped_keys,omitempty"`
}

type skippedKeyEntry struct {
	DHPublic [32]byte `json:"dh_public"`
	MsgNum   uint32   `json:"msg_num"`
	MsgKey   [32]byte `json:"msg_key"`
}

// DoubleRatchet implements the Signal Double Ratchet protocol.
type DoubleRatchet struct {
	dhSelf       *X25519Keypair
	dhRemote     *[32]byte
	rootKey      [32]byte
	chainKeySend *[32]byte
	chainKeyRecv *[32]byte
	msgNumSend   uint32
	msgNumRecv   uint32
	prevChainLen uint32
	skippedKeys  map[skippedKeyID][32]byte
	config       RatchetConfig
}

// InitSender initializes the Double Ratchet as the sender (Alice/initiator).
// sharedSecret is the 32-byte shared secret from key agreement.
// remoteDH is the receiver's initial DH ratchet public key.
func InitSender(sharedSecret [32]byte, remoteDH [32]byte, config *RatchetConfig) (*DoubleRatchet, error) {
	cfg := DefaultRatchetConfig()
	if config != nil {
		cfg = *config
	}

	dhSelf, err := GenerateX25519()
	if err != nil {
		return nil, err
	}

	// Perform initial DH ratchet step
	dhOutput, err := dhSelf.DiffieHellman(remoteDH)
	if err != nil {
		return nil, err
	}

	rootKey, chainKeySend, err := kdfRK(sharedSecret, dhOutput)
	if err != nil {
		return nil, err
	}

	return &DoubleRatchet{
		dhSelf:       dhSelf,
		dhRemote:     &remoteDH,
		rootKey:      rootKey,
		chainKeySend: &chainKeySend,
		skippedKeys:  make(map[skippedKeyID][32]byte),
		config:       cfg,
	}, nil
}

// InitReceiver initializes the Double Ratchet as the receiver (Bob/responder).
// sharedSecret is the 32-byte shared secret from key agreement.
// ourKeypair is the receiver's initial DH ratchet keypair.
func InitReceiver(sharedSecret [32]byte, ourKeypair *X25519Keypair, config *RatchetConfig) (*DoubleRatchet, error) {
	cfg := DefaultRatchetConfig()
	if config != nil {
		cfg = *config
	}

	return &DoubleRatchet{
		dhSelf:      ourKeypair,
		rootKey:     sharedSecret,
		skippedKeys: make(map[skippedKeyID][32]byte),
		config:      cfg,
	}, nil
}

// Encrypt encrypts a plaintext message. Returns the header and ciphertext.
func (dr *DoubleRatchet) Encrypt(plaintext []byte) (*RatchetHeader, []byte, error) {
	if dr.chainKeySend == nil {
		return nil, nil, fmt.Errorf("no sending chain key established")
	}

	newChainKey, messageKey, err := kdfCK(*dr.chainKeySend)
	if err != nil {
		return nil, nil, err
	}
	dr.chainKeySend = &newChainKey

	header := &RatchetHeader{
		DHPublic:     dr.dhSelf.PublicKeyBytes(),
		PrevChainLen: dr.prevChainLen,
		MsgNum:       dr.msgNumSend,
	}
	dr.msgNumSend++

	nonce := deriveNonce(messageKey, header.MsgNum)

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, nil, fmt.Errorf("header serialization: %w", err)
	}

	ciphertext, err := AeadEncrypt(dr.config.Cipher, messageKey, nonce, plaintext, headerBytes)
	if err != nil {
		return nil, nil, err
	}

	return header, ciphertext, nil
}

// Decrypt decrypts a message given the header and ciphertext.
func (dr *DoubleRatchet) Decrypt(header *RatchetHeader, ciphertext []byte) ([]byte, error) {
	// Try skipped keys first
	skID := skippedKeyID{dhPublic: header.DHPublic, msgNum: header.MsgNum}
	if mk, ok := dr.skippedKeys[skID]; ok {
		delete(dr.skippedKeys, skID)
		return decryptWithKey(dr.config.Cipher, mk, header, ciphertext)
	}

	// Check if peer's DH key changed (DH ratchet step needed)
	needDHRatchet := dr.dhRemote == nil || *dr.dhRemote != header.DHPublic

	if needDHRatchet {
		// Skip remaining messages in the current receiving chain
		if err := dr.skipMessageKeys(header.PrevChainLen); err != nil {
			return nil, err
		}
		// Perform DH ratchet step
		if err := dr.dhRatchet(header.DHPublic); err != nil {
			return nil, err
		}
	}

	// Skip ahead in the current receiving chain if needed
	if err := dr.skipMessageKeys(header.MsgNum); err != nil {
		return nil, err
	}

	// Derive the message key from the receiving chain
	if dr.chainKeyRecv == nil {
		return nil, fmt.Errorf("no receiving chain key established")
	}
	newChainKey, messageKey, err := kdfCK(*dr.chainKeyRecv)
	if err != nil {
		return nil, err
	}
	dr.chainKeyRecv = &newChainKey
	dr.msgNumRecv++

	return decryptWithKey(dr.config.Cipher, messageKey, header, ciphertext)
}

// ExportState serializes the ratchet state for persistence.
func (dr *DoubleRatchet) ExportState() ([]byte, error) {
	state := ratchetState{
		DHSelfSecret: dr.dhSelf.PrivateKeyBytes(),
		DHSelfPublic: dr.dhSelf.PublicKeyBytes(),
		RootKey:      dr.rootKey,
		MsgNumSend:   dr.msgNumSend,
		MsgNumRecv:   dr.msgNumRecv,
		PrevChainLen: dr.prevChainLen,
	}
	if dr.dhRemote != nil {
		remote := *dr.dhRemote
		state.DHRemote = &remote
	}
	if dr.chainKeySend != nil {
		ck := *dr.chainKeySend
		state.ChainKeySend = &ck
	}
	if dr.chainKeyRecv != nil {
		ck := *dr.chainKeyRecv
		state.ChainKeyRecv = &ck
	}
	for id, mk := range dr.skippedKeys {
		state.SkippedKeys = append(state.SkippedKeys, skippedKeyEntry{
			DHPublic: id.dhPublic,
			MsgNum:   id.msgNum,
			MsgKey:   mk,
		})
	}
	return json.Marshal(state)
}

// ImportState restores a DoubleRatchet from persisted state.
func ImportState(data []byte, config *RatchetConfig) (*DoubleRatchet, error) {
	cfg := DefaultRatchetConfig()
	if config != nil {
		cfg = *config
	}

	var state ratchetState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("ratchet state deserialization: %w", err)
	}

	dhSelf, err := X25519FromBytes(state.DHSelfSecret)
	if err != nil {
		return nil, err
	}

	dr := &DoubleRatchet{
		dhSelf:       dhSelf,
		rootKey:      state.RootKey,
		msgNumSend:   state.MsgNumSend,
		msgNumRecv:   state.MsgNumRecv,
		prevChainLen: state.PrevChainLen,
		skippedKeys:  make(map[skippedKeyID][32]byte),
		config:       cfg,
	}
	if state.DHRemote != nil {
		remote := *state.DHRemote
		dr.dhRemote = &remote
	}
	if state.ChainKeySend != nil {
		ck := *state.ChainKeySend
		dr.chainKeySend = &ck
	}
	if state.ChainKeyRecv != nil {
		ck := *state.ChainKeyRecv
		dr.chainKeyRecv = &ck
	}
	for _, entry := range state.SkippedKeys {
		dr.skippedKeys[skippedKeyID{dhPublic: entry.DHPublic, msgNum: entry.MsgNum}] = entry.MsgKey
	}
	return dr, nil
}

// Close zeroizes sensitive key material.
func (dr *DoubleRatchet) Close() {
	for i := range dr.rootKey {
		dr.rootKey[i] = 0
	}
	if dr.chainKeySend != nil {
		for i := range dr.chainKeySend {
			dr.chainKeySend[i] = 0
		}
	}
	if dr.chainKeyRecv != nil {
		for i := range dr.chainKeyRecv {
			dr.chainKeyRecv[i] = 0
		}
	}
	for id, mk := range dr.skippedKeys {
		for i := range mk {
			mk[i] = 0
		}
		dr.skippedKeys[id] = mk
	}
}

// --- Internal functions ---

func (dr *DoubleRatchet) skipMessageKeys(until uint32) error {
	if dr.chainKeyRecv == nil {
		return nil
	}

	toSkip := int(until) - int(dr.msgNumRecv)
	if toSkip < 0 {
		toSkip = 0
	}
	if toSkip > dr.config.MaxSkip {
		return fmt.Errorf("max skip threshold exceeded")
	}

	ck := *dr.chainKeyRecv
	for dr.msgNumRecv < until {
		newCK, mk, err := kdfCK(ck)
		if err != nil {
			return err
		}
		if dr.dhRemote == nil {
			return fmt.Errorf("no remote DH key for skipping")
		}
		id := skippedKeyID{dhPublic: *dr.dhRemote, msgNum: dr.msgNumRecv}
		dr.skippedKeys[id] = mk
		ck = newCK
		dr.msgNumRecv++
	}
	dr.chainKeyRecv = &ck
	return nil
}

func (dr *DoubleRatchet) dhRatchet(newRemotePublic [32]byte) error {
	dr.prevChainLen = dr.msgNumSend
	dr.msgNumSend = 0
	dr.msgNumRecv = 0
	dr.dhRemote = &newRemotePublic

	// Derive receiving chain key from current DH keypair + new remote key
	dhOutput, err := dr.dhSelf.DiffieHellman(newRemotePublic)
	if err != nil {
		return err
	}
	rootKey, chainKeyRecv, err := kdfRK(dr.rootKey, dhOutput)
	if err != nil {
		return err
	}
	dr.rootKey = rootKey
	dr.chainKeyRecv = &chainKeyRecv

	// Generate new DH keypair and derive sending chain key
	newDH, err := GenerateX25519()
	if err != nil {
		return err
	}
	dr.dhSelf = newDH
	dhOutput2, err := newDH.DiffieHellman(newRemotePublic)
	if err != nil {
		return err
	}
	rootKey2, chainKeySend, err := kdfRK(dr.rootKey, dhOutput2)
	if err != nil {
		return err
	}
	dr.rootKey = rootKey2
	dr.chainKeySend = &chainKeySend

	return nil
}

// kdfRK derives new root key and chain key from DH output.
func kdfRK(rootKey, dhOutput [32]byte) ([32]byte, [32]byte, error) {
	output, err := HkdfSHA256(dhOutput[:], rootKey[:], RatchetRootKdfInfo, 64)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	var rk, ck [32]byte
	copy(rk[:], output[:32])
	copy(ck[:], output[32:])
	return rk, ck, nil
}

// kdfCK derives message key from chain key and advances the chain.
func kdfCK(chainKey [32]byte) ([32]byte, [32]byte, error) {
	newCKBytes, err := HkdfSHA256(chainKey[:], nil, RatchetChainKdfInfo, 32)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	mkBytes, err := HkdfSHA256(chainKey[:], nil, RatchetMessageKdfInfo, 32)
	if err != nil {
		return [32]byte{}, [32]byte{}, err
	}
	var newCK, mk [32]byte
	copy(newCK[:], newCKBytes)
	copy(mk[:], mkBytes)
	return newCK, mk, nil
}

// deriveNonce constructs a 12-byte nonce from message key and message number.
// nonce = message_key[0:8] || big_endian_u32(msg_num)
func deriveNonce(messageKey [32]byte, msgNum uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:8], messageKey[:8])
	binary.BigEndian.PutUint32(nonce[8:], msgNum)
	return nonce
}

func decryptWithKey(cipher CipherSuite, messageKey [32]byte, header *RatchetHeader, ciphertext []byte) ([]byte, error) {
	nonce := deriveNonce(messageKey, header.MsgNum)
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("header serialization: %w", err)
	}
	return AeadDecrypt(cipher, messageKey, nonce, ciphertext, headerBytes)
}
