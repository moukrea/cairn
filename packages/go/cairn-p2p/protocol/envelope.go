package protocol

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// MessageEnvelope is the wire-level message envelope used for all cairn protocol messages.
// Serialized as a CBOR map with integer keys (0-5) for compactness.
type MessageEnvelope struct {
	Version   uint8           `cbor:"0,keyasint"`
	Type      uint16          `cbor:"1,keyasint"`
	MsgID     [16]byte        `cbor:"2,keyasint"`
	SessionID []byte          `cbor:"3,keyasint,omitempty"`
	Payload   cbor.RawMessage `cbor:"4,keyasint"`
	AuthTag   []byte          `cbor:"5,keyasint,omitempty"`
}

// NewMsgID generates a new UUID v7 message ID as a 16-byte array.
func NewMsgID() [16]byte {
	return uuid.Must(uuid.NewV7())
}

// Encode serializes the envelope to CBOR bytes.
func (e *MessageEnvelope) Encode() ([]byte, error) {
	data, err := cbor.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("CBOR encode error: %w", err)
	}
	return data, nil
}

// EncodeDeterministic serializes the envelope using canonical/deterministic CBOR
// encoding (RFC 8949 section 4.2). Used when the output will be input to a
// signature or HMAC computation.
func (e *MessageEnvelope) EncodeDeterministic() ([]byte, error) {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("CBOR deterministic mode error: %w", err)
	}
	data, err := em.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("CBOR deterministic encode error: %w", err)
	}
	return data, nil
}

// DecodeEnvelope decodes a MessageEnvelope from CBOR bytes.
func DecodeEnvelope(data []byte) (*MessageEnvelope, error) {
	var env MessageEnvelope
	if err := cbor.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("CBOR decode error: %w", err)
	}
	return &env, nil
}
