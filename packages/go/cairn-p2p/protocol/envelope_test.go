package protocol

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cborBytes returns a CBOR-encoded byte string payload for testing.
func cborBytes(t *testing.T, v interface{}) cbor.RawMessage {
	t.Helper()
	data, err := cbor.Marshal(v)
	require.NoError(t, err)
	return data
}

func TestNewMsgIDIs16Bytes(t *testing.T) {
	id := NewMsgID()
	assert.Len(t, id, 16)
}

func TestNewMsgIDUnique(t *testing.T) {
	id1 := NewMsgID()
	id2 := NewMsgID()
	assert.NotEqual(t, id1, id2)
}

func TestRoundtripMinimalEnvelope(t *testing.T) {
	env := &MessageEnvelope{
		Version:   1,
		Type:      MsgHeartbeat,
		MsgID:     NewMsgID(),
		SessionID: nil,
		Payload:   cborBytes(t, nil),
		AuthTag:   nil,
	}

	encoded, err := env.Encode()
	require.NoError(t, err)

	decoded, err := DecodeEnvelope(encoded)
	require.NoError(t, err)

	assert.Equal(t, env.Version, decoded.Version)
	assert.Equal(t, env.Type, decoded.Type)
	assert.Equal(t, env.MsgID, decoded.MsgID)
	assert.Nil(t, decoded.SessionID)
	assert.Nil(t, decoded.AuthTag)
}

func TestRoundtripFullEnvelope(t *testing.T) {
	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = 0xAB
	}
	payload := cborBytes(t, []byte{0xCA, 0xFE, 0xBA, 0xBE})
	env := &MessageEnvelope{
		Version:   1,
		Type:      MsgDataMessage,
		MsgID:     NewMsgID(),
		SessionID: sessionID,
		Payload:   payload,
		AuthTag:   []byte{0xDE, 0xAD},
	}

	encoded, err := env.Encode()
	require.NoError(t, err)

	decoded, err := DecodeEnvelope(encoded)
	require.NoError(t, err)

	assert.Equal(t, env.Version, decoded.Version)
	assert.Equal(t, env.Type, decoded.Type)
	assert.Equal(t, env.MsgID, decoded.MsgID)
	assert.Equal(t, env.SessionID, decoded.SessionID)
	assert.Equal(t, []byte(env.Payload), []byte(decoded.Payload))
	assert.Equal(t, env.AuthTag, decoded.AuthTag)
}

func TestOptionalFieldsAbsent(t *testing.T) {
	env := &MessageEnvelope{
		Version: 1,
		Type:    MsgPairRequest,
		MsgID:   NewMsgID(),
		Payload: cborBytes(t, true),
	}

	encoded, err := env.Encode()
	require.NoError(t, err)

	decoded, err := DecodeEnvelope(encoded)
	require.NoError(t, err)
	assert.Nil(t, decoded.SessionID)
	assert.Nil(t, decoded.AuthTag)
}

func TestDeterministicEncodingStable(t *testing.T) {
	sessionID := make([]byte, 32)
	for i := range sessionID {
		sessionID[i] = 0x02
	}
	env := &MessageEnvelope{
		Version:   1,
		Type:      MsgHeartbeat,
		MsgID:     [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		SessionID: sessionID,
		Payload:   cborBytes(t, "test"),
		AuthTag:   []byte{0x00, 0x01},
	}

	enc1, err := env.EncodeDeterministic()
	require.NoError(t, err)
	enc2, err := env.EncodeDeterministic()
	require.NoError(t, err)

	assert.Equal(t, enc1, enc2)
}

func TestDecodeInvalidCBOR(t *testing.T) {
	_, err := DecodeEnvelope([]byte{0xFF, 0xFF, 0xFF})
	assert.Error(t, err)
}

func TestVersionFieldPreserved(t *testing.T) {
	for _, v := range []uint8{0, 1, 255} {
		env := &MessageEnvelope{
			Version: v,
			Type:    MsgHeartbeat,
			MsgID:   [16]byte{},
			Payload: cborBytes(t, nil),
		}
		encoded, err := env.Encode()
		require.NoError(t, err)
		decoded, err := DecodeEnvelope(encoded)
		require.NoError(t, err)
		assert.Equal(t, v, decoded.Version)
	}
}
