package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runHandshake(t *testing.T, pakeSecret []byte) (*HandshakeResult, *HandshakeResult) {
	t.Helper()
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	bobID, err := GenerateIdentity()
	require.NoError(t, err)
	return runHandshakeWithIdentities(t, aliceID, bobID, pakeSecret)
}

func runHandshakeWithIdentities(t *testing.T, aliceID, bobID *IdentityKeypair, pakeSecret []byte) (*HandshakeResult, *HandshakeResult) {
	t.Helper()

	initiator := NewNoiseXX(RoleInitiator, aliceID, pakeSecret)
	responder := NewNoiseXX(RoleResponder, bobID, pakeSecret)

	// Initiator sends msg1
	out1, err := initiator.Step(nil)
	require.NoError(t, err)
	require.NotNil(t, out1.Message)
	require.Nil(t, out1.Complete)

	// Responder receives msg1, sends msg2
	out2, err := responder.Step(out1.Message)
	require.NoError(t, err)
	require.NotNil(t, out2.Message)
	require.Nil(t, out2.Complete)

	// Initiator receives msg2, sends msg3
	out3, err := initiator.Step(out2.Message)
	require.NoError(t, err)
	require.NotNil(t, out3.Message)

	// Get initiator result
	initResult, err := initiator.Result()
	require.NoError(t, err)

	// Responder receives msg3
	out4, err := responder.Step(out3.Message)
	require.NoError(t, err)
	require.Nil(t, out4.Message)
	require.NotNil(t, out4.Complete)

	return initResult, out4.Complete
}

func TestFullHandshakeProducesMatchingSessionKeys(t *testing.T) {
	initResult, respResult := runHandshake(t, nil)
	assert.Equal(t, initResult.SessionKey, respResult.SessionKey)
}

func TestHandshakeRevealsRemoteStaticKeys(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	bobID, err := GenerateIdentity()
	require.NoError(t, err)

	alicePub := aliceID.PublicKey()
	bobPub := bobID.PublicKey()

	initResult, respResult := runHandshakeWithIdentities(t, aliceID, bobID, nil)

	assert.Equal(t, bobPub, initResult.RemoteStatic)
	assert.Equal(t, alicePub, respResult.RemoteStatic)
}

func TestHandshakeTranscriptHashesMatch(t *testing.T) {
	initResult, respResult := runHandshake(t, nil)
	assert.Equal(t, initResult.TranscriptHash, respResult.TranscriptHash)
}

func TestDifferentHandshakesProduceDifferentSessionKeys(t *testing.T) {
	result1, _ := runHandshake(t, nil)
	result2, _ := runHandshake(t, nil)
	assert.NotEqual(t, result1.SessionKey, result2.SessionKey)
}

func TestHandshakeWithPakeSecret(t *testing.T) {
	pake := make([]byte, 32)
	for i := range pake {
		pake[i] = 42
	}
	initResult, respResult := runHandshake(t, pake)
	assert.Equal(t, initResult.SessionKey, respResult.SessionKey)
}

func TestMismatchedPakeSecretsFail(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	bobID, err := GenerateIdentity()
	require.NoError(t, err)

	pake1 := make([]byte, 32)
	pake1[0] = 1
	pake2 := make([]byte, 32)
	pake2[0] = 2

	initiator := NewNoiseXX(RoleInitiator, aliceID, pake1)
	responder := NewNoiseXX(RoleResponder, bobID, pake2)

	out1, err := initiator.Step(nil)
	require.NoError(t, err)

	out2, err := responder.Step(out1.Message)
	require.NoError(t, err)

	out3, err := initiator.Step(out2.Message)
	require.NoError(t, err)

	// Responder should fail to decrypt msg3
	_, err = responder.Step(out3.Message)
	assert.Error(t, err)
}

func TestMsg1WrongLengthRejected(t *testing.T) {
	bobID, err := GenerateIdentity()
	require.NoError(t, err)
	responder := NewNoiseXX(RoleResponder, bobID, nil)

	_, err = responder.Step([]byte{0, 1, 2, 3})
	assert.Error(t, err)
}

func TestMsg2TooShortRejected(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	initiator := NewNoiseXX(RoleInitiator, aliceID, nil)

	out1, err := initiator.Step(nil)
	require.NoError(t, err)

	// Pass a truncated message 2
	_, err = initiator.Step(out1.Message[:10])
	assert.Error(t, err)
}

func TestTamperedMsg2Rejected(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	bobID, err := GenerateIdentity()
	require.NoError(t, err)

	initiator := NewNoiseXX(RoleInitiator, aliceID, nil)
	responder := NewNoiseXX(RoleResponder, bobID, nil)

	out1, err := initiator.Step(nil)
	require.NoError(t, err)

	out2, err := responder.Step(out1.Message)
	require.NoError(t, err)

	// Tamper with encrypted portion
	if len(out2.Message) > 40 {
		out2.Message[40] ^= 0xFF
	}

	_, err = initiator.Step(out2.Message)
	assert.Error(t, err)
}

func TestTamperedMsg3Rejected(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	bobID, err := GenerateIdentity()
	require.NoError(t, err)

	initiator := NewNoiseXX(RoleInitiator, aliceID, nil)
	responder := NewNoiseXX(RoleResponder, bobID, nil)

	out1, err := initiator.Step(nil)
	require.NoError(t, err)

	out2, err := responder.Step(out1.Message)
	require.NoError(t, err)

	out3, err := initiator.Step(out2.Message)
	require.NoError(t, err)

	out3.Message[0] ^= 0xFF

	_, err = responder.Step(out3.Message)
	assert.Error(t, err)
}

func TestOutOfOrderStepRejected(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	initiator := NewNoiseXX(RoleInitiator, aliceID, nil)

	_, err = initiator.Step([]byte{0})
	assert.Error(t, err)
}

func TestResponderRejectsNoInput(t *testing.T) {
	bobID, err := GenerateIdentity()
	require.NoError(t, err)
	responder := NewNoiseXX(RoleResponder, bobID, nil)

	_, err = responder.Step(nil)
	assert.Error(t, err)
}

func TestStepAfterCompleteRejected(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	bobID, err := GenerateIdentity()
	require.NoError(t, err)

	initiator := NewNoiseXX(RoleInitiator, aliceID, nil)
	responder := NewNoiseXX(RoleResponder, bobID, nil)

	out1, err := initiator.Step(nil)
	require.NoError(t, err)
	out2, err := responder.Step(out1.Message)
	require.NoError(t, err)
	out3, err := initiator.Step(out2.Message)
	require.NoError(t, err)

	out4, err := responder.Step(out3.Message)
	require.NoError(t, err)
	require.NotNil(t, out4.Complete)

	_, err = responder.Step(nil)
	assert.Error(t, err)
}

func TestMsg1Is32Bytes(t *testing.T) {
	aliceID, err := GenerateIdentity()
	require.NoError(t, err)
	initiator := NewNoiseXX(RoleInitiator, aliceID, nil)

	out, err := initiator.Step(nil)
	require.NoError(t, err)
	assert.Len(t, out.Message, 32)
}

// --- SAS tests ---

func TestSASDerivableFromHandshake(t *testing.T) {
	initResult, respResult := runHandshake(t, nil)

	initSAS, err := NumericSAS(initResult.TranscriptHash)
	require.NoError(t, err)
	respSAS, err := NumericSAS(respResult.TranscriptHash)
	require.NoError(t, err)

	assert.Equal(t, initSAS, respSAS)
}

func TestEmojiSASMatchesBetweenPeers(t *testing.T) {
	initResult, respResult := runHandshake(t, nil)

	initEmoji, err := EmojiSAS(initResult.TranscriptHash)
	require.NoError(t, err)
	respEmoji, err := EmojiSAS(respResult.TranscriptHash)
	require.NoError(t, err)

	assert.Equal(t, initEmoji, respEmoji)
}

func TestNumericSASFormat(t *testing.T) {
	hash := [32]byte{42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
		42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42}
	sas, err := NumericSAS(hash)
	require.NoError(t, err)
	assert.Len(t, sas, 6)
	for _, c := range sas {
		assert.True(t, c >= '0' && c <= '9')
	}
}

func TestNumericSASIsDeterministic(t *testing.T) {
	hash := [32]byte{99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
		99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99}
	sas1, err := NumericSAS(hash)
	require.NoError(t, err)
	sas2, err := NumericSAS(hash)
	require.NoError(t, err)
	assert.Equal(t, sas1, sas2)
}

func TestDifferentTranscriptsProduceDifferentSAS(t *testing.T) {
	hash1 := [32]byte{1}
	hash2 := [32]byte{2}
	sas1, err := NumericSAS(hash1)
	require.NoError(t, err)
	sas2, err := NumericSAS(hash2)
	require.NoError(t, err)
	assert.NotEqual(t, sas1, sas2)
}

func TestEmojiSASReturns4Entries(t *testing.T) {
	hash := [32]byte{42}
	emojis, err := EmojiSAS(hash)
	require.NoError(t, err)
	assert.Len(t, emojis, 4)
}

func TestEmojiSASIsDeterministic(t *testing.T) {
	hash := [32]byte{99}
	e1, err := EmojiSAS(hash)
	require.NoError(t, err)
	e2, err := EmojiSAS(hash)
	require.NoError(t, err)
	assert.Equal(t, e1, e2)
}

func TestEmojiSASEntriesAreFromTable(t *testing.T) {
	hash := [32]byte{77}
	emojis, err := EmojiSAS(hash)
	require.NoError(t, err)
	for _, emoji := range emojis {
		found := false
		for _, e := range EmojiTable {
			if emoji == e {
				found = true
				break
			}
		}
		assert.True(t, found, "emoji %q not found in table", emoji)
	}
}
