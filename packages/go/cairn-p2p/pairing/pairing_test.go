package pairing

import (
	"testing"
	"time"

	"github.com/moukrea/cairn/packages/go/cairn-p2p/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- PIN tests ---

func TestGeneratePin(t *testing.T) {
	pin, raw, err := GeneratePin()
	require.NoError(t, err)
	assert.Len(t, pin, 9) // XXXX-XXXX
	assert.Equal(t, "-", string(pin[4]))
	assert.Len(t, raw, 5)
}

func TestPinOnlyCrockfordChars(t *testing.T) {
	for i := 0; i < 50; i++ {
		pin, _, err := GeneratePin()
		require.NoError(t, err)
		stripped := pin[:4] + pin[5:]
		err = ValidatePin(stripped)
		assert.NoError(t, err)
	}
}

func TestNormalizePinCaseInsensitive(t *testing.T) {
	assert.Equal(t, "ABCDEFGH", NormalizePin("abcd-efgh"))
}

func TestNormalizePinStrips(t *testing.T) {
	assert.Equal(t, "ABCDEFGH", NormalizePin("AB CD-EF GH"))
}

func TestNormalizePinSubstitutions(t *testing.T) {
	assert.Equal(t, "1100AAAA", NormalizePin("ILOO-AAAA"))
}

func TestNormalizePinRemovesU(t *testing.T) {
	assert.Equal(t, "ABCD", NormalizePin("AUBU-CUDU"))
}

func TestCrockfordRoundtrip(t *testing.T) {
	for i := 0; i < 50; i++ {
		pin, raw, err := GeneratePin()
		require.NoError(t, err)
		stripped := pin[:4] + pin[5:]
		decoded, err := DecodeCrockford(stripped)
		require.NoError(t, err)
		var expected [5]byte
		copy(expected[:], raw)
		assert.Equal(t, expected, decoded)
	}
}

func TestCrockfordKnownValues(t *testing.T) {
	assert.Equal(t, "00000000", encodeCrockford([5]byte{0, 0, 0, 0, 0}))
	assert.Equal(t, "ZZZZZZZZ", encodeCrockford([5]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}))
}

func TestValidatePinRejectsWrongLength(t *testing.T) {
	assert.Error(t, ValidatePin("ABC"))
}

func TestValidatePinRejectsInvalidChars(t *testing.T) {
	assert.Error(t, ValidatePin("!@#$%^&*"))
}

// --- QR tests ---

func TestQRPayloadRoundtrip(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	data, encoded, err := GenerateQRPayload(identity, DefaultPairingTTL, []string{"relay.example.com:9090"})
	require.NoError(t, err)
	assert.True(t, len(encoded) <= 256)

	parsed, err := ParseQRPayload(encoded)
	require.NoError(t, err)
	assert.Equal(t, data.PeerID, parsed.PeerID)
	assert.Equal(t, data.Nonce, parsed.Nonce)
	assert.Equal(t, data.PakeCred, parsed.PakeCred)
	assert.Equal(t, data.Hints, parsed.Hints)
}

func TestQRPayloadNotExpired(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	data, _, err := GenerateQRPayload(identity, DefaultPairingTTL, nil)
	require.NoError(t, err)
	assert.False(t, data.IsExpired())
}

func TestQRPayloadRejectsOversized(t *testing.T) {
	_, err := ParseQRPayload(make([]byte, 300))
	assert.Error(t, err)
}

// --- Link tests ---

func TestLinkRoundtrip(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	data, uri, err := GeneratePairingLink(identity, DefaultPairingTTL, []string{"relay.example.com"})
	require.NoError(t, err)
	assert.Contains(t, uri, "cairn://pair?")

	parsed, err := ParsePairingLink(uri)
	require.NoError(t, err)
	assert.Equal(t, data.PeerID, parsed.PeerID)
	assert.Equal(t, data.Nonce, parsed.Nonce)
	assert.Equal(t, data.PakeCred, parsed.PakeCred)
}

func TestLinkRejectsMissingPid(t *testing.T) {
	_, err := ParsePairingLink("cairn://pair?nonce=aa&pake=bb")
	assert.Error(t, err)
}

func TestLinkRejectsWrongScheme(t *testing.T) {
	_, err := ParsePairingLink("https://pair?pid=abc&nonce=abc&pake=abc")
	assert.Error(t, err)
}

// --- PSK tests ---

func TestPskAcceptsSufficientKey(t *testing.T) {
	psk := make([]byte, 16)
	for i := range psk {
		psk[i] = 0xAB
	}
	data, err := PairWithPSK(psk)
	require.NoError(t, err)
	assert.Equal(t, psk, data.PakeInput)
}

func TestPskRejectsShortKey(t *testing.T) {
	_, err := PairWithPSK(make([]byte, 8))
	assert.Error(t, err)
}

func TestPskRejectsEmptyKey(t *testing.T) {
	_, err := PairWithPSK([]byte{})
	assert.Error(t, err)
}

func TestPskRendezvousIsDeterministic(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = 0x42
	}
	d1, err := PairWithPSK(key)
	require.NoError(t, err)
	d2, err := PairWithPSK(key)
	require.NoError(t, err)
	assert.Equal(t, d1.RendezvousID, d2.RendezvousID)
}

func TestPskDifferentKeysProduceDifferentRendezvous(t *testing.T) {
	k1 := make([]byte, 16)
	k1[0] = 1
	k2 := make([]byte, 16)
	k2[0] = 2
	d1, err := PairWithPSK(k1)
	require.NoError(t, err)
	d2, err := PairWithPSK(k2)
	require.NoError(t, err)
	assert.NotEqual(t, d1.RendezvousID, d2.RendezvousID)
}

// --- Rendezvous tests ---

func TestRendezvousIDDerivation(t *testing.T) {
	pake := make([]byte, 32)
	nonce := make([]byte, 16)
	id1, err := PairingRendezvousID(pake, nonce)
	require.NoError(t, err)
	id2, err := PairingRendezvousID(pake, nonce)
	require.NoError(t, err)
	assert.Equal(t, id1, id2)
	assert.Len(t, id1, 32)
}

func TestRendezvousIDDiffersForDifferentInputs(t *testing.T) {
	pake1 := make([]byte, 32)
	pake1[0] = 1
	pake2 := make([]byte, 32)
	pake2[0] = 2
	nonce := make([]byte, 16)
	id1, err := PairingRendezvousID(pake1, nonce)
	require.NoError(t, err)
	id2, err := PairingRendezvousID(pake2, nonce)
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2)
}

// --- State Machine tests ---

func TestInitiatorSessionState(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	session, outbound, err := NewInitiator(identity, []byte("test-password"), 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, StateAwaitingPakeExchange, session.State())
	assert.Equal(t, RoleInitiator, session.Role())
	assert.Equal(t, FlowInitiation, session.FlowType())
	assert.NotEmpty(t, outbound)
}

func TestResponderSessionState(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	session, err := NewResponder(identity, []byte("test-password"), 5*time.Minute)
	require.NoError(t, err)
	assert.Equal(t, StateIdle, session.State())
	assert.Equal(t, RoleResponder, session.Role())
}

func TestStandardInitiatorState(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	session := NewStandardInitiator(identity, 5*time.Minute)
	assert.Equal(t, StateAwaitingVerification, session.State())
	assert.Equal(t, FlowStandard, session.FlowType())
}

func TestStandardResponderState(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	session := NewStandardResponder(identity, 5*time.Minute)
	assert.Equal(t, StateIdle, session.State())
}

func TestSpake2FullExchange(t *testing.T) {
	password := []byte("correct-horse-battery-staple")

	aliceID, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	bobID, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	alice, aliceMsg, err := NewInitiator(aliceID, password, 5*time.Minute)
	require.NoError(t, err)

	bob, err := NewResponder(bobID, password, 5*time.Minute)
	require.NoError(t, err)

	// Set remote nonces before PAKE exchange (in real flow, nonces travel with PairRequest/Challenge)
	bob.SetRemoteNonce(alice.Nonce())

	// Bob processes Alice's PAKE message, produces challenge
	bobMsg, err := bob.HandlePakeMessage(aliceMsg)
	require.NoError(t, err)
	assert.NotEmpty(t, bobMsg)
	assert.Equal(t, StateAwaitingVerification, bob.State())

	// Alice sets bob's nonce (received with PairChallenge)
	alice.SetRemoteNonce(bob.Nonce())

	// Alice processes Bob's challenge
	_, err = alice.HandlePakeMessage(bobMsg)
	require.NoError(t, err)
	assert.Equal(t, StateAwaitingVerification, alice.State())

	// Alice sends key confirmation
	aliceConfirm, err := alice.SendKeyConfirmation()
	require.NoError(t, err)
	assert.Equal(t, StateAwaitingConfirmation, alice.State())

	// Bob verifies and sends key confirmation
	bobConfirm, err := bob.SendKeyConfirmation()
	require.NoError(t, err)
	assert.Equal(t, StateAwaitingConfirmation, bob.State())

	// Both verify peer's confirmation
	err = alice.VerifyKeyConfirmation(bobConfirm)
	require.NoError(t, err)
	assert.Equal(t, StateCompleted, alice.State())
	assert.NotNil(t, alice.SharedKey())

	err = bob.VerifyKeyConfirmation(aliceConfirm)
	require.NoError(t, err)
	assert.Equal(t, StateCompleted, bob.State())
	assert.NotNil(t, bob.SharedKey())

	// Both derived the same shared key
	assert.Equal(t, alice.SharedKey(), bob.SharedKey())
}

func TestStandardFlowKeyConfirmation(t *testing.T) {
	aliceID, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	bobID, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	alice := NewStandardInitiator(aliceID, 5*time.Minute)
	bob := NewStandardResponder(bobID, 5*time.Minute)

	// Bob handles request
	err = bob.HandleStandardRequest(alice.Nonce())
	require.NoError(t, err)
	assert.Equal(t, StateAwaitingVerification, bob.State())

	// Set shared key (from Noise XX in real use)
	sharedKey := make([]byte, 32)
	for i := range sharedKey {
		sharedKey[i] = 0xAB
	}
	alice.SetSharedKey(sharedKey)
	bob.SetSharedKey(sharedKey)
	alice.SetRemoteNonce(bob.Nonce())
	bob.SetRemoteNonce(alice.Nonce())

	// Key confirmation exchange
	aliceConfirm, err := alice.SendKeyConfirmation()
	require.NoError(t, err)

	bobConfirm, err := bob.SendKeyConfirmation()
	require.NoError(t, err)

	err = alice.VerifyKeyConfirmation(bobConfirm)
	require.NoError(t, err)
	assert.Equal(t, StateCompleted, alice.State())

	err = bob.VerifyKeyConfirmation(aliceConfirm)
	require.NoError(t, err)
	assert.Equal(t, StateCompleted, bob.State())
}

func TestMismatchedKeysFailVerification(t *testing.T) {
	aliceID, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	bobID, err := crypto.GenerateIdentity()
	require.NoError(t, err)

	alice := NewStandardInitiator(aliceID, 5*time.Minute)
	bob := NewStandardResponder(bobID, 5*time.Minute)

	err = bob.HandleStandardRequest(alice.Nonce())
	require.NoError(t, err)

	alice.SetSharedKey([]byte{0xAA, 0xAA, 0xAA, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	bob.SetSharedKey([]byte{0xBB, 0xBB, 0xBB, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	alice.SetRemoteNonce(bob.Nonce())
	bob.SetRemoteNonce(alice.Nonce())

	aliceConfirm, err := alice.SendKeyConfirmation()
	require.NoError(t, err)

	_, err = bob.SendKeyConfirmation()
	require.NoError(t, err)

	err = bob.VerifyKeyConfirmation(aliceConfirm)
	assert.Error(t, err)
	assert.Equal(t, StateFailed, bob.State())
}

func TestRejectTransitionsToFailed(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	session := NewStandardInitiator(identity, 5*time.Minute)

	session.Reject("user rejected")
	assert.Equal(t, StateFailed, session.State())
	assert.Equal(t, "user rejected", session.FailReason())
}

func TestSharedKeyNotAvailableBeforeCompletion(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	session := NewStandardInitiator(identity, 5*time.Minute)
	session.SetSharedKey(make([]byte, 32))
	assert.Nil(t, session.SharedKey())
}

func TestNoncesAreUnique(t *testing.T) {
	n1 := generateNonce()
	n2 := generateNonce()
	assert.NotEqual(t, n1, n2)
	assert.Len(t, n1, 16)
}

func TestSessionNotExpired(t *testing.T) {
	identity, err := crypto.GenerateIdentity()
	require.NoError(t, err)
	session := NewStandardInitiator(identity, 5*time.Minute)
	assert.False(t, session.IsExpired())
}
