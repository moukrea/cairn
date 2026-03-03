package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMessageCategory(t *testing.T) {
	assert.Equal(t, "version", MessageCategory(MsgVersionNegotiate))
	assert.Equal(t, "pairing", MessageCategory(MsgPairRequest))
	assert.Equal(t, "pairing", MessageCategory(MsgPairRevoke))
	assert.Equal(t, "session", MessageCategory(MsgSessionResume))
	assert.Equal(t, "session", MessageCategory(MsgSessionClose))
	assert.Equal(t, "data", MessageCategory(MsgDataMessage))
	assert.Equal(t, "data", MessageCategory(MsgDataNack))
	assert.Equal(t, "control", MessageCategory(MsgHeartbeat))
	assert.Equal(t, "control", MessageCategory(MsgTransportMigrateAck))
	assert.Equal(t, "mesh", MessageCategory(MsgRouteRequest))
	assert.Equal(t, "mesh", MessageCategory(MsgRelayAck))
	assert.Equal(t, "rendezvous", MessageCategory(MsgRendezvousPublish))
	assert.Equal(t, "rendezvous", MessageCategory(MsgRendezvousResponse))
	assert.Equal(t, "forward", MessageCategory(MsgForwardRequest))
	assert.Equal(t, "forward", MessageCategory(MsgForwardPurge))
	assert.Equal(t, "application", MessageCategory(0xF000))
	assert.Equal(t, "application", MessageCategory(0xFFFF))
	assert.Equal(t, "reserved", MessageCategory(0x0800))
}
