package protocol

// Pairing (0x01xx)
const (
	MsgPairRequest   uint16 = 0x0100
	MsgPairChallenge uint16 = 0x0101
	MsgPairResponse  uint16 = 0x0102
	MsgPairConfirm   uint16 = 0x0103
	MsgPairReject    uint16 = 0x0104
	MsgPairRevoke    uint16 = 0x0105
)

// Session (0x02xx)
const (
	MsgSessionResume    uint16 = 0x0200
	MsgSessionResumeAck uint16 = 0x0201
	MsgSessionExpired   uint16 = 0x0202
	MsgSessionClose     uint16 = 0x0203
)

// Data (0x03xx)
const (
	MsgDataMessage uint16 = 0x0300
	MsgDataAck     uint16 = 0x0301
	MsgDataNack    uint16 = 0x0302
)

// Control (0x04xx)
const (
	MsgHeartbeat           uint16 = 0x0400
	MsgHeartbeatAck        uint16 = 0x0401
	MsgTransportMigrate    uint16 = 0x0402
	MsgTransportMigrateAck uint16 = 0x0403
)

// Mesh (0x05xx)
const (
	MsgRouteRequest  uint16 = 0x0500
	MsgRouteResponse uint16 = 0x0501
	MsgRelayData     uint16 = 0x0502
	MsgRelayAck      uint16 = 0x0503
)

// Rendezvous (0x06xx)
const (
	MsgRendezvousPublish  uint16 = 0x0600
	MsgRendezvousQuery    uint16 = 0x0601
	MsgRendezvousResponse uint16 = 0x0602
)

// Forward (0x07xx)
const (
	MsgForwardRequest uint16 = 0x0700
	MsgForwardAck     uint16 = 0x0701
	MsgForwardDeliver uint16 = 0x0702
	MsgForwardPurge   uint16 = 0x0703
)

// Version negotiation
const MsgVersionNegotiate uint16 = 0x0001

// Reserved and application extension ranges
const (
	CairnReservedStart uint16 = 0x0100
	CairnReservedEnd   uint16 = 0xEFFF
	AppExtensionStart  uint16 = 0xF000
	AppExtensionEnd    uint16 = 0xFFFF
)

// MessageCategory returns the category name for a given message type code.
func MessageCategory(msgType uint16) string {
	switch {
	case msgType == MsgVersionNegotiate:
		return "version"
	case msgType >= 0x0100 && msgType <= 0x01FF:
		return "pairing"
	case msgType >= 0x0200 && msgType <= 0x02FF:
		return "session"
	case msgType >= 0x0300 && msgType <= 0x03FF:
		return "data"
	case msgType >= 0x0400 && msgType <= 0x04FF:
		return "control"
	case msgType >= 0x0500 && msgType <= 0x05FF:
		return "mesh"
	case msgType >= 0x0600 && msgType <= 0x06FF:
		return "rendezvous"
	case msgType >= 0x0700 && msgType <= 0x07FF:
		return "forward"
	case msgType >= 0x0800 && msgType <= 0xEFFF:
		return "reserved"
	case msgType >= AppExtensionStart && msgType <= AppExtensionEnd:
		return "application"
	default:
		return "reserved"
	}
}
