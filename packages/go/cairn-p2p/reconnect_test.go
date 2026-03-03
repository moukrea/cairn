package cairn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- BackoffPolicy tests ---

func TestDefaultBackoffPolicy(t *testing.T) {
	bp := DefaultBackoffPolicy()
	assert.Equal(t, 1*time.Second, bp.Initial)
	assert.Equal(t, 60*time.Second, bp.Max)
	assert.Equal(t, 2.0, bp.Factor)
}

func TestBackoffFirstAttempt(t *testing.T) {
	bp := DefaultBackoffPolicy()
	assert.Equal(t, 1*time.Second, bp.NextDelay(0))
}

func TestBackoffExponentialGrowth(t *testing.T) {
	bp := DefaultBackoffPolicy()
	assert.Equal(t, 1*time.Second, bp.NextDelay(0))
	assert.Equal(t, 2*time.Second, bp.NextDelay(1))
	assert.Equal(t, 4*time.Second, bp.NextDelay(2))
	assert.Equal(t, 8*time.Second, bp.NextDelay(3))
	assert.Equal(t, 16*time.Second, bp.NextDelay(4))
	assert.Equal(t, 32*time.Second, bp.NextDelay(5))
}

func TestBackoffCapsAtMax(t *testing.T) {
	bp := DefaultBackoffPolicy()
	// 2^6 = 64s > 60s max
	assert.Equal(t, 60*time.Second, bp.NextDelay(6))
	assert.Equal(t, 60*time.Second, bp.NextDelay(10))
	assert.Equal(t, 60*time.Second, bp.NextDelay(100))
}

func TestBackoffCustomValues(t *testing.T) {
	bp := &BackoffPolicy{
		Initial: 500 * time.Millisecond,
		Max:     10 * time.Second,
		Factor:  3.0,
	}
	assert.Equal(t, 500*time.Millisecond, bp.NextDelay(0))
	assert.Equal(t, 1500*time.Millisecond, bp.NextDelay(1))
	assert.Equal(t, 4500*time.Millisecond, bp.NextDelay(2))
	assert.Equal(t, 10*time.Second, bp.NextDelay(3)) // 13.5s capped to 10s
}

func TestBackoffNegativeAttempt(t *testing.T) {
	bp := DefaultBackoffPolicy()
	assert.Equal(t, 1*time.Second, bp.NextDelay(-1))
}

// --- HeartbeatConfig tests ---

func TestDefaultHeartbeatConfig(t *testing.T) {
	hc := DefaultHeartbeatConfig()
	assert.Equal(t, 30*time.Second, hc.Interval)
	assert.Equal(t, 90*time.Second, hc.Timeout)
}

func TestHeartbeatTimeoutIsThreeTimesInterval(t *testing.T) {
	hc := DefaultHeartbeatConfig()
	assert.Equal(t, 3*hc.Interval, hc.Timeout)
}

// --- QueueStrategy tests ---

func TestQueueStrategyString(t *testing.T) {
	assert.Equal(t, "fifo", QueueFIFO.String())
	assert.Equal(t, "lifo", QueueLIFO.String())
	assert.Contains(t, QueueStrategy(99).String(), "unknown")
}

// --- MessageQueue FIFO tests ---

func TestNewMessageQueueDefaults(t *testing.T) {
	q := NewMessageQueue(nil)
	assert.True(t, q.IsEnabled())
	assert.Equal(t, 0, q.Len())
}

func TestEnqueueAndDrain(t *testing.T) {
	q := NewMessageQueue(nil)
	require.NoError(t, q.Enqueue("ch1", []byte("msg1")))
	require.NoError(t, q.Enqueue("ch1", []byte("msg2")))
	assert.Equal(t, 2, q.Len())

	msgs := q.Drain()
	assert.Len(t, msgs, 2)
	assert.Equal(t, "msg1", string(msgs[0].Data))
	assert.Equal(t, "msg2", string(msgs[1].Data))
	assert.Equal(t, uint64(0), msgs[0].SeqNumber)
	assert.Equal(t, uint64(1), msgs[1].SeqNumber)

	assert.Equal(t, 0, q.Len())
}

func TestFIFORejectsWhenFull(t *testing.T) {
	cfg := &MessageQueueConfig{
		Enabled:  true,
		MaxSize:  3,
		MaxAge:   1 * time.Hour,
		Strategy: QueueFIFO,
	}
	q := NewMessageQueue(cfg)
	require.NoError(t, q.Enqueue("ch", []byte("1")))
	require.NoError(t, q.Enqueue("ch", []byte("2")))
	require.NoError(t, q.Enqueue("ch", []byte("3")))

	err := q.Enqueue("ch", []byte("4"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "queue full")
	assert.Equal(t, 3, q.Len())
}

func TestLIFODiscardsOldestWhenFull(t *testing.T) {
	cfg := &MessageQueueConfig{
		Enabled:  true,
		MaxSize:  3,
		MaxAge:   1 * time.Hour,
		Strategy: QueueLIFO,
	}
	q := NewMessageQueue(cfg)
	q.Enqueue("ch", []byte("1"))
	q.Enqueue("ch", []byte("2"))
	q.Enqueue("ch", []byte("3"))

	// This should discard "1" and add "4"
	err := q.Enqueue("ch", []byte("4"))
	assert.NoError(t, err)
	assert.Equal(t, 3, q.Len())

	msgs := q.Drain()
	assert.Equal(t, "2", string(msgs[0].Data))
	assert.Equal(t, "3", string(msgs[1].Data))
	assert.Equal(t, "4", string(msgs[2].Data))
}

func TestDisabledQueueRejectsEnqueue(t *testing.T) {
	cfg := &MessageQueueConfig{
		Enabled: false,
	}
	q := NewMessageQueue(cfg)
	err := q.Enqueue("ch", []byte("msg"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestDiscardClearsQueue(t *testing.T) {
	q := NewMessageQueue(nil)
	q.Enqueue("ch", []byte("1"))
	q.Enqueue("ch", []byte("2"))
	assert.Equal(t, 2, q.Len())

	q.Discard()
	assert.Equal(t, 0, q.Len())
}

func TestDrainReturnsEmptyForEmptyQueue(t *testing.T) {
	q := NewMessageQueue(nil)
	msgs := q.Drain()
	assert.Nil(t, msgs)
}

func TestEnqueuePreservesChannelInfo(t *testing.T) {
	q := NewMessageQueue(nil)
	q.Enqueue("data", []byte("payload"))
	msgs := q.Drain()
	assert.Equal(t, "data", msgs[0].Channel)
}

func TestSequenceNumbersMonotonicallyIncrease(t *testing.T) {
	q := NewMessageQueue(nil)
	for i := 0; i < 5; i++ {
		q.Enqueue("ch", []byte("msg"))
	}
	msgs := q.Drain()
	for i, m := range msgs {
		assert.Equal(t, uint64(i), m.SeqNumber)
	}
}

func TestDiscardResetsSequenceNumbers(t *testing.T) {
	q := NewMessageQueue(nil)
	q.Enqueue("ch", []byte("1"))
	q.Enqueue("ch", []byte("2"))
	q.Discard()

	q.Enqueue("ch", []byte("3"))
	msgs := q.Drain()
	assert.Equal(t, uint64(0), msgs[0].SeqNumber)
}

// --- TimeoutConfig tests ---

func TestDefaultTimeoutConfig(t *testing.T) {
	tc := DefaultTimeoutConfig()
	assert.Equal(t, 30*time.Second, tc.ConnectTimeout)
	assert.Equal(t, 10*time.Second, tc.TransportTimeout)
	assert.Equal(t, 1*time.Hour, tc.ReconnectMaxDuration)
	assert.Equal(t, 1*time.Second, tc.BackoffInitial)
	assert.Equal(t, 60*time.Second, tc.BackoffMax)
	assert.Equal(t, 2.0, tc.BackoffFactor)
	assert.Equal(t, 30*time.Second, tc.RendezvousPollInterval)
	assert.Equal(t, 24*time.Hour, tc.SessionExpiry)
	assert.Equal(t, 5*time.Minute, tc.PairingPayloadExpiry)
	assert.Equal(t, 30*time.Second, tc.HeartbeatInterval)
	assert.Equal(t, 90*time.Second, tc.HeartbeatTimeout)
}

// --- Integration: backoff schedule test ---

func TestBackoffScheduleMatchesSpec(t *testing.T) {
	bp := DefaultBackoffPolicy()

	// Spec: initial 1s, max 60s, factor 2.0
	expected := []time.Duration{
		1 * time.Second,  // attempt 0
		2 * time.Second,  // attempt 1
		4 * time.Second,  // attempt 2
		8 * time.Second,  // attempt 3
		16 * time.Second, // attempt 4
		32 * time.Second, // attempt 5
		60 * time.Second, // attempt 6 (capped)
		60 * time.Second, // attempt 7 (capped)
	}

	for i, exp := range expected {
		assert.Equal(t, exp, bp.NextDelay(i), "attempt %d", i)
	}
}

// --- Message queue config tests ---

func TestDefaultMessageQueueConfig(t *testing.T) {
	cfg := DefaultMessageQueueConfig()
	assert.True(t, cfg.Enabled)
	assert.Equal(t, 1000, cfg.MaxSize)
	assert.Equal(t, 1*time.Hour, cfg.MaxAge)
	assert.Equal(t, QueueFIFO, cfg.Strategy)
}
