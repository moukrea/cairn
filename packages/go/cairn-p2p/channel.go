package cairn

import (
	"sync"
)

// Channel represents a named, multiplexed communication channel within a session.
// Channels map to yamux streams; each channel has independent flow control.
type Channel struct {
	mu   sync.RWMutex
	name string
	open bool
}

// NewChannel creates a new open channel with the given name.
func NewChannel(name string) *Channel {
	return &Channel{
		name: name,
		open: true,
	}
}

// Name returns the channel name.
func (c *Channel) Name() string {
	return c.name
}

// IsOpen reports whether the channel is still open.
func (c *Channel) IsOpen() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.open
}

// Close closes the channel.
func (c *Channel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.open = false
	return nil
}
