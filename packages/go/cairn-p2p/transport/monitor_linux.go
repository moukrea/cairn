//go:build linux

package transport

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
)

// Netlink message types for address changes (from linux/rtnetlink.h).
const (
	rtmNewAddr = 20 // RTM_NEWADDR
	rtmDelAddr = 21 // RTM_DELADDR
)

// Netlink message header size.
const nlmsghdrSize = 16

// netlinkHeader represents a netlink message header.
type netlinkHeader struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

// NetlinkNetworkMonitor listens for RTM_NEWADDR/RTM_DELADDR events via
// a Linux netlink socket to detect network interface changes in real time.
type NetlinkNetworkMonitor struct {
	mu       sync.Mutex
	fd       int
	callback func(NetworkEvent)
	stopCh   chan struct{}
	stopped  bool
	wg       sync.WaitGroup
}

// NewNetworkMonitor returns a Linux netlink-based NetworkMonitor.
func NewNetworkMonitor() NetworkMonitor {
	return &NetlinkNetworkMonitor{}
}

// Start begins monitoring network changes via netlink.
// Events are delivered to the callback when address changes are detected.
func (m *NetlinkNetworkMonitor) Start(callback func(NetworkEvent)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return fmt.Errorf("monitor already stopped")
	}
	if m.fd != 0 {
		return fmt.Errorf("monitor already started")
	}

	m.callback = callback

	// Create a netlink socket for RTMGRP_IPV4_IFADDR and RTMGRP_IPV6_IFADDR
	fd, err := syscall.Socket(
		syscall.AF_NETLINK,
		syscall.SOCK_DGRAM,
		syscall.NETLINK_ROUTE,
	)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}

	// Bind to address change multicast groups:
	//   RTMGRP_IPV4_IFADDR = 0x10  (bit 4)
	//   RTMGRP_IPV6_IFADDR = 0x20  (bit 5 -- actually 0x100 for group 8, but
	//   the legacy group bitmask for IPv6 addr is not straightforward.
	//   We use RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR.
	sa := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Groups: (1 << (syscall.RTNLGRP_IPV4_IFADDR - 1)) |
			(1 << (syscall.RTNLGRP_IPV6_IFADDR - 1)),
	}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("netlink bind: %w", err)
	}

	m.fd = fd
	m.stopCh = make(chan struct{})

	m.wg.Add(1)
	go m.readLoop()

	return nil
}

// readLoop reads netlink messages and dispatches events.
func (m *NetlinkNetworkMonitor) readLoop() {
	defer m.wg.Done()

	buf := make([]byte, 4096)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		// Set a short read timeout so we can check stopCh
		tv := syscall.Timeval{Sec: 1, Usec: 0}
		syscall.SetsockoptTimeval(m.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

		n, _, err := syscall.Recvfrom(m.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			// Check if we've been stopped
			select {
			case <-m.stopCh:
				return
			default:
				continue
			}
		}

		if n < nlmsghdrSize {
			continue
		}

		m.parseMessages(buf[:n])
	}
}

// parseMessages parses netlink messages from a buffer and dispatches events.
func (m *NetlinkNetworkMonitor) parseMessages(data []byte) {
	for len(data) >= nlmsghdrSize {
		hdr := netlinkHeader{
			Len:   binary.LittleEndian.Uint32(data[0:4]),
			Type:  binary.LittleEndian.Uint16(data[4:6]),
			Flags: binary.LittleEndian.Uint16(data[6:8]),
			Seq:   binary.LittleEndian.Uint32(data[8:12]),
			Pid:   binary.LittleEndian.Uint32(data[12:16]),
		}

		if hdr.Len < nlmsghdrSize || int(hdr.Len) > len(data) {
			break
		}

		switch hdr.Type {
		case rtmNewAddr:
			if m.callback != nil {
				m.callback(NetworkEvent{
					Type:    NetworkEventInterfaceChanged,
					Details: "RTM_NEWADDR: new address assigned",
				})
			}
		case rtmDelAddr:
			if m.callback != nil {
				m.callback(NetworkEvent{
					Type:    NetworkEventInterfaceChanged,
					Details: "RTM_DELADDR: address removed",
				})
			}
		}

		// Advance to next message (aligned to 4 bytes)
		msgLen := hdr.Len
		if msgLen%4 != 0 {
			msgLen += 4 - (msgLen % 4)
		}
		if int(msgLen) >= len(data) {
			break
		}
		data = data[msgLen:]
	}
}

// Stop halts monitoring and releases resources.
func (m *NetlinkNetworkMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.stopped {
		return nil
	}
	m.stopped = true

	if m.stopCh != nil {
		close(m.stopCh)
	}

	if m.fd != 0 {
		syscall.Close(m.fd)
		m.fd = 0
	}

	m.wg.Wait()
	return nil
}
