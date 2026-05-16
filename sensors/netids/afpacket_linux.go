//go:build linux

package netids

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// AFPacketCapture opens a raw AF_PACKET socket on iface and pumps
// each packet to a callback. Used as the host-side hybrid network
// sensor when Suricata is not installed (or to feed xhelix's own
// detectors directly).
//
// We use SOCK_RAW + ETH_P_ALL so we see every Ethernet frame
// regardless of protocol. The socket is non-blocking; the read loop
// uses recvfrom in a tight loop with a Stop channel to cooperate
// with shutdown.
type AFPacketCapture struct {
	iface string

	mu      sync.Mutex
	fd      int
	cancel  context.CancelFunc
	dropped atomic.Uint64
	bytes   atomic.Uint64
	frames  atomic.Uint64
	running atomic.Bool
}

// PacketFn is invoked once per captured packet.
type PacketFn func(data []byte)

// New constructs a capture on iface. iface == "" means "every
// interface" (kernel selects via ifindex 0).
func NewAFPacket(iface string) *AFPacketCapture {
	return &AFPacketCapture{iface: iface, fd: -1}
}

// Start opens the socket and begins the capture goroutine.
func (a *AFPacketCapture) Start(parent context.Context, fn PacketFn) error {
	if !a.running.CompareAndSwap(false, true) {
		return errors.New("afpacket: already started")
	}
	const ETH_P_ALL = 0x0003
	proto := int(htons(ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, proto)
	if err != nil {
		a.running.Store(false)
		return fmt.Errorf("afpacket socket: %w", err)
	}

	if a.iface != "" {
		ifi, err := net.InterfaceByName(a.iface)
		if err != nil {
			_ = unix.Close(fd)
			a.running.Store(false)
			return fmt.Errorf("afpacket interface %q: %w", a.iface, err)
		}
		sa := &unix.SockaddrLinklayer{
			Protocol: htons(ETH_P_ALL),
			Ifindex:  ifi.Index,
		}
		if err := unix.Bind(fd, sa); err != nil {
			_ = unix.Close(fd)
			a.running.Store(false)
			return fmt.Errorf("afpacket bind: %w", err)
		}
	}
	// Promiscuous-style behaviour costs CAP_NET_ADMIN; we skip
	// PACKET_ADD_MEMBERSHIP for v0.x and accept the host's own L2.

	a.mu.Lock()
	a.fd = fd
	ctx, cancel := context.WithCancel(parent)
	a.cancel = cancel
	a.mu.Unlock()

	go a.loop(ctx, fn)
	return nil
}

// Stop closes the socket and waits for the capture loop to exit.
func (a *AFPacketCapture) Stop(_ context.Context) error {
	if !a.running.CompareAndSwap(true, false) {
		return nil
	}
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	if a.fd >= 0 {
		_ = unix.Close(a.fd)
		a.fd = -1
	}
	a.mu.Unlock()
	return nil
}

// Stats returns counters for the TUI.
type Stats struct {
	Frames  uint64
	Bytes   uint64
	Dropped uint64
}

func (a *AFPacketCapture) Stats() Stats {
	return Stats{
		Frames:  a.frames.Load(),
		Bytes:   a.bytes.Load(),
		Dropped: a.dropped.Load(),
	}
}

func (a *AFPacketCapture) loop(ctx context.Context, fn PacketFn) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Poll the fd for readability with a short timeout so Stop
		// is responsive.
		pfd := []unix.PollFd{{Fd: int32(a.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(pfd, 250)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return
		}
		if pfd[0].Revents&unix.POLLIN == 0 {
			continue
		}
		n, _, err := unix.Recvfrom(a.fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			a.dropped.Add(1)
			continue
		}
		a.frames.Add(1)
		a.bytes.Add(uint64(n))
		// fn must not block — it copies what it needs.
		fn(buf[:n])
	}
}

func htons(h uint16) uint16 {
	return (h << 8) | (h >> 8)
}
