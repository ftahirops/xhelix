//go:build linux

// Package nfqueue wraps the netfilter NFQUEUE userspace verdict
// mechanism. The Manager opens a queue, parses each enqueued packet
// just enough to extract the 5-tuple, calls the caller-supplied
// VerdictFn, and replies ACCEPT or DROP.
//
// Safety properties:
//   - The caller must register the nft rule with `bypass` so that if
//     the daemon is too slow or dies, the kernel forwards the
//     packet on its own instead of dropping it.
//   - VerdictFn runs with a context deadline; on timeout the manager
//     returns ACCEPT (fail-open).
//   - On Stop the manager closes its netlink socket; pending packets
//     in the queue revert to the bypass behaviour.
package nfqueue

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	nfq "github.com/florianl/go-nfqueue"
	"golang.org/x/sys/unix"
)

// Proto is the L4 protocol of the queued packet.
type Proto uint8

const (
	ProtoUnknown Proto = 0
	ProtoTCP     Proto = 6
	ProtoUDP     Proto = 17
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return "unknown"
}

// Packet describes one enqueued packet that the verdict function
// inspects. The Raw bytes are the L3 packet (IP header onwards).
type Packet struct {
	Proto    Proto
	SrcIP    netip.Addr
	DstIP    netip.Addr
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	Raw      []byte
}

// Verdict is the manager's reply.
type Verdict uint8

const (
	VerdictAccept Verdict = 0
	VerdictDrop   Verdict = 1
	VerdictRepeat Verdict = 2 // re-evaluate at the start of the queueing chain
)

// VerdictFn is the per-packet decision. Implementations should
// return quickly; the manager applies a per-call deadline.
type VerdictFn func(ctx context.Context, p Packet) Verdict

// Config tunes the manager.
type Config struct {
	QueueNum     uint16
	MaxPacketLen uint32        // bytes to copy from kernel; 256 is enough for headers + first TLS bytes
	Deadline     time.Duration // per-verdict timeout; default 50ms (then fail-open accept)
	Logger       *slog.Logger
}

// Manager owns the NFQUEUE socket.
type Manager struct {
	cfg     Config
	verdict VerdictFn

	nf     *nfq.Nfqueue
	cancel context.CancelFunc
	wg     sync.WaitGroup

	stats Stats
	mu    sync.Mutex
	running atomic.Bool
}

// Stats are exported snapshots (loaded atomically).
type Stats struct {
	Enqueued  atomic.Uint64
	Accepted  atomic.Uint64
	Dropped   atomic.Uint64
	Failed    atomic.Uint64
	TimedOut  atomic.Uint64
	NotParsed atomic.Uint64
}

// New builds a Manager. Doesn't open the socket — call Start.
func New(cfg Config, fn VerdictFn) *Manager {
	if cfg.MaxPacketLen == 0 {
		cfg.MaxPacketLen = 256
	}
	if cfg.Deadline <= 0 {
		cfg.Deadline = 50 * time.Millisecond
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Manager{cfg: cfg, verdict: fn}
}

// Start opens the queue and begins handling packets. Returns an
// error if the kernel rejects the open (typically: queue already
// in use or CAP_NET_ADMIN missing).
func (m *Manager) Start(parent context.Context) error {
	if m.running.Load() {
		return errors.New("nfqueue: already running")
	}
	conf := nfq.Config{
		NfQueue:      m.cfg.QueueNum,
		MaxPacketLen: m.cfg.MaxPacketLen,
		MaxQueueLen:  1024,
		Copymode:     nfq.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
		ReadTimeout:  500 * time.Millisecond,
	}
	q, err := nfq.Open(&conf)
	if err != nil {
		return fmt.Errorf("nfqueue: open: %w", err)
	}
	m.nf = q
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.running.Store(true)
	if err := q.RegisterWithErrorFunc(ctx, m.onPacket, m.onErr); err != nil {
		_ = q.Close()
		m.nf = nil
		m.running.Store(false)
		return fmt.Errorf("nfqueue: register: %w", err)
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		<-ctx.Done()
	}()
	return nil
}

// Stop closes the queue. Pending packets revert to the nft rule's
// bypass behaviour. Idempotent.
func (m *Manager) Stop() {
	if !m.running.Load() {
		return
	}
	m.running.Store(false)
	if m.cancel != nil {
		m.cancel()
	}
	if m.nf != nil {
		_ = m.nf.Close()
		m.nf = nil
	}
	m.wg.Wait()
}

// StatsSnapshot returns a copy of current counters.
func (m *Manager) StatsSnapshot() map[string]uint64 {
	return map[string]uint64{
		"enqueued":   m.stats.Enqueued.Load(),
		"accepted":   m.stats.Accepted.Load(),
		"dropped":    m.stats.Dropped.Load(),
		"failed":     m.stats.Failed.Load(),
		"timed_out":  m.stats.TimedOut.Load(),
		"not_parsed": m.stats.NotParsed.Load(),
	}
}

func (m *Manager) onErr(err error) int {
	if err == nil {
		return 0
	}
	// Filter the noisy "no buffer space" warnings that the kernel
	// surfaces on bursts; they don't indicate a fatal condition.
	if errors.Is(err, unix.ENOBUFS) {
		return 0
	}
	m.cfg.Logger.Warn("nfqueue err", "err", err)
	return 0
}

func (m *Manager) onPacket(a nfq.Attribute) int {
	if a.PacketID == nil {
		return 0
	}
	id := *a.PacketID
	m.stats.Enqueued.Add(1)

	// Parse — fail-open on any oddity.
	var pkt Packet
	if a.Payload != nil {
		pkt = parseL3(*a.Payload)
		pkt.Raw = *a.Payload
	}
	if pkt.Proto == ProtoUnknown {
		m.stats.NotParsed.Add(1)
		_ = m.nf.SetVerdict(id, nfq.NfAccept)
		m.stats.Accepted.Add(1)
		return 0
	}

	// Call verdict with a hard deadline. If the call doesn't return
	// in time we ACCEPT — bypass kernel safety guarantees this is
	// the right default.
	ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Deadline)
	defer cancel()
	done := make(chan Verdict, 1)
	go func() { done <- m.verdict(ctx, pkt) }()
	var v Verdict
	select {
	case v = <-done:
	case <-ctx.Done():
		m.stats.TimedOut.Add(1)
		v = VerdictAccept
	}

	switch v {
	case VerdictDrop:
		if err := m.nf.SetVerdict(id, nfq.NfDrop); err != nil {
			m.stats.Failed.Add(1)
			return 0
		}
		m.stats.Dropped.Add(1)
	case VerdictRepeat:
		if err := m.nf.SetVerdict(id, nfq.NfRepeat); err != nil {
			m.stats.Failed.Add(1)
			return 0
		}
	default:
		if err := m.nf.SetVerdict(id, nfq.NfAccept); err != nil {
			m.stats.Failed.Add(1)
			return 0
		}
		m.stats.Accepted.Add(1)
	}
	return 0
}

// parseL3 extracts L3+L4 headers without allocating. Returns
// Proto=Unknown on malformed input.
func parseL3(pkt []byte) Packet {
	if len(pkt) < 1 {
		return Packet{}
	}
	v := pkt[0] >> 4
	switch v {
	case 4:
		return parseV4(pkt)
	case 6:
		return parseV6(pkt)
	}
	return Packet{}
}

func parseV4(pkt []byte) Packet {
	if len(pkt) < 20 {
		return Packet{}
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return Packet{}
	}
	proto := pkt[9]
	srcIP, _ := netip.AddrFromSlice(pkt[12:16])
	dstIP, _ := netip.AddrFromSlice(pkt[16:20])
	return parseL4(pkt[ihl:], proto, srcIP, dstIP)
}

func parseV6(pkt []byte) Packet {
	if len(pkt) < 40 {
		return Packet{}
	}
	proto := pkt[6]
	srcIP, _ := netip.AddrFromSlice(pkt[8:24])
	dstIP, _ := netip.AddrFromSlice(pkt[24:40])
	return parseL4(pkt[40:], proto, srcIP, dstIP)
}

func parseL4(body []byte, proto uint8, src, dst netip.Addr) Packet {
	p := Packet{SrcIP: src, DstIP: dst}
	switch proto {
	case 6:
		if len(body) < 14 {
			return Packet{}
		}
		p.Proto = ProtoTCP
		p.SrcPort = binary.BigEndian.Uint16(body[0:2])
		p.DstPort = binary.BigEndian.Uint16(body[2:4])
		p.TCPFlags = body[13]
	case 17:
		if len(body) < 8 {
			return Packet{}
		}
		p.Proto = ProtoUDP
		p.SrcPort = binary.BigEndian.Uint16(body[0:2])
		p.DstPort = binary.BigEndian.Uint16(body[2:4])
	default:
		return Packet{}
	}
	return p
}
