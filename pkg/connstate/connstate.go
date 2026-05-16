// Package connstate is the live per-process connection table.
//
// It maintains a map of every TCP/UDP flow the host has opened or
// accepted, tagged with the owning pid, executable, cgroup class,
// and (when known) the DNS name the destination was resolved from.
// It runs purely in observation mode: never blocks, never drops a
// packet. See docs/NETVISIBILITY.md for the design rationale.
//
// The table is fed by three external sources:
//
//   - eBPF connect/accept/close events from sensors/ebpf
//   - DNS query/response events from sensors/dnsresolver (Phase 2)
//   - Periodic reconciliation against /proc/net/{tcp,udp} +
//     conntrack via netlink (Phase 2 — interface defined here)
//
// The table itself is goroutine-safe; all mutating methods take a
// short critical section under a single RWMutex. Reads (Snapshot,
// Lookup) take the read lock and never block writers for long.
package connstate

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/cgroupclass"
)

// State is the TCP/UDP flow lifecycle state.
type State uint8

const (
	StateUnknown     State = 0
	StateNew         State = 1 // syscall fired, no SYN yet
	StateSynSent     State = 2 // outbound SYN sent
	StateEstablished State = 3 // handshake complete (or first UDP datagram)
	StateFinWait     State = 4 // FIN seen, awaiting close
	StateClosed      State = 5 // clean shutdown
	StateReset       State = 6 // RST seen
	StateTimeout     State = 7 // reaped by reconciler
)

// String returns a stable lowercase token.
func (s State) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateSynSent:
		return "syn_sent"
	case StateEstablished:
		return "established"
	case StateFinWait:
		return "fin_wait"
	case StateClosed:
		return "closed"
	case StateReset:
		return "reset"
	case StateTimeout:
		return "timeout"
	}
	return "unknown"
}

// Proto is the L4 protocol.
type Proto uint8

const (
	ProtoUnknown Proto = 0
	ProtoTCP     Proto = 6
	ProtoUDP     Proto = 17
)

// String returns a stable lowercase token.
func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	}
	return "unknown"
}

// Direction distinguishes outbound (locally initiated) from inbound
// (accepted) flows.
type Direction uint8

const (
	DirUnknown  Direction = 0
	DirOutbound Direction = 1
	DirInbound  Direction = 2
)

// String returns a stable lowercase token.
func (d Direction) String() string {
	switch d {
	case DirOutbound:
		return "outbound"
	case DirInbound:
		return "inbound"
	}
	return "unknown"
}

// Tuple is the 5-tuple that keys a flow. SrcPort may be zero when
// the eBPF probe didn't capture it (current decoder limitation —
// see sensors/ebpf/decoder.go decodeNetEvent). In that case the key
// degenerates to a 4-tuple; multiple short-lived ephemeral-port
// connects to the same dst collapse into one Conn row, which is the
// right behaviour for the UI grouping.
type Tuple struct {
	Proto   Proto
	SrcAddr netip.Addr
	SrcPort uint16
	DstAddr netip.Addr
	DstPort uint16
}

// String returns "proto src:port -> dst:port".
func (t Tuple) String() string {
	return fmt.Sprintf("%s %s:%d -> %s:%d",
		t.Proto, t.SrcAddr, t.SrcPort, t.DstAddr, t.DstPort)
}

// Conn is one tracked flow.
type Conn struct {
	Tuple     Tuple
	Direction Direction
	State     State

	// Process attribution
	PID         uint32
	PPID        uint32
	Comm        string
	Exe         string // resolved executable path
	ExeSHA      string // hex SHA-256 of executable, when available
	CGroupClass cgroupclass.Class
	Unit        string // systemd unit or container id
	UserID      string // login uid, when ClassUser

	// DNS linkage (filled by Phase 2 dnsresolver)
	DNSName string

	// SNI from TLS ClientHello — populated by sensors/dpi when the
	// flow carries a TLS handshake the sniffer could observe.
	SNI string

	// Counters (best-effort; eBPF doesn't yet emit byte counts —
	// these get populated by the conntrack reconciler in Phase 2).
	BytesOut uint64
	BytesIn  uint64

	OpenedAt time.Time
	LastSeen time.Time
	ClosedAt time.Time
}

// IntelVerdict is set by external enrichment (pkg/intel). We carry
// it on the Conn so the UI can colour rows without a second lookup.
// "clean" / "deny" / "unknown".
type IntelVerdict string

// Table is the live conn-table.
type Table struct {
	mu    sync.RWMutex
	conns map[Tuple]*Conn

	// Per-pid index for "show all conns for pid N" without scanning
	// the whole table. Values are aliases to the same *Conn.
	byPID map[uint32]map[Tuple]*Conn

	// Per (pid, dst_ip) DNS hints from RecordDNS; consumed on
	// next OnConnect to enrich Conn.DNSName.
	dnsHints map[dnsHintKey]dnsHintEntry

	cap int
	now func() time.Time

	closed  uint64 // count of terminated flows since boot
	dropped uint64 // count of inserts dropped due to cap pressure
}

// New returns a Table with the given soft cap (cap<=0 -> 100000).
func New(cap int) *Table {
	if cap <= 0 {
		cap = 100_000
	}
	return &Table{
		conns: make(map[Tuple]*Conn, 1024),
		byPID: make(map[uint32]map[Tuple]*Conn, 256),
		cap:   cap,
		now:   time.Now,
	}
}

// ConnectEvent is the input shape for outbound connect() syscalls.
// Fields not known at the source (e.g. SrcPort from current eBPF)
// may be zero — Table tolerates this.
type ConnectEvent struct {
	Time        time.Time
	PID         uint32
	PPID        uint32
	Comm        string
	Exe         string
	ExeSHA      string
	CGroupClass cgroupclass.Class
	Unit        string
	UserID      string
	Tuple       Tuple
}

// OnConnect inserts (or refreshes) an outbound flow in StateNew. If
// the tuple already exists, fields that arrive later in the flow's
// life (process attribution from /proc, exe sha from imagecache)
// are merged in instead of overwriting the row.
func (t *Table) OnConnect(e ConnectEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := e.Time
	if now.IsZero() {
		now = t.now()
	}

	c, ok := t.conns[e.Tuple]
	if !ok {
		if len(t.conns) >= t.cap {
			if !t.evictOneLocked(now) {
				t.dropped++
				return
			}
		}
		c = &Conn{
			Tuple:     e.Tuple,
			Direction: DirOutbound,
			State:     StateNew,
			OpenedAt:  now,
		}
		t.conns[e.Tuple] = c
		t.indexInsertLocked(c)
	}
	c.LastSeen = now
	prevPID := c.PID
	mergeAttribution(c, e.PID, e.PPID, e.Comm, e.Exe, e.ExeSHA,
		e.CGroupClass, e.Unit, e.UserID)
	if prevPID == 0 && c.PID != 0 {
		t.indexInsertLocked(c)
	}
	if c.State == StateUnknown {
		c.State = StateNew
	}
	// DNS qname attribution from recent RecordDNS hints.
	if c.DNSName == "" && c.PID != 0 && c.Tuple.DstAddr.IsValid() {
		if q := t.lookupDNSHintLocked(c.PID, c.Tuple.DstAddr, now); q != "" {
			c.DNSName = q
		}
	}
}

// AcceptEvent is the input shape for inbound accept() events.
type AcceptEvent = ConnectEvent

// OnAccept inserts (or refreshes) an inbound flow in StateEstablished
// (accept() returns when the handshake is already complete).
func (t *Table) OnAccept(e AcceptEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := e.Time
	if now.IsZero() {
		now = t.now()
	}

	c, ok := t.conns[e.Tuple]
	if !ok {
		if len(t.conns) >= t.cap {
			if !t.evictOneLocked(now) {
				t.dropped++
				return
			}
		}
		c = &Conn{
			Tuple:     e.Tuple,
			Direction: DirInbound,
			State:     StateEstablished,
			OpenedAt:  now,
		}
		t.conns[e.Tuple] = c
		t.indexInsertLocked(c)
	}
	c.LastSeen = now
	prevPID := c.PID
	mergeAttribution(c, e.PID, e.PPID, e.Comm, e.Exe, e.ExeSHA,
		e.CGroupClass, e.Unit, e.UserID)
	if prevPID == 0 && c.PID != 0 {
		t.indexInsertLocked(c)
	}
}

// OnEstablished promotes an existing flow into StateEstablished. The
// conntrack reconciler calls this when it sees ESTABLISHED in
// /proc/net/nf_conntrack.
func (t *Table) OnEstablished(tup Tuple, when time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.conns[tup]; ok {
		c.State = StateEstablished
		c.LastSeen = when
	}
}

// OnClose transitions a flow to StateClosed. The row is not deleted
// immediately — it stays in the table for at least RetainAfter so
// the UI can still render "recently closed."
func (t *Table) OnClose(tup Tuple, when time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.conns[tup]; ok {
		c.State = StateClosed
		c.LastSeen = when
		c.ClosedAt = when
		t.closed++
	}
}

// OnReset transitions a flow to StateReset.
func (t *Table) OnReset(tup Tuple, when time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.conns[tup]; ok {
		c.State = StateReset
		c.LastSeen = when
		c.ClosedAt = when
		t.closed++
	}
}

// AttachDNS records that this flow's destination was the result of a
// DNS lookup for qname by the same pid (within the resolver shim's
// recency window). Phase 2 — kept as a no-op-safe entry point now.
func (t *Table) AttachDNS(tup Tuple, qname string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.conns[tup]; ok && c.DNSName == "" {
		c.DNSName = qname
	}
}

// UpdateBytes increments the byte counters on a matching flow.
// dir=0 → bytes are outbound; dir=1 → inbound. If no exact tuple
// match exists, falls back to (proto, dst, port) lookup and updates
// the first hit. Cheap & silent — never errors.
func (t *Table) UpdateBytes(tup Tuple, dir uint8, bytes uint64) {
	if bytes == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.conns[tup]; ok {
		if dir == 0 {
			c.BytesOut += bytes
		} else {
			c.BytesIn += bytes
		}
		return
	}
	for k, c := range t.conns {
		if k.Proto == tup.Proto && k.DstAddr == tup.DstAddr && k.DstPort == tup.DstPort {
			if dir == 0 {
				c.BytesOut += bytes
			} else {
				c.BytesIn += bytes
			}
			return
		}
	}
}

// AttachSNI stamps the TLS ClientHello SNI onto an existing flow.
// Lookup is on the full tuple first; if SrcPort is unknown to the
// caller (sniffer can't always associate src-port reliably), it falls
// back to a per-PID dst-IP+port match — there is rarely more than
// one TLS session per (pid, dst-ip, dst-port).
func (t *Table) AttachSNI(tup Tuple, sni string) {
	if sni == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if c, ok := t.conns[tup]; ok {
		if c.SNI == "" {
			c.SNI = sni
		}
		return
	}
	// Fallback: walk conns with matching dst tuple but any src-port.
	for k, c := range t.conns {
		if k.Proto == tup.Proto && k.DstAddr == tup.DstAddr && k.DstPort == tup.DstPort {
			if c.SNI == "" {
				c.SNI = sni
			}
			return
		}
	}
}

// RecordDNS pre-attributes a (pid, dst_ip → qname) mapping so the
// next OnConnect for that pid+ip can be enriched with the qname.
// Mappings expire after dnsAttributionTTL. Safe to call from the
// DNS observation path before the connect arrives.
func (t *Table) RecordDNS(pid uint32, qname string, ips []string) {
	if pid == 0 || qname == "" || len(ips) == 0 {
		return
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dnsHints == nil {
		t.dnsHints = make(map[dnsHintKey]dnsHintEntry, 64)
	}
	for _, ip := range ips {
		t.dnsHints[dnsHintKey{pid: pid, ip: ip}] = dnsHintEntry{qname: qname, at: now}
	}
	// Opportunistic sweep — keep the map bounded.
	if len(t.dnsHints) > 4096 {
		t.pruneDNSHintsLocked(now)
	}
}

// dnsAttributionTTL is the recency window for matching a pid's
// recent DNS answer against its next outbound connect.
const dnsAttributionTTL = 60 * time.Second

type dnsHintKey struct {
	pid uint32
	ip  string
}

type dnsHintEntry struct {
	qname string
	at    time.Time
}

func (t *Table) lookupDNSHintLocked(pid uint32, ip netip.Addr, now time.Time) string {
	if t.dnsHints == nil {
		return ""
	}
	key := dnsHintKey{pid: pid, ip: ip.String()}
	e, ok := t.dnsHints[key]
	if !ok {
		return ""
	}
	if now.Sub(e.at) > dnsAttributionTTL {
		delete(t.dnsHints, key)
		return ""
	}
	return e.qname
}

func (t *Table) pruneDNSHintsLocked(now time.Time) {
	for k, e := range t.dnsHints {
		if now.Sub(e.at) > dnsAttributionTTL {
			delete(t.dnsHints, k)
		}
	}
}

// Snapshot returns a copy of every Conn currently in the table. The
// returned values are owned by the caller. Sorted by OpenedAt desc
// so the UI gets newest first.
func (t *Table) Snapshot() []Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Conn, 0, len(t.conns))
	for _, c := range t.conns {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OpenedAt.After(out[j].OpenedAt)
	})
	return out
}

// SnapshotByPID returns Conns owned by pid.
func (t *Table) SnapshotByPID(pid uint32) []Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	m := t.byPID[pid]
	out := make([]Conn, 0, len(m))
	for _, c := range m {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OpenedAt.After(out[j].OpenedAt)
	})
	return out
}

// SnapshotByClass returns Conns whose owning process is in the given
// cgroup class. Used to power the "user apps" / "system services" /
// "containers" pre-grouped UI views.
func (t *Table) SnapshotByClass(class cgroupclass.Class) []Conn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]Conn, 0, len(t.conns)/3)
	for _, c := range t.conns {
		if c.CGroupClass == class {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].OpenedAt.After(out[j].OpenedAt)
	})
	return out
}

// Lookup returns a copy of the Conn for tup, if any.
func (t *Table) Lookup(tup Tuple) (Conn, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if c, ok := t.conns[tup]; ok {
		return *c, true
	}
	return Conn{}, false
}

// Stats is the small status struct the TUI renders.
type Stats struct {
	Live      int
	ByState   map[State]int
	ByClass   map[cgroupclass.Class]int
	Closed    uint64
	Dropped   uint64
}

// Stats returns a current count snapshot.
func (t *Table) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s := Stats{
		Live:    len(t.conns),
		ByState: make(map[State]int, 8),
		ByClass: make(map[cgroupclass.Class]int, 5),
		Closed:  t.closed,
		Dropped: t.dropped,
	}
	for _, c := range t.conns {
		s.ByState[c.State]++
		s.ByClass[c.CGroupClass]++
	}
	return s
}

// Sweep removes terminal-state flows older than retainAfter and
// also reaps stuck non-terminal flows older than idleTimeout. Call
// this from a goroutine on a ~30s cadence. Returns the number of
// entries removed.
func (t *Table) Sweep(now time.Time, retainAfter, idleTimeout time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	removed := 0
	for tup, c := range t.conns {
		switch c.State {
		case StateClosed, StateReset, StateTimeout:
			if now.Sub(c.LastSeen) >= retainAfter {
				t.removeLocked(tup)
				removed++
			}
		default:
			if idleTimeout > 0 && now.Sub(c.LastSeen) >= idleTimeout {
				c.State = StateTimeout
				c.ClosedAt = now
				t.closed++
				// Mark for next sweep — don't delete now so the UI
				// shows the transition once.
			}
		}
	}
	return removed
}

// indexInsertLocked adds c to the byPID index. Caller holds t.mu.
func (t *Table) indexInsertLocked(c *Conn) {
	if c.PID == 0 {
		return
	}
	m, ok := t.byPID[c.PID]
	if !ok {
		m = make(map[Tuple]*Conn, 4)
		t.byPID[c.PID] = m
	}
	m[c.Tuple] = c
}

// indexRemoveLocked removes a Tuple from the byPID index.
func (t *Table) indexRemoveLocked(pid uint32, tup Tuple) {
	m, ok := t.byPID[pid]
	if !ok {
		return
	}
	delete(m, tup)
	if len(m) == 0 {
		delete(t.byPID, pid)
	}
}

func (t *Table) removeLocked(tup Tuple) {
	c, ok := t.conns[tup]
	if !ok {
		return
	}
	delete(t.conns, tup)
	t.indexRemoveLocked(c.PID, tup)
}

// evictOneLocked drops the oldest closed entry, or — if no closed
// entries exist — the oldest established entry. Returns true if
// an eviction happened.
func (t *Table) evictOneLocked(now time.Time) bool {
	var (
		oldestClosed   *Conn
		oldestAny      *Conn
	)
	for _, c := range t.conns {
		switch c.State {
		case StateClosed, StateReset, StateTimeout:
			if oldestClosed == nil || c.LastSeen.Before(oldestClosed.LastSeen) {
				oldestClosed = c
			}
		}
		if oldestAny == nil || c.LastSeen.Before(oldestAny.LastSeen) {
			oldestAny = c
		}
	}
	if oldestClosed != nil {
		t.removeLocked(oldestClosed.Tuple)
		return true
	}
	if oldestAny != nil {
		t.removeLocked(oldestAny.Tuple)
		return true
	}
	return false
}

// mergeAttribution fills empty fields on c without overwriting
// already-populated ones. PID is the exception: the byPID index
// must be kept consistent if pid arrives late.
func mergeAttribution(c *Conn, pid, ppid uint32, comm, exe, exeSHA string,
	class cgroupclass.Class, unit, userID string) {
	if c.PID == 0 {
		c.PID = pid
	}
	if c.PPID == 0 {
		c.PPID = ppid
	}
	if c.Comm == "" {
		c.Comm = comm
	}
	if c.Exe == "" {
		c.Exe = exe
	}
	if c.ExeSHA == "" {
		c.ExeSHA = exeSHA
	}
	if c.CGroupClass == cgroupclass.ClassUnknown {
		c.CGroupClass = class
	}
	if c.Unit == "" {
		c.Unit = unit
	}
	if c.UserID == "" {
		c.UserID = userID
	}
}
