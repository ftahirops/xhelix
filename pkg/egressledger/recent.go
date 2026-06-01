package egressledger

import (
	"encoding/gob"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ProcEvent is one (PID → dest) observation captured by the recent-
// events ring. The country drilldown joins these with proctree data
// to answer "which PIDs touched this country in the last N minutes",
// even for processes that have since exited.
type ProcEvent struct {
	Time           time.Time
	Binary         string
	Comm           string
	PID            uint32
	PPID           uint32
	UID            uint32
	DestIP         string
	DestPort       uint16
	SrcPort        uint16
	Role           string
	BytesOut       uint64
	BytesIn        uint64
	SNI            string
	ContainerID    string
	ContainerClass string
	Unit           string
	ServiceRole    string
	ParentComm     string
	L7Protocol     string
}

// recentRing is a bounded FIFO of ProcEvent for short-term forensic
// recall. Drops oldest on overflow. Independent of the aggregated
// FlowKey ring — keeps PID cardinality OUT of the aggregation path.
type recentRing struct {
	mu   sync.Mutex
	buf  []ProcEvent
	cap  int
	head int // next write
	n    int
}

func newRecentRing(cap int) *recentRing {
	if cap <= 0 {
		cap = 65536
	}
	return &recentRing{buf: make([]ProcEvent, cap), cap: cap}
}

func (r *recentRing) push(e ProcEvent) {
	r.mu.Lock()
	r.buf[r.head] = e
	r.head = (r.head + 1) % r.cap
	if r.n < r.cap {
		r.n++
	}
	r.mu.Unlock()
}

// query returns events in [since, now] matching dstSet (if non-nil)
// and/or binary (if non-empty). Newest first.
func (r *recentRing) query(since time.Time, dstSet map[string]bool, binary string, limit int) []ProcEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.n == 0 {
		return nil
	}
	out := []ProcEvent{}
	// Walk from newest backward.
	for i := 0; i < r.n; i++ {
		idx := (r.head - 1 - i + r.cap) % r.cap
		e := r.buf[idx]
		if e.Time.Before(since) {
			continue
		}
		if dstSet != nil && !dstSet[e.DestIP] {
			continue
		}
		if binary != "" && e.Binary != binary {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// observeRecent adds one event to the ring. Skipped if PID==0 (we
// have nothing useful to record without a process identity).
func (l *Ledger) observeRecent(ev Event, cidr string) {
	if l == nil || l.recent == nil || ev.PID == 0 {
		return
	}
	l.recent.push(ProcEvent{
		Time: ev.Time, Binary: ev.Binary, Comm: ev.Comm,
		PID: ev.PID, PPID: ev.PPID, UID: ev.UID,
		DestIP: ipString(ev.DestIP), DestPort: ev.DestPort,
		SrcPort: ev.SrcPort, Role: ev.Role,
		BytesOut: ev.BytesOut, BytesIn: ev.BytesIn,
		SNI:            ev.SNI,
		ContainerID:    ev.ContainerID,
		ContainerClass: ev.ContainerClass,
		Unit:           ev.Unit,
		ServiceRole:    ev.ServiceRole,
		ParentComm:     ev.ParentComm,
		L7Protocol:     ev.L7Protocol,
	})
	_ = cidr
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// QueryRecent is the public accessor used by the web layer.
func (l *Ledger) QueryRecent(since time.Time, dstSet map[string]bool, binary string, limit int) []ProcEvent {
	if l == nil || l.recent == nil {
		return nil
	}
	return l.recent.query(since, dstSet, binary, limit)
}

// snapshot returns a copy of all live ring entries newest-first.
func (r *recentRing) snapshot() []ProcEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ProcEvent, 0, r.n)
	for i := 0; i < r.n; i++ {
		idx := (r.head - 1 - i + r.cap) % r.cap
		out = append(out, r.buf[idx])
	}
	return out
}

// restore replaces the ring contents with the supplied events (oldest
// first). Used at startup after gob-decoding from disk.
func (r *recentRing) restore(evs []ProcEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.buf {
		r.buf[i] = ProcEvent{}
	}
	r.head = 0
	r.n = 0
	for _, e := range evs {
		r.buf[r.head] = e
		r.head = (r.head + 1) % r.cap
		if r.n < r.cap {
			r.n++
		}
	}
}

// flushRecent persists the recent ring to disk. Called from Tick().
// Atomic via tmp+rename. Best-effort; errors are logged but not fatal.
func (l *Ledger) flushRecent() {
	if l == nil || l.recent == nil {
		return
	}
	path := filepath.Join(l.opts.Dir, "recent.gob")
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return
	}
	// Snapshot newest-first; we want oldest-first on disk so restore is
	// natural.
	snap := l.recent.snapshot()
	out := make([]ProcEvent, len(snap))
	for i, e := range snap {
		out[len(snap)-1-i] = e
	}
	enc := gob.NewEncoder(f)
	err = enc.Encode(out)
	f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return
	}
	_ = os.Rename(tmp, path)
}

// loadRecent restores the recent ring from disk at startup. Drops any
// entries older than maxAge (default 24h) so a long-stopped daemon
// doesn't bring back ancient data.
func (l *Ledger) loadRecent(maxAge time.Duration) {
	if l == nil || l.recent == nil {
		return
	}
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	path := filepath.Join(l.opts.Dir, "recent.gob")
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	var evs []ProcEvent
	if err := gob.NewDecoder(f).Decode(&evs); err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	kept := evs[:0]
	for _, e := range evs {
		if e.Time.After(cutoff) {
			kept = append(kept, e)
		}
	}
	l.recent.restore(kept)
}

// inferRole returns "server" when the local end of the flow is a
// listening service, "client" when the remote end is. Uses two
// signals in priority order:
//
//  1. The host-wide listening-port cache (authoritative for custom
//     apps on non-standard ports — refreshed from /proc/net/tcp
//     every 15s).
//  2. A static well-known-port set (fallback when the cache is
//     empty, e.g. very early after daemon start).
func inferRole(srcPort, dstPort uint16) string {
	// Authoritative: this host is listening on srcPort → we are the
	// server in this flow; bytes are replies.
	if srcPort > 0 && localPortIsListening(srcPort) && !localPortIsListening(dstPort) {
		return "server"
	}
	// Authoritative: remote end's port is one we listen on locally —
	// implausible for a real client connection. Skip.
	wellKnown := func(p uint16) bool {
		switch p {
		case 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
			3306, 5432, 6379, 9200, 27017, 8080, 8443, 8081, 8086, 9081:
			return true
		}
		return false
	}
	if srcPort > 0 && wellKnown(srcPort) && !wellKnown(dstPort) {
		return "server"
	}
	if dstPort > 0 && wellKnown(dstPort) && !wellKnown(srcPort) {
		return "client"
	}
	return ""
}
