// Package snicheck detects outbound TLS connections that fail to
// present an SNI extension in their ClientHello.
//
// Why this matters: legitimate web traffic to virtual-hosted services
// (which is ~all of the internet) sets SNI. Bare-IP TLS or TLS to a
// destination without SNI is the canonical C2 / IMDS-bypass shape:
//
//   - C2 callbacks to attacker IPs that don't match a public DNS name
//   - IMDS-via-TLS reads (169.254.169.254 with TLS termination)
//   - custom-tooling backdoors that talk to a hardcoded IP
//
// Implementation: deferred evaluation.
//
//  1. Pipeline calls Note(tuple) on every outbound net_connect to a
//     TLS port (443/8443/... configurable).
//  2. A background ticker drains pending entries that are at least
//     EvalDelay old. For each, it consults connstate: if the matching
//     Conn row has SNI=="" AND has carried bytes (proving the
//     ClientHello was sent), the tuple is flagged.
//  3. Flagged tuples produce a model.Event with kind=tls_no_sni; the
//     rule engine + (in enforce mode) netban consume it.
//
// CIDR allowlist exempts known bare-IP infrastructure (time servers,
// well-known IMDS endpoints if the operator wants to keep them
// reachable, etc.). Lineage allowlist exempts processes like
// systemd-resolved, package managers, that legitimately do bare-IP
// TLS.
package snicheck

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/model"
)

// Detector runs the deferred-SNI check.
type Detector struct {
	conn       *connstate.Table
	out        chan<- model.Event
	host       string
	evalDelay  time.Duration
	tlsPorts   map[uint16]struct{}
	allowCIDRs []*net.IPNet
	allowComms map[string]struct{}

	mu      sync.Mutex
	pending []pendingEntry

	running atomic.Bool
	stats   struct {
		seen    atomic.Uint64
		flagged atomic.Uint64
		skipped atomic.Uint64
	}
}

type pendingEntry struct {
	at    time.Time
	pid   uint32
	comm  string
	image string
	uid   uint32
	dst   net.IP
	port  uint16
}

// Config carries the operator-tunable knobs.
type Config struct {
	// Host is the agent hostname stamped on emitted events.
	Host string
	// EvalDelay is the wait between Note() and the SNI check. Default
	// 800ms — long enough for a typical ClientHello to traverse the
	// kernel, short enough that the deny verdict still matters for
	// a live attacker.
	EvalDelay time.Duration
	// TLSPorts is the set of destination ports treated as TLS. If
	// empty, defaults to {443, 8443, 853, 993, 995}.
	TLSPorts []uint16
	// AllowCIDRs are destination subnets exempted from the check.
	// Useful for known-good bare-IP infrastructure (NTP servers,
	// in some deployments the cloud IMDS endpoint).
	AllowCIDRs []string
	// AllowReaderComms exempts processes (by 16-char comm name) that
	// legitimately do bare-IP TLS. Defaults include systemd-resolved,
	// apt, dnf, snapd, plus xhelix itself.
	AllowReaderComms []string
}

// New constructs a Detector.
func New(conn *connstate.Table, out chan<- model.Event, cfg Config) *Detector {
	if cfg.EvalDelay <= 0 {
		cfg.EvalDelay = 800 * time.Millisecond
	}
	d := &Detector{
		conn:       conn,
		out:        out,
		host:       cfg.Host,
		evalDelay:  cfg.EvalDelay,
		tlsPorts:   map[uint16]struct{}{},
		allowComms: map[string]struct{}{},
	}
	ports := cfg.TLSPorts
	if len(ports) == 0 {
		ports = []uint16{443, 8443, 853, 993, 995}
	}
	for _, p := range ports {
		d.tlsPorts[p] = struct{}{}
	}
	for _, c := range cfg.AllowCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			d.allowCIDRs = append(d.allowCIDRs, n)
		}
	}
	for _, c := range defaultAllowComms() {
		d.allowComms[c] = struct{}{}
	}
	for _, c := range cfg.AllowReaderComms {
		d.allowComms[c] = struct{}{}
	}
	return d
}

// defaultAllowComms covers processes that have legitimate reasons
// to do TLS without SNI (e.g. to a hardcoded IP).
func defaultAllowComms() []string {
	return []string{
		"systemd-resolve", "systemd-network", "systemd-timesync",
		"chronyd", "ntpd", "openvpn", "wireguard",
		"apt", "apt-get", "dpkg", "dnf", "yum", "snapd", "snap",
		"xhelix", "xhelixctl",
		"sshd", "ssh", "scp", "rsync",
	}
}

// Note records a TLS-port outbound connect to be checked later.
func (d *Detector) Note(pid uint32, comm, image string, uid uint32, dstIP net.IP, dstPort uint16) {
	if d == nil || !d.running.Load() {
		return
	}
	if _, ok := d.tlsPorts[dstPort]; !ok {
		return
	}
	if _, ok := d.allowComms[comm]; ok {
		d.stats.skipped.Add(1)
		return
	}
	if d.cidrAllowed(dstIP) {
		d.stats.skipped.Add(1)
		return
	}
	d.stats.seen.Add(1)
	d.mu.Lock()
	d.pending = append(d.pending, pendingEntry{
		at:    time.Now(),
		pid:   pid,
		comm:  comm,
		image: image,
		uid:   uid,
		dst:   dstIP,
		port:  dstPort,
	})
	d.mu.Unlock()
}

func (d *Detector) cidrAllowed(ip net.IP) bool {
	for _, n := range d.allowCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Start kicks off the background ticker.
func (d *Detector) Start(ctx context.Context) {
	if !d.running.CompareAndSwap(false, true) {
		return
	}
	go d.loop(ctx)
}

func (d *Detector) loop(ctx context.Context) {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.running.Store(false)
			return
		case now := <-t.C:
			d.drainOlderThan(now)
		}
	}
}

// drainOlderThan evaluates and removes entries past their deadline.
// Sorted-by-time invariant: pending is append-only with time.Now(),
// so older entries are at the front.
func (d *Detector) drainOlderThan(now time.Time) {
	cutoff := now.Add(-d.evalDelay)
	d.mu.Lock()
	keep := d.pending[:0]
	var ready []pendingEntry
	for _, e := range d.pending {
		if e.at.Before(cutoff) {
			ready = append(ready, e)
		} else {
			keep = append(keep, e)
		}
	}
	d.pending = keep
	d.mu.Unlock()

	for _, e := range ready {
		d.evaluate(e)
	}
}

// evaluate checks connstate for the tuple. If no SNI was attached
// AND the connection actually carried bytes (proving a ClientHello
// went out), emit the alert.
//
// We don't know the source port at connect time, so we can't do an
// exact Tuple lookup. Instead we snapshot the PID's connections and
// find the one matching (dst_ip, dst_port).
func (d *Detector) evaluate(e pendingEntry) {
	conns := d.conn.SnapshotByPID(e.pid)
	var matched *connstate.Conn
	dstStr := e.dst.String()
	for i := range conns {
		c := &conns[i]
		if c.Tuple.DstAddr.String() == dstStr && c.Tuple.DstPort == e.port {
			matched = c
			break
		}
	}
	if matched == nil {
		// Connect didn't land or was already swept — can't conclude
		// anything. Skip silently.
		return
	}
	if matched.SNI != "" {
		return // legitimate SNI was attached; not our case
	}
	// Require evidence of actual traffic to filter spurious failed
	// connects. The byte counters are populated by ebpf.net_bytes
	// events; if there's nothing, the ClientHello may not have been
	// sent (connection refused, mid-handshake reset, etc.).
	if matched.BytesOut == 0 {
		return
	}
	d.stats.flagged.Add(1)
	d.emit(e)
}

func (d *Detector) emit(e pendingEntry) {
	if d.out == nil {
		return
	}
	ev := model.NewEvent("snicheck", model.SeverityWarn)
	ev.Time = time.Now().UTC()
	ev.Host = d.host
	ev.PID = e.pid
	ev.Comm = e.comm
	ev.Image = e.image
	ev.UID = e.uid
	ev.Tags["kind"] = "tls_no_sni"
	ev.Tags["dst_ip"] = e.dst.String()
	ev.Tags["dst_port"] = strconv.Itoa(int(e.port))
	ev.Tags["outbound"] = "true"
	// Send non-blocking; this runs from the snicheck ticker
	// goroutine and we'd rather drop than wedge it.
	select {
	case d.out <- ev:
	default:
	}
}

// Stats returns snapshot counters for status reporting.
func (d *Detector) Stats() Stats {
	return Stats{
		Seen:    d.stats.seen.Load(),
		Flagged: d.stats.flagged.Load(),
		Skipped: d.stats.skipped.Load(),
		Pending: d.pendingLen(),
	}
}

// Stats is a snapshot for /xhelixctl status / health surfaces.
type Stats struct {
	Seen, Flagged, Skipped, Pending uint64
}

// String returns a human one-liner.
func (s Stats) String() string {
	return fmt.Sprintf("seen=%d flagged=%d skipped=%d pending=%d",
		s.Seen, s.Flagged, s.Skipped, s.Pending)
}

func (d *Detector) pendingLen() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return uint64(len(d.pending))
}

// AllowedComms returns the active reader-comm allowlist (default +
// configured). Sorted for stable output.
func (d *Detector) AllowedComms() []string {
	out := make([]string, 0, len(d.allowComms))
	for c := range d.allowComms {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
