// Package baseline aggregates events into per-binary, per-hour
// feature vectors. The result is the "ledger of normal" we score
// future events against — and the data we'd ship to a fleet hub for
// cross-host learning.
//
// Phase 1 scope: feature extraction + persistence only. No scoring,
// no upload, no ML. Once we have a week of data on real hosts we'll
// know whether the chosen features are predictive enough to invest
// in the rest of the stack.
//
// Why per-binary: the unit of behavioural normality is the binary,
// not the host. nginx behaves like nginx whether it runs on web-01
// or web-99. A per-host baseline mixes nginx, sshd, cron, etc. into
// noise; a per-binary baseline is much sharper.
//
// Why hourly: long enough to smooth out per-event noise, short enough
// that rare events still appear in some window. Day-of-week patterns
// emerge naturally over 7 days of hourly windows.
//
// What we project from each event:
//
//   syscalls      counts of (sensor or syscall name)         — what it does
//   children      set+counts of child comm names              — what it spawns
//   endpoints     set+counts of (CIDR/16, port) tuples       — what it talks to
//   file_writes   set+counts of write target paths           — what it touches
//   uid_dist      counts of UIDs the binary ran as           — who runs it
//
// We deliberately keep cardinality bounded: top-N truncation per
// window before persistence so a runaway binary can't blow up storage.
package baseline

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Endpoint is the (CIDR/16, port) tuple — coarser than per-IP so we
// pick up "talking to AWS us-east" rather than "talking to specifically
// these 50 IPs". /16 + port survives load-balancer churn.
type Endpoint struct {
	CIDR16 string `json:"cidr16"` // "203.0.113.0/16"
	Port   uint16 `json:"port"`
}

// Window is one (binary, hour) feature record.
type Window struct {
	Binary     string             `json:"binary"`
	Hour       time.Time          `json:"hour"`        // truncated to hour
	Events     uint64             `json:"events"`      // total events in window
	Syscalls   map[string]uint64  `json:"syscalls"`    // sensor/syscall → count
	Children   map[string]uint64  `json:"children"`    // child comm → count
	Endpoints  map[string]uint64  `json:"endpoints"`   // "cidr:port" → count
	FileWrites map[string]uint64  `json:"file_writes"` // path → count
	UIDs       map[uint32]uint64  `json:"uids"`        // uid → count
	Severities map[string]uint64  `json:"severities"`  // sensor severity tally
}

// Aggregator keeps the in-memory window state.
//
// State model:
//   tracks[(binary, hour)] = *Window
//
// Caller drives time progress via Observe(now=event.Timestamp). When
// an event arrives whose hour is older than (newest_hour - keepHours),
// older windows are flushed. Flushing also happens when a window's
// cardinality exceeds caps.
type Aggregator struct {
	cfg    Config
	mu     sync.Mutex
	tracks map[key]*Window
	// flushQ holds windows ready for persistence; FlushReady() drains.
	flushQ []*Window
}

type key struct {
	binary string
	hour   int64 // unix seconds, truncated
}

// Config tunes feature extraction.
type Config struct {
	// KeepHours is how many hours of windows we hold in memory before
	// flushing the tail. 2 = current + previous hour. Default 2.
	KeepHours int
	// MaxKeysPerWindow caps every map field at top-N to bound memory
	// per (binary, hour). Truncation happens lazily on flush. Default 64.
	MaxKeysPerWindow int
	// IgnoreBinaries skips events from these comms entirely. Useful
	// to drop the daemon's own activity from baselines. Default empty.
	IgnoreBinaries map[string]bool
}

// NewAggregator returns an aggregator with sane defaults.
//
// Note: this package also exposes New() which returns a LOLBin
// tracker. The LOLBin tracker is a separate, narrower baseline
// (parent→child invocations) that long predates this aggregator;
// they coexist in the same package because both are "baselines of
// normal" — the aggregator is the general feature-vector record,
// the LOLBin tracker is a specific behavioural rule on top.
func NewAggregator(cfg Config) *Aggregator {
	if cfg.KeepHours <= 0 {
		cfg.KeepHours = 2
	}
	if cfg.MaxKeysPerWindow <= 0 {
		cfg.MaxKeysPerWindow = 64
	}
	if cfg.IgnoreBinaries == nil {
		cfg.IgnoreBinaries = map[string]bool{}
	}
	return &Aggregator{
		cfg:    cfg,
		tracks: map[key]*Window{},
	}
}

// Observe folds an event into the running windows.
//
// The "binary" identity is event.Image when present, else event.Comm.
// Events with neither are skipped — they can't be associated with a
// behavioural baseline.
func (a *Aggregator) Observe(e model.Event) {
	binary := e.Image
	if binary == "" {
		binary = e.Comm
	}
	if binary == "" {
		// Fall back to sensor name. Many sensors (fim, posture, heartbeat,
		// netids) carry their detail in Tags rather than .Comm/.Image —
		// using the sensor as the identity gives us per-sensor aggregates
		// (file_writes per fim, query rates per netids, etc.) which are
		// still useful baseline data. When sensors are upgraded to attribute
		// writer/source pid+exe, those fields will start populating
		// naturally and we'll get per-actual-binary aggregates.
		binary = e.Sensor
	}
	if binary == "" {
		return
	}
	if a.cfg.IgnoreBinaries[binary] || a.cfg.IgnoreBinaries[e.Comm] || a.cfg.IgnoreBinaries[e.Sensor] {
		return
	}

	hour := e.Time.Truncate(time.Hour)
	k := key{binary: binary, hour: hour.Unix()}

	a.mu.Lock()
	defer a.mu.Unlock()

	w, ok := a.tracks[k]
	if !ok {
		w = newWindow(binary, hour)
		a.tracks[k] = w
	}

	w.Events++
	if e.Sensor != "" {
		w.Syscalls[e.Sensor]++
	}
	if e.UID != 0 || hasUIDTag(e) {
		w.UIDs[e.UID]++
	}

	// Severities is a coarse stress signal: even before we fire alerts,
	// a binary suddenly producing more high-severity events than usual
	// is a feature.
	w.Severities[e.Severity.String()]++

	// Children: when an exec event names a parent, attribute the child
	// comm to the parent's window.
	if parent := tagOr(e, "parent_comm", "ppid_comm"); parent != "" && e.Comm != "" && e.Comm != parent {
		// This event represents `parent → e.Comm`. Attribute to parent's window.
		pk := key{binary: parent, hour: hour.Unix()}
		pw, ok := a.tracks[pk]
		if !ok {
			pw = newWindow(parent, hour)
			a.tracks[pk] = pw
		}
		pw.Children[e.Comm]++
	}

	// Network endpoint: any tag with dst_ip + dst_port.
	if dst := e.Tags["dst_ip"]; dst != "" {
		if cidr := cidr16(dst); cidr != "" {
			port := uint16(0)
			if p := e.Tags["dst_port"]; p != "" {
				if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
					port = uint16(n)
				}
			}
			ek := cidr + ":" + strconv.Itoa(int(port))
			w.Endpoints[ek]++
		}
	}

	// File writes: any FIM event with path.
	if (strings.HasPrefix(e.Sensor, "fim") || e.Tags["op"] == "write" ||
		e.Tags["event_type"] == "fim_write") && e.Tags["path"] != "" {
		w.FileWrites[e.Tags["path"]]++
	}

	// Mark older windows for flushing.
	a.maybeFlushOldUnlocked(hour)
}

// FlushReady atomically returns every window queued for persistence
// and resets the queue. Caller writes them to durable storage.
//
// Also drains in-memory windows older than KeepHours+now relative to
// the latest observed event — even if we never get a "newer" event,
// stale windows shouldn't sit forever.
func (a *Aggregator) FlushReady(now time.Time) []*Window {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.maybeFlushOldUnlocked(now)
	out := a.flushQ
	a.flushQ = nil
	for _, w := range out {
		w.truncateTopN(a.cfg.MaxKeysPerWindow)
	}
	return out
}

// FlushAll drains every in-memory window. Call at shutdown.
func (a *Aggregator) FlushAll() []*Window {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := a.flushQ
	a.flushQ = nil
	for _, w := range a.tracks {
		w.truncateTopN(a.cfg.MaxKeysPerWindow)
		out = append(out, w)
	}
	a.tracks = map[key]*Window{}
	return out
}

// Stats reports current aggregator state for the dashboard.
type Stats struct {
	OpenWindows int
	QueuedFlush int
	Binaries    int
}

func (a *Aggregator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	bins := map[string]struct{}{}
	for k := range a.tracks {
		bins[k.binary] = struct{}{}
	}
	return Stats{
		OpenWindows: len(a.tracks),
		QueuedFlush: len(a.flushQ),
		Binaries:    len(bins),
	}
}

// maybeFlushOldUnlocked moves windows older than KeepHours into the
// flush queue. Caller must hold a.mu.
func (a *Aggregator) maybeFlushOldUnlocked(now time.Time) {
	cutoff := now.Add(-time.Duration(a.cfg.KeepHours) * time.Hour).Unix()
	for k, w := range a.tracks {
		if k.hour < cutoff {
			a.flushQ = append(a.flushQ, w)
			delete(a.tracks, k)
		}
	}
}

func newWindow(binary string, hour time.Time) *Window {
	return &Window{
		Binary:     binary,
		Hour:       hour.UTC(),
		Syscalls:   map[string]uint64{},
		Children:   map[string]uint64{},
		Endpoints:  map[string]uint64{},
		FileWrites: map[string]uint64{},
		UIDs:       map[uint32]uint64{},
		Severities: map[string]uint64{},
	}
}

// truncateTopN keeps only the top-N highest-count keys per map. We
// run this on flush rather than on insert so cardinality scaling
// is bounded by N events of work per flush, not per insert.
func (w *Window) truncateTopN(n int) {
	w.Syscalls = topNStr(w.Syscalls, n)
	w.Children = topNStr(w.Children, n)
	w.Endpoints = topNStr(w.Endpoints, n)
	w.FileWrites = topNStr(w.FileWrites, n)
	// UIDs and Severities are naturally low-cardinality; leave intact.
}

func topNStr(m map[string]uint64, n int) map[string]uint64 {
	if len(m) <= n {
		return m
	}
	type kv struct {
		k string
		v uint64
	}
	tmp := make([]kv, 0, len(m))
	for k, v := range m {
		tmp = append(tmp, kv{k, v})
	}
	sort.Slice(tmp, func(i, j int) bool { return tmp[i].v > tmp[j].v })
	out := make(map[string]uint64, n)
	for _, p := range tmp[:n] {
		out[p.k] = p.v
	}
	return out
}

// cidr16 reduces an IPv4 address to its /16 prefix string. IPv6 maps
// to a /48. Returns "" on parse failure or for loopback/link-local
// (which aren't useful in fleet baselines).
func cidr16(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		mask := net.CIDRMask(16, 32)
		return (&net.IPNet{IP: v4.Mask(mask), Mask: mask}).String()
	}
	mask := net.CIDRMask(48, 128)
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

func tagOr(e model.Event, keys ...string) string {
	for _, k := range keys {
		if v := e.Tags[k]; v != "" {
			return v
		}
	}
	return ""
}

func hasUIDTag(e model.Event) bool {
	_, ok := e.Tags["uid"]
	return ok
}
