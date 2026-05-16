// Package beacon detects periodic outbound network connections that
// look like a command-and-control callback.
//
// Why this catches elite operators when nothing else does: every C2
// framework — Cobalt Strike, Sliver, Mythic, Brute Ratel, custom Go
// implants — has the same shape. The implant calls home on a
// schedule. Sleep + jitter are configurable, but the resulting
// inter-arrival distribution still has telltale statistics:
//
//   - count over a window: many calls to the same destination
//   - tight clustering: the coefficient of variation (stddev/mean) of
//     inter-arrival times is small for a beacon (typically < 0.3)
//     compared to a normal interactive process (>1)
//   - persistence: a beacon survives over hours, not seconds
//
// We don't try to decode TLS or fingerprint payloads; we just observe
// the rhythm. That works against domain-fronted CDN-fronted fully-
// encrypted custom protocols. As long as the implant talks home on a
// schedule, this catches it.
//
// Inputs are simple "outbound connect" events: pid, comm, dst_ip,
// dst_port, timestamp. Sources: pkg/sensors/ebpf (tcp_connect kprobe)
// or sensors/netids/afpacket. The detector keeps a sliding window
// per (pid, dst_ip, dst_port) tuple and emits an alert when the
// statistics cross thresholds.
//
// State is in-memory only. A daemon restart loses learning, which is
// fine: a real beacon will resume its schedule and we'll re-learn
// within a window.
package beacon

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Event is one observed outbound connect.
type Event struct {
	PID     uint32
	Comm    string
	DstIP   string
	DstPort uint16
	At      time.Time
}

// Verdict is what the detector returns when it spots a beacon.
type Verdict struct {
	Key       Key
	Count     int
	MeanGap   time.Duration
	JitterCV  float64       // stddev / mean (lower = tighter)
	First     time.Time
	Last      time.Time
	Comm      string
}

// Key identifies a (pid, dst) tuple. We deliberately key on PID, not
// just dst, so the alert names the offending process — multiple
// processes hitting the same destination with different schedules
// each get their own track.
type Key struct {
	PID     uint32
	DstIP   string
	DstPort uint16
}

// Config tunes the detector.
type Config struct {
	// MinSamples is the minimum count before we emit a verdict.
	// Lower catches faster-beaconing implants; higher reduces FPs
	// for legitimate periodic services (NTP, monitoring agents).
	// Default: 8.
	MinSamples int
	// MaxJitterCV is the upper bound on stddev/mean. A scheduler
	// running every 60s ± 15s has CV ≈ 0.25; an interactive process
	// has CV ≫ 1. Default: 0.35.
	MaxJitterCV float64
	// MinSpan is the minimum elapsed time between First and Last
	// before we trust the verdict. Filters out short bursts that
	// happen to look periodic. Default: 5 minutes.
	MinSpan time.Duration
	// MaxSamples bounds memory per track. Default: 64.
	MaxSamples int
	// IdleTTL purges tracks that haven't seen an event recently.
	// Default: 1 hour.
	IdleTTL time.Duration
	// AllowList of dst IPs / hostnames that always pass — NTP, the
	// org's monitoring SaaS, etc. Match by exact IP string.
	AllowList map[string]bool
}

// Detector keeps per-key sliding windows.
type Detector struct {
	cfg Config

	mu     sync.Mutex
	tracks map[Key]*track
	verdicts map[Key]time.Time // last-emitted, for de-dup
}

type track struct {
	gaps    []time.Duration
	first   time.Time
	last    time.Time
	comm    string
}

// New builds a detector with sane defaults filled in.
func New(cfg Config) *Detector {
	if cfg.MinSamples == 0 {
		cfg.MinSamples = 8
	}
	if cfg.MaxJitterCV == 0 {
		cfg.MaxJitterCV = 0.35
	}
	if cfg.MinSpan == 0 {
		cfg.MinSpan = 5 * time.Minute
	}
	if cfg.MaxSamples == 0 {
		cfg.MaxSamples = 64
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = time.Hour
	}
	return &Detector{
		cfg:      cfg,
		tracks:   map[Key]*track{},
		verdicts: map[Key]time.Time{},
	}
}

// Observe records an outbound connect. If, with this event, the track
// crosses the beacon thresholds, returns a non-nil Verdict; otherwise
// returns nil.
//
// The detector debounces: once a verdict fires for a key, we suppress
// further verdicts for that key for cfg.IdleTTL. The caller can rely
// on a non-nil return being a fresh detection worth alerting on.
func (d *Detector) Observe(e Event) *Verdict {
	if d.cfg.AllowList != nil && d.cfg.AllowList[e.DstIP] {
		return nil
	}
	k := Key{PID: e.PID, DstIP: e.DstIP, DstPort: e.DstPort}

	d.mu.Lock()
	defer d.mu.Unlock()

	t, ok := d.tracks[k]
	if !ok {
		t = &track{first: e.At, last: e.At, comm: e.Comm}
		d.tracks[k] = t
		return nil
	}
	gap := e.At.Sub(t.last)
	t.last = e.At
	if e.Comm != "" {
		t.comm = e.Comm
	}
	t.gaps = append(t.gaps, gap)
	if len(t.gaps) > d.cfg.MaxSamples {
		t.gaps = t.gaps[len(t.gaps)-d.cfg.MaxSamples:]
	}

	if len(t.gaps) < d.cfg.MinSamples {
		return nil
	}
	if t.last.Sub(t.first) < d.cfg.MinSpan {
		return nil
	}
	mean, cv := stats(t.gaps)
	if cv > d.cfg.MaxJitterCV {
		return nil
	}
	// De-dup: don't re-emit for the same key within IdleTTL.
	if last, ok := d.verdicts[k]; ok && e.At.Sub(last) < d.cfg.IdleTTL {
		return nil
	}
	d.verdicts[k] = e.At
	return &Verdict{
		Key:      k,
		Count:    len(t.gaps) + 1, // gaps = N samples ⇒ N+1 events
		MeanGap:  mean,
		JitterCV: cv,
		First:    t.first,
		Last:     t.last,
		Comm:     t.comm,
	}
}

// Sweep purges idle tracks. Run on a 1-min ticker.
func (d *Detector) Sweep(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.tracks {
		if now.Sub(t.last) > d.cfg.IdleTTL {
			delete(d.tracks, k)
		}
	}
	for k, ts := range d.verdicts {
		if now.Sub(ts) > 24*time.Hour {
			delete(d.verdicts, k)
		}
	}
}

// Snapshot returns a copy of current tracks for the dashboard.
type TrackView struct {
	Key       Key
	Comm      string
	Samples   int
	MeanGap   time.Duration
	JitterCV  float64
	Span      time.Duration
}

// Tracks returns a sorted view of the current sliding-window state,
// useful for the doctor / dashboard "in-flight beacons" panel.
func (d *Detector) Tracks() []TrackView {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]TrackView, 0, len(d.tracks))
	for k, t := range d.tracks {
		if len(t.gaps) < 2 {
			continue
		}
		mean, cv := stats(t.gaps)
		out = append(out, TrackView{
			Key:      k,
			Comm:     t.comm,
			Samples:  len(t.gaps) + 1,
			MeanGap:  mean,
			JitterCV: cv,
			Span:     t.last.Sub(t.first),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].JitterCV < out[j].JitterCV })
	return out
}

// stats returns mean and coefficient-of-variation of a duration slice.
// Returns (0,0) on empty / single-sample / zero-mean input.
//
// Uses the Bessel-corrected sample variance (denominator n-1) so the
// CV is statistically correct on small samples — the prior population
// formula halved CV at n=2 and could fire false positives when callers
// configured a low MinSamples.
func stats(gaps []time.Duration) (time.Duration, float64) {
	if len(gaps) < 2 {
		return 0, 0
	}
	var sum int64
	for _, g := range gaps {
		sum += int64(g)
	}
	mean := sum / int64(len(gaps))
	if mean == 0 {
		return 0, 0
	}
	var ssd float64
	for _, g := range gaps {
		d := float64(int64(g) - mean)
		ssd += d * d
	}
	stddev := math.Sqrt(ssd / float64(len(gaps)-1))
	return time.Duration(mean), stddev / float64(mean)
}
