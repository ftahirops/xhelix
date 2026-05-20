// Package evidence aggregates repeated alert firings into per-minute
// buckets. Per ROADMAP.md P2.4:
//
//   Bucket key: (rule_id, kind, actor_exe_sha, target_class, cgroup,
//   origin_type, 1-min window)
//
// What this prevents: a noisy rule firing 60 times in a minute
// emerges as one bucket with count=60 + first_seen + last_seen + up
// to 8 sample event ids, not 60 line items in an operator's queue.
//
// What this enables: operator-marked buckets become candidate rules.
// "This bucket has fired 4000 times across 12 hosts with the same
// (rule, kind, exe_sha) — promote it to a real rule."
//
// In-memory by design for v1. Buckets age out via Sweep(cutoff);
// persistence is a future P5 enhancement (likely an evidence_buckets
// table in the cold store, mirrored from this aggregator's snapshot
// on each sweep tick).
package evidence

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Bucket is one aggregated rollup. Identical key → same bucket; same
// bucket grows count + last_seen + sample list (capped).
type Bucket struct {
	Key            string         `json:"key"`
	RuleID         string         `json:"rule_id"`
	Kind           string         `json:"kind"`
	ActorExeSHA    string         `json:"actor_exe_sha,omitempty"`
	TargetClass    string         `json:"target_class,omitempty"`
	CGroupID       uint64         `json:"cgroup_id,omitempty"`
	OriginType     string         `json:"origin_type,omitempty"`
	WindowStart    time.Time      `json:"window_start"`
	FirstSeen      time.Time      `json:"first_seen"`
	LastSeen       time.Time      `json:"last_seen"`
	Count          uint64         `json:"count"`
	MaxSeverity    model.Severity `json:"max_severity"`
	SampleEventIDs []string       `json:"sample_event_ids,omitempty"`
	Promoted       bool           `json:"promoted,omitempty"`
}

// Options configures the Aggregator.
type Options struct {
	// MaxBuckets caps the in-memory map. When at cap, Observe drops
	// the oldest-LastSeen non-promoted bucket. Default: 16384.
	MaxBuckets int

	// MaxSamples is the cap on SampleEventIDs per bucket. Default: 8.
	MaxSamples int

	// Window is the bucket time-granularity. Default: 1 minute.
	Window time.Duration
}

// Aggregator holds the live bucket map.
type Aggregator struct {
	mu      sync.Mutex
	buckets map[string]*Bucket

	maxBuckets int
	maxSamples int
	window     time.Duration

	observed atomic.Uint64
	dropped  atomic.Uint64
	swept    atomic.Uint64
}

// New constructs an Aggregator.
func New(opts Options) *Aggregator {
	if opts.MaxBuckets <= 0 {
		opts.MaxBuckets = 16384
	}
	if opts.MaxSamples <= 0 {
		opts.MaxSamples = 8
	}
	if opts.Window <= 0 {
		opts.Window = time.Minute
	}
	return &Aggregator{
		buckets:    make(map[string]*Bucket, opts.MaxBuckets/4),
		maxBuckets: opts.MaxBuckets,
		maxSamples: opts.MaxSamples,
		window:     opts.Window,
	}
}

// Observe merges an alert into its matching bucket. Creates the
// bucket on first hit. Returns the post-merge Bucket pointer (read-only
// for the caller — do not mutate).
func (a *Aggregator) Observe(alert *model.Alert) *Bucket {
	if alert == nil || alert.RuleID == "" {
		return nil
	}
	a.observed.Add(1)

	now := alert.Event.Time
	if now.IsZero() {
		now = time.Now()
	}
	windowStart := now.Truncate(a.window)

	exeSHA := alert.Event.Tags["exe_sha"]
	targetClass := alert.Event.Tags["data_classes"]
	originType := alert.Event.Tags["origin_type"]

	keyStr := bucketKeyAt(alert.RuleID, alert.Event.Sensor, exeSHA, targetClass, alert.Event.CGroupID, originType, windowStart)

	a.mu.Lock()
	defer a.mu.Unlock()

	if b, ok := a.buckets[keyStr]; ok {
		// Existing bucket: merge.
		b.Count++
		if now.After(b.LastSeen) {
			b.LastSeen = now
		}
		if alert.Event.Severity > b.MaxSeverity {
			b.MaxSeverity = alert.Event.Severity
		}
		if len(b.SampleEventIDs) < a.maxSamples {
			b.SampleEventIDs = append(b.SampleEventIDs, alert.Event.ID.String())
		}
		return b
	}

	// New bucket — but first, evict if we're at capacity.
	if len(a.buckets) >= a.maxBuckets {
		a.evictOldestLocked()
	}

	b := &Bucket{
		Key:            keyStr,
		RuleID:         alert.RuleID,
		Kind:           alert.Event.Sensor,
		ActorExeSHA:    exeSHA,
		TargetClass:    targetClass,
		CGroupID:       alert.Event.CGroupID,
		OriginType:     originType,
		WindowStart:    windowStart,
		FirstSeen:      now,
		LastSeen:       now,
		Count:          1,
		MaxSeverity:    alert.Event.Severity,
		SampleEventIDs: []string{alert.Event.ID.String()},
	}
	a.buckets[keyStr] = b
	return b
}

// bucketKeyAt produces a canonical opaque key. Hashes all key
// dimensions plus the window-start so different windows for the same
// (rule, kind, ...) tuple are distinct buckets.
func bucketKeyAt(rule, kind, exeSHA, targetClass string, cgroup uint64, originType string, window time.Time) string {
	parts := []string{
		rule, kind, exeSHA, targetClass,
		strconv.FormatUint(cgroup, 10),
		originType,
		strconv.FormatInt(window.Unix(), 10),
	}
	// Hash for compactness — full string would be operator-readable
	// but waste memory at 16k+ buckets.
	sum := sha1.Sum([]byte(strings.Join(parts, "\x1f"))) // ASCII unit-separator
	return hex.EncodeToString(sum[:])
}

// evictOldestLocked drops the bucket with the oldest LastSeen among
// non-promoted buckets. Caller holds the lock.
func (a *Aggregator) evictOldestLocked() {
	var oldestKey string
	var oldestT time.Time
	for k, b := range a.buckets {
		if b.Promoted {
			continue
		}
		if oldestKey == "" || b.LastSeen.Before(oldestT) {
			oldestKey = k
			oldestT = b.LastSeen
		}
	}
	if oldestKey != "" {
		delete(a.buckets, oldestKey)
		a.dropped.Add(1)
	}
}

// Get returns the bucket for key, if present.
func (a *Aggregator) Get(key string) (Bucket, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.buckets[key]
	if !ok {
		return Bucket{}, false
	}
	return *b, true
}

// Snapshot returns a copy of every bucket. Order is by LastSeen
// descending (most recent first) — convenient for operator UI.
func (a *Aggregator) Snapshot() []Bucket {
	a.mu.Lock()
	out := make([]Bucket, 0, len(a.buckets))
	for _, b := range a.buckets {
		out = append(out, *b)
	}
	a.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// Promote marks a bucket for operator consideration as a candidate
// rule. Promoted buckets are not evicted by capacity pressure.
// Returns false if the key doesn't exist.
func (a *Aggregator) Promote(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.buckets[key]
	if !ok {
		return false
	}
	b.Promoted = true
	return true
}

// Unpromote clears the promotion flag.
func (a *Aggregator) Unpromote(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, ok := a.buckets[key]
	if !ok {
		return false
	}
	b.Promoted = false
	return true
}

// Sweep removes buckets whose LastSeen is before cutoff AND that
// are not promoted. Returns count removed.
func (a *Aggregator) Sweep(cutoff time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, b := range a.buckets {
		if b.Promoted {
			continue
		}
		if b.LastSeen.Before(cutoff) {
			delete(a.buckets, k)
			n++
		}
	}
	a.swept.Add(uint64(n))
	return n
}

// Stats is the snapshot for health.snapshot / LocalAPI.
type Stats struct {
	Buckets      int    `json:"buckets"`
	MaxBuckets   int    `json:"max_buckets"`
	Promoted     int    `json:"promoted"`
	Observed     uint64 `json:"observed"`
	Dropped      uint64 `json:"dropped"`
	Swept        uint64 `json:"swept"`
	WindowSecs   int    `json:"window_secs"`
}

// Stats returns counter snapshot.
func (a *Aggregator) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	promoted := 0
	for _, b := range a.buckets {
		if b.Promoted {
			promoted++
		}
	}
	return Stats{
		Buckets:    len(a.buckets),
		MaxBuckets: a.maxBuckets,
		Promoted:   promoted,
		Observed:   a.observed.Load(),
		Dropped:    a.dropped.Load(),
		Swept:      a.swept.Load(),
		WindowSecs: int(a.window / time.Second),
	}
}
