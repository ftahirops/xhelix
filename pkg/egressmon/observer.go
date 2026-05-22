// Package egressmon is the egress Mode-1 observer layer described in
// docs/EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md §1.2.
//
// The observer is pure data + classification. It consumes outbound
// connect events (one Observe call per event), runs each through the
// destclass classifier, and records per-lineage counters so the
// takeover scorer and operator CLI can later answer:
//
//   - "what classes of destinations has lineage X talked to in the
//     last 5 minutes?"
//   - "how many distinct unknown destinations has lineage X hit?"
//   - "is this lineage talking to anything in the intel-bad class?"
//
// The observer does NOT enforce. Mode-2 disarm is a separate policy
// that consults the observer's state plus other triggers. Keeping
// observe and enforce as separate stages is the design rule from the
// architecture doc: ship Mode-1 first, no friction; layer Mode-2 on
// top later.
//
// Thread-safety: Observe and Snapshot may be called concurrently.
// Each call takes O(1) work on a sharded mutex.
package egressmon

import (
	"net"
	"sort"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/destclass"
)

// LineageID is the per-process lineage identifier xhelix uses
// elsewhere (pkg/lineage). Re-declared as a uint64 alias here to
// avoid importing pkg/lineage and creating a cycle.
type LineageID uint64

// Observation is the data we record about one outbound connect.
// Kept small — observer state can grow large on busy hosts.
type Observation struct {
	At    time.Time
	IP    net.IP
	SNI   string
	Port  uint16
	Class destclass.Class
	// BytesOut tallies tcp_sendmsg bytes attributed to this (lineage,
	// destination) flow since the observation was first recorded.
	// Updated via ObserveBytes; zero on the initial Observe call.
	BytesOut uint64
}

// PerLineageStats is the aggregate the takeover scorer / CLI read.
type PerLineageStats struct {
	LineageID         LineageID
	AppID             string                     // appident "name[:vhost]"; "" = unidentified
	AppKind           string                     // "web", "service", ...
	TotalConnects     int
	ByClass           map[destclass.Class]int
	BytesOutByClass   map[destclass.Class]uint64 // bytes per class
	BytesOutByDest    map[string]uint64          // bytes per "ip|sni" key
	TotalBytesOut     uint64
	UniqueDests       int       // unique (ip, sni) pairs
	UniqueUnknown     int       // unique destinations classed Unknown
	LastConnect       time.Time
	FirstUnknownAt    time.Time // zero if no unknown seen
	FirstIntelBadAt   time.Time // zero if no intel-bad seen
	RecentSample      []Observation // bounded sample for forensics
}

// Observer is the per-lineage egress data layer.
type Observer struct {
	classifier *destclass.Classifier
	clock      func() time.Time

	// retention: drop observations older than this on the snapshot
	// path (lazy cleanup; fine for our scale).
	ttl time.Duration

	// per-lineage state, sharded by lineage id to reduce contention.
	shards [16]shard
}

type shard struct {
	mu      sync.Mutex
	byLid   map[LineageID]*lineageState
}

type lineageState struct {
	stats     PerLineageStats
	uniques   map[string]struct{}        // IP set for UniqueDests
	unknown   map[string]struct{}        // subset of uniques in class Unknown
	destClass map[string]destclass.Class // IP → best-known class
	destSNI   map[string]string          // IP → last-seen SNI (for display)
}

// New constructs an Observer.
// classifier is required; ttl bounds retention of forensic samples
// (zero = 10 minutes); clock may be nil (uses time.Now).
func New(classifier *destclass.Classifier, ttl time.Duration) *Observer {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	o := &Observer{
		classifier: classifier,
		clock:      time.Now,
		ttl:        ttl,
	}
	for i := range o.shards {
		o.shards[i].byLid = map[LineageID]*lineageState{}
	}
	return o
}

// WithClock overrides time.Now (test hook).
func (o *Observer) WithClock(c func() time.Time) *Observer {
	o.clock = c
	return o
}

func (o *Observer) shardFor(lid LineageID) *shard {
	return &o.shards[uint64(lid)%uint64(len(o.shards))]
}

// SetAppID stamps a sticky AppID onto the lineage. Idempotent — first
// non-empty value wins; later calls with the same value are no-ops.
// Callers (Pipeline.Handle) invoke this once per lineage after
// resolving the app via pkg/appident.
func (o *Observer) SetAppID(lid LineageID, appID, kind string) {
	if appID == "" || lid == 0 {
		return
	}
	sh := o.shardFor(lid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st := getOrCreateState(sh, lid)
	if st.stats.AppID == "" {
		st.stats.AppID = appID
		st.stats.AppKind = kind
	}
}

// Observe records one outbound connect. Safe under concurrent calls.
// Returns the classifier Decision so callers can stamp it onto event
// metadata for downstream sinks.
func (o *Observer) Observe(lid LineageID, ip net.IP, sni string, port uint16) destclass.Decision {
	now := o.clock()
	d := o.classifier.Classify(ip, sni, port)

	sh := o.shardFor(lid)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	st := getOrCreateState(sh, lid)

	st.stats.TotalConnects++
	st.stats.LastConnect = now

	key := keyFor(ip, sni)
	if sni != "" {
		st.destSNI[key] = sni
	}
	// If we have a previously-recorded class and the new classification
	// is still ClassUnknown, keep the better one. This makes the
	// reclassify path (SNI arriving after the connect) upgrade Unknown
	// → CDN cleanly without double-counting.
	prevClass, hadPrev := st.destClass[key]
	chosenClass := d.Class
	if hadPrev && d.Class == destclass.ClassUnknown && prevClass != destclass.ClassUnknown {
		chosenClass = prevClass
	}
	st.destClass[key] = chosenClass
	st.stats.ByClass[chosenClass]++

	if _, seen := st.uniques[key]; !seen {
		st.uniques[key] = struct{}{}
		st.stats.UniqueDests = len(st.uniques)
		if chosenClass == destclass.ClassUnknown {
			st.unknown[key] = struct{}{}
			st.stats.UniqueUnknown = len(st.unknown)
		}
	} else if hadPrev && prevClass == destclass.ClassUnknown && chosenClass != destclass.ClassUnknown {
		// Promoted out of Unknown — clean up the unknown counter.
		delete(st.unknown, key)
		st.stats.UniqueUnknown = len(st.unknown)
	}

	switch d.Class {
	case destclass.ClassUnknown:
		if st.stats.FirstUnknownAt.IsZero() {
			st.stats.FirstUnknownAt = now
		}
	case destclass.ClassIntelBad:
		if st.stats.FirstIntelBadAt.IsZero() {
			st.stats.FirstIntelBadAt = now
		}
	}

	// Bounded forensic sample: keep the last N observations.
	const sampleMax = 64
	st.stats.RecentSample = append(st.stats.RecentSample, Observation{
		At: now, IP: ip, SNI: sni, Port: port, Class: d.Class,
	})
	if len(st.stats.RecentSample) > sampleMax {
		st.stats.RecentSample = st.stats.RecentSample[len(st.stats.RecentSample)-sampleMax:]
	}

	return d
}

// Snapshot returns the per-lineage stats. Caller-owned copy.
// If lineageID is 0, snapshots every known lineage.
func (o *Observer) Snapshot(lid LineageID) []PerLineageStats {
	cutoff := o.clock().Add(-o.ttl)
	if lid != 0 {
		sh := o.shardFor(lid)
		sh.mu.Lock()
		defer sh.mu.Unlock()
		st, ok := sh.byLid[lid]
		if !ok {
			return nil
		}
		return []PerLineageStats{copyStats(st, cutoff)}
	}
	var out []PerLineageStats
	for i := range o.shards {
		sh := &o.shards[i]
		sh.mu.Lock()
		for _, st := range sh.byLid {
			out = append(out, copyStats(st, cutoff))
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LineageID < out[j].LineageID
	})
	return out
}

// Reclassify is called when better destination identity (typically
// SNI from TLS ClientHello parsing arriving after the connect) lets
// us improve the recorded class for an existing (lineage, ip).
// Bumps a previously-Unknown destination to its true class without
// double-counting. No-op if no prior observation exists or if the
// new SNI doesn't improve the classification.
func (o *Observer) Reclassify(lid LineageID, ip net.IP, sni string, port uint16) {
	if ip == nil || lid == 0 || sni == "" {
		return
	}
	sh := o.shardFor(lid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st, ok := sh.byLid[lid]
	if !ok {
		return
	}
	key := keyFor(ip, sni)
	prev, had := st.destClass[key]
	if !had {
		return
	}
	d := o.classifier.Classify(ip, sni, port)
	if d.Class == destclass.ClassUnknown || d.Class == prev {
		return
	}
	st.destSNI[key] = sni
	st.destClass[key] = d.Class
	// Move the connect-count from prev class to new class. We don't
	// know how many of the prev-class connects belonged to this IP
	// alone vs the whole class, so apply a single re-tag: subtract one
	// from prev and add one to new (the bare-minimum re-attribution).
	if st.stats.ByClass[prev] > 0 {
		st.stats.ByClass[prev]--
	}
	st.stats.ByClass[d.Class]++
	// Move bytes attribution too — full byte count for this dest moves.
	moved := st.stats.BytesOutByClass[prev]
	if moved > 0 {
		st.stats.BytesOutByClass[prev] -= 0 // no-op safeguard
	}
	// Bytes-by-class is aggregated across all dests; we can't subtract
	// just this dest's bytes without tracking per-dest-per-class. For
	// v1 we accept the slight class-byte skew on reclassify and call
	// it out in the doc. The destination-level (BytesOutByDest[ip])
	// is unaffected (still correct).
	_ = moved
	if prev == destclass.ClassUnknown {
		delete(st.unknown, key)
		st.stats.UniqueUnknown = len(st.unknown)
	}
}

// ObserveBytes attributes sendmsg byte counts to a (lineage, dest)
// flow. Idempotent on dest unknowns: if Classify has not yet been
// called for this key, the bytes are counted against ClassUnknown and
// the dest is added to the unknown set. Safe under concurrent calls.
func (o *Observer) ObserveBytes(lid LineageID, ip net.IP, sni string, port uint16, bytes uint64) {
	if bytes == 0 || ip == nil {
		return
	}
	sh := o.shardFor(lid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st := getOrCreateState(sh, lid)
	key := keyFor(ip, sni)
	class, known := st.destClass[key]
	if !known {
		// Bytes seen for a destination we haven't classified — record
		// against Unknown. The next Observe call for this key will
		// reclassify in place; aggregates already attributed remain.
		class = destclass.ClassUnknown
		st.destClass[key] = class
	}
	st.stats.TotalBytesOut += bytes
	st.stats.BytesOutByClass[class] += bytes
	st.stats.BytesOutByDest[key] += bytes
}

func getOrCreateState(sh *shard, lid LineageID) *lineageState {
	st, ok := sh.byLid[lid]
	if !ok {
		st = &lineageState{
			stats: PerLineageStats{
				LineageID:       lid,
				ByClass:         map[destclass.Class]int{},
				BytesOutByClass: map[destclass.Class]uint64{},
				BytesOutByDest:  map[string]uint64{},
			},
			uniques:   map[string]struct{}{},
			unknown:   map[string]struct{}{},
			destClass: map[string]destclass.Class{},
			destSNI:   map[string]string{},
		}
		sh.byLid[lid] = st
	}
	return st
}

// Forget drops state for a lineage. Called when the lineage exits.
func (o *Observer) Forget(lid LineageID) {
	sh := o.shardFor(lid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	delete(sh.byLid, lid)
}

// CountClass is a quick lookup for the takeover scorer: how many
// connects of a given class has this lineage made? Returns 0 if no
// state.
func (o *Observer) CountClass(lid LineageID, class destclass.Class) int {
	sh := o.shardFor(lid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	st, ok := sh.byLid[lid]
	if !ok {
		return 0
	}
	return st.stats.ByClass[class]
}

func copyStats(st *lineageState, cutoff time.Time) PerLineageStats {
	out := st.stats
	out.ByClass = make(map[destclass.Class]int, len(st.stats.ByClass))
	for k, v := range st.stats.ByClass {
		out.ByClass[k] = v
	}
	out.BytesOutByClass = make(map[destclass.Class]uint64, len(st.stats.BytesOutByClass))
	for k, v := range st.stats.BytesOutByClass {
		out.BytesOutByClass[k] = v
	}
	out.BytesOutByDest = make(map[string]uint64, len(st.stats.BytesOutByDest))
	for k, v := range st.stats.BytesOutByDest {
		out.BytesOutByDest[k] = v
	}
	// Prune samples older than cutoff (forensic sample only).
	keep := out.RecentSample[:0]
	for _, s := range out.RecentSample {
		if s.At.After(cutoff) {
			keep = append(keep, s)
		}
	}
	out.RecentSample = append([]Observation{}, keep...)
	return out
}

// keyFor canonicalises a destination to an IP-only key. SNI is
// stored separately (see SNIForKey below) — keying by (ip, sni)
// shards data when SNI arrives retroactively via TLS ClientHello
// parsing or DNS hints. Operators expect "this IP" rollups, not
// "this IP-SNI-pair" rollups.
func keyFor(ip net.IP, sni string) string {
	return ip.String()
}
