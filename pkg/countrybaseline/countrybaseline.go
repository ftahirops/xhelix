// Package countrybaseline learns the set of destination countries
// each binary normally contacts, and flags first-time / off-pattern
// contact as anomalous.
//
// The "data going to China from a machine with no Chinese apps"
// red alert: this package is its evidence layer.
//
// Storage model: per-binary (keyed by exe_sha or, as a fallback,
// the exe path) — a small struct holding
//   - First/Last seen timestamps
//   - Set of countries observed, each with hit count + last-seen
//   - ConfidenceWindow: minimum age before "novel country" alerts
//     start firing for this binary (cold-start dampener)
//
// The package is goroutine-safe and persistence-agnostic. A caller
// that wants durability can call Snapshot() to dump the maps and
// Load() to restore. Pure-Go, no I/O.
package countrybaseline

import (
	"sort"
	"sync"
	"time"
)

// Default confidence window: a binary needs at least this much
// observed-history before novel-country alerts begin to fire.
const DefaultConfidenceWindow = 14 * 24 * time.Hour

// Detector holds the per-binary baseline maps.
type Detector struct {
	// ConfidenceWindow gates "novel country" alerts. <=0 selects
	// DefaultConfidenceWindow.
	ConfidenceWindow time.Duration

	mu        sync.RWMutex
	binaries  map[string]*Binary
	now       func() time.Time
}

// Binary is the per-binary baseline.
type Binary struct {
	Key       string // exe_sha or exe path
	FirstSeen time.Time
	LastSeen  time.Time
	Countries map[string]*CountryStat
}

// CountryStat is the per-country fact.
type CountryStat struct {
	Count    uint64
	First    time.Time
	Last     time.Time
}

// Anomaly is the detector output for one Observe call.
type Anomaly struct {
	IsNovel    bool          // first ever contact to this country for this binary
	IsRecent   bool          // last contact < RecentWindow ago — not anomalous
	HitCount   uint64        // total hits for (binary, country)
	BinaryAge  time.Duration // elapsed since FirstSeen
	Country    string
}

// New returns a Detector with sensible defaults.
func New(confidence time.Duration) *Detector {
	if confidence <= 0 {
		confidence = DefaultConfidenceWindow
	}
	return &Detector{
		ConfidenceWindow: confidence,
		binaries:         map[string]*Binary{},
		now:              time.Now,
	}
}

// Observe records one observation. Returns the Anomaly evaluation
// at the time of the observation. Callers route IsNovel and
// IsConfident() == true into alerting; novel-but-cold-start
// observations are absorbed silently to learn the baseline.
func (d *Detector) Observe(key, country string) Anomaly {
	if key == "" || country == "" {
		return Anomaly{}
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()

	b, ok := d.binaries[key]
	if !ok {
		b = &Binary{Key: key, FirstSeen: now, LastSeen: now, Countries: map[string]*CountryStat{}}
		d.binaries[key] = b
	}
	b.LastSeen = now
	cs, ok := b.Countries[country]
	if !ok {
		cs = &CountryStat{First: now}
		b.Countries[country] = cs
		// Novel
		cs.Count++
		cs.Last = now
		return Anomaly{
			IsNovel: true, IsRecent: false, HitCount: 1,
			BinaryAge: now.Sub(b.FirstSeen), Country: country,
		}
	}
	cs.Count++
	cs.Last = now
	return Anomaly{
		IsNovel: false, IsRecent: true,
		HitCount: cs.Count, BinaryAge: now.Sub(b.FirstSeen), Country: country,
	}
}

// IsConfident reports whether the binary's baseline is mature
// enough that novel-country observations should fire alerts.
func (d *Detector) IsConfident(key string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	b, ok := d.binaries[key]
	if !ok {
		return false
	}
	return d.now().Sub(b.FirstSeen) >= d.ConfidenceWindow
}

// KnownCountries returns the sorted list of countries the binary
// has contacted. Empty slice for unknown binaries.
func (d *Detector) KnownCountries(key string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	b, ok := d.binaries[key]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(b.Countries))
	for c := range b.Countries {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Stats is the public snapshot for status reporting.
type Stats struct {
	Binaries  int
	Countries int // distinct across all binaries
}

// Stats returns a brief inventory.
func (d *Detector) Stats() Stats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	seen := map[string]struct{}{}
	for _, b := range d.binaries {
		for c := range b.Countries {
			seen[c] = struct{}{}
		}
	}
	return Stats{Binaries: len(d.binaries), Countries: len(seen)}
}

// Snapshot returns a deep-copy snapshot suitable for persistence.
func (d *Detector) Snapshot() []Binary {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]Binary, 0, len(d.binaries))
	for _, b := range d.binaries {
		cp := Binary{
			Key: b.Key, FirstSeen: b.FirstSeen, LastSeen: b.LastSeen,
			Countries: make(map[string]*CountryStat, len(b.Countries)),
		}
		for c, cs := range b.Countries {
			c2 := *cs
			cp.Countries[c] = &c2
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Load replaces the in-memory state from a Snapshot.
func (d *Detector) Load(snap []Binary) {
	m := make(map[string]*Binary, len(snap))
	for _, b := range snap {
		cp := b
		cp.Countries = make(map[string]*CountryStat, len(b.Countries))
		for c, cs := range b.Countries {
			c2 := *cs
			cp.Countries[c] = &c2
		}
		m[b.Key] = &cp
	}
	d.mu.Lock()
	d.binaries = m
	d.mu.Unlock()
}

// Forget drops a binary's baseline. Useful when an exe is upgraded
// and its previous baseline no longer applies.
func (d *Detector) Forget(key string) {
	d.mu.Lock()
	delete(d.binaries, key)
	d.mu.Unlock()
}
