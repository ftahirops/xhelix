package baseline

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Scorer compares incoming Windows against a learned union-baseline
// of "what this binary normally does". It emits Verdicts when a
// window contains endpoints, children, or file_writes that are not in
// the baseline.
//
// Set-diff is the cheapest useful anomaly detector and the right
// starting point. Per-binary feature unions over a 7-day window catch:
//
//   - new outbound destinations a binary has never connected to
//   - new child processes a binary has never spawned
//   - new file paths a binary has never written
//
// We deliberately do NOT use ML in Phase 2. Statistics first, ML
// later — only after this proves itself in production.
//
// False-positive controls (stack the four together; alone they each
// are too noisy):
//
//   - Warmup: no scoring during the first WarmupHours of observation
//     for a given binary, so a brand-new binary doesn't fire on every
//     feature.
//   - Hysteresis: a feature must appear in N consecutive windows
//     before its anomaly is reported. Single-blip noise is suppressed.
//   - Required-evidence: configure the scorer to require K of the M
//     feature classes to be anomalous before emitting a Verdict.
//   - Operator feedback: caller can call MarkBenign(binary, feature)
//     after triage; that feature is added to the baseline so future
//     scoring won't fire on it.
type Scorer struct {
	cfg ScorerConfig

	mu        sync.RWMutex
	baselines map[string]*binaryBaseline
	repeats   map[string]map[string]int // binary → feature → consecutive seen
	fleetRare map[string]map[string]struct{} // binary → set of fleet-rare endpoints
}

// ScorerConfig tunes the scorer.
type ScorerConfig struct {
	// BaselineDir is the JSONL directory the scorer reads from to
	// build its baseline. Typically the same dir Store writes to.
	BaselineDir string
	// LookbackDays is how many days of historical windows to fold
	// into the baseline at rebuild time. Default 7.
	LookbackDays int
	// WarmupHours is how many hours a binary must have been observed
	// before it becomes scoring-eligible. Default 24.
	WarmupHours int
	// HysteresisN: a feature must appear in N consecutive *new* windows
	// before its anomaly is reported. Default 2.
	HysteresisN int
	// MinFeatureClasses: a Verdict requires this many feature classes
	// (endpoint / child / file_write) to be anomalous. Default 1.
	MinFeatureClasses int
	// IgnoreBinaries are never scored. Default empty.
	IgnoreBinaries map[string]bool
}

// binaryBaseline holds the learned "union of seen features" per binary.
type binaryBaseline struct {
	binary       string
	firstSeen    time.Time // earliest window hour observed
	lastSeen     time.Time
	endpoints    map[string]struct{}
	children     map[string]struct{}
	fileWrites   map[string]struct{}
	syscalls     map[string]struct{}
	totalEvents  uint64
	totalWindows int
}

// Verdict is one anomaly report.
type Verdict struct {
	Binary           string    `json:"binary"`
	Hour             time.Time `json:"hour"`
	NewEndpoints     []string  `json:"new_endpoints,omitempty"`
	NewChildren      []string  `json:"new_children,omitempty"`
	NewFileWrites    []string  `json:"new_file_writes,omitempty"`
	NewSyscalls      []string  `json:"new_syscalls,omitempty"`
	BaselineWindows  int       `json:"baseline_windows"`
	BaselineEvents   uint64    `json:"baseline_events"`
	HoursSinceFirst  float64   `json:"hours_since_first"`
	// FleetRareEndpoints is the subset of NewEndpoints that the fleet
	// hub reports as rare across other hosts in the same role —
	// strong cross-fleet evidence that the endpoint is genuinely
	// novel and not just first-seen on this host.
	FleetRareEndpoints []string `json:"fleet_rare_endpoints,omitempty"`
}

// SetFleetRare loads a per-binary rare-endpoint set learned from the
// fleet hub. Subsequent Score() calls use this set to populate
// Verdict.FleetRareEndpoints.
//
// The fleet rare-set is purely informational: it elevates the
// confidence of the local set-diff verdict, but it doesn't itself
// trigger alerts. We never auto-suppress on "common in the fleet"
// either — being common doesn't make a behaviour benign.
func (s *Scorer) SetFleetRare(binary string, rareEndpoints []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fleetRare == nil {
		s.fleetRare = map[string]map[string]struct{}{}
	}
	set := map[string]struct{}{}
	for _, e := range rareEndpoints {
		set[e] = struct{}{}
	}
	s.fleetRare[binary] = set
}

// NewScorer returns an unloaded scorer. Call LoadBaseline before
// scoring; otherwise the binary baselines map will be empty and
// nothing will score (which is the safe default during warmup).
func NewScorer(cfg ScorerConfig) *Scorer {
	if cfg.LookbackDays <= 0 {
		cfg.LookbackDays = 7
	}
	if cfg.WarmupHours <= 0 {
		cfg.WarmupHours = 24
	}
	if cfg.HysteresisN <= 0 {
		cfg.HysteresisN = 2
	}
	if cfg.MinFeatureClasses <= 0 {
		cfg.MinFeatureClasses = 1
	}
	if cfg.IgnoreBinaries == nil {
		cfg.IgnoreBinaries = map[string]bool{}
	}
	return &Scorer{
		cfg:       cfg,
		baselines: map[string]*binaryBaseline{},
		repeats:   map[string]map[string]int{},
	}
}

// LoadBaseline reads every .jsonl and .jsonl.gz file in BaselineDir
// whose filename day is within LookbackDays of `now`, parses each
// Window, and folds it into the per-binary baseline. Atomically
// replaces any prior in-memory baseline.
//
// Returns the number of binaries learned and any non-fatal error
// reading specific files (it logs but doesn't abort — partial
// baselines are preferable to no baseline).
func (s *Scorer) LoadBaseline(now time.Time) (int, error) {
	if s.cfg.BaselineDir == "" {
		return 0, fmt.Errorf("scorer: empty BaselineDir")
	}
	cutoff := now.UTC().AddDate(0, 0, -s.cfg.LookbackDays).Format("2006-01-02")

	entries, err := os.ReadDir(s.cfg.BaselineDir)
	if err != nil {
		return 0, fmt.Errorf("read baseline dir: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if len(name) < 10 {
			continue
		}
		if !strings.HasSuffix(name, ".jsonl") && !strings.HasSuffix(name, ".jsonl.gz") {
			continue
		}
		if name[:10] < cutoff {
			continue
		}
		files = append(files, filepath.Join(s.cfg.BaselineDir, name))
	}
	sort.Strings(files)

	fresh := map[string]*binaryBaseline{}
	for _, f := range files {
		if err := s.loadFileInto(f, fresh); err != nil {
			// Continue on file-level error; a corrupt one shouldn't
			// blank the baseline.
			continue
		}
	}

	s.mu.Lock()
	s.baselines = fresh
	s.mu.Unlock()
	return len(fresh), nil
}

func (s *Scorer) loadFileInto(path string, into map[string]*binaryBaseline) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}

	dec := json.NewDecoder(r)
	for dec.More() {
		var w Window
		if err := dec.Decode(&w); err != nil {
			break
		}
		if s.cfg.IgnoreBinaries[w.Binary] {
			continue
		}
		b, ok := into[w.Binary]
		if !ok {
			b = &binaryBaseline{
				binary:     w.Binary,
				firstSeen:  w.Hour,
				lastSeen:   w.Hour,
				endpoints:  map[string]struct{}{},
				children:   map[string]struct{}{},
				fileWrites: map[string]struct{}{},
				syscalls:   map[string]struct{}{},
			}
			into[w.Binary] = b
		}
		if w.Hour.Before(b.firstSeen) {
			b.firstSeen = w.Hour
		}
		if w.Hour.After(b.lastSeen) {
			b.lastSeen = w.Hour
		}
		b.totalWindows++
		b.totalEvents += w.Events
		for k := range w.Endpoints {
			b.endpoints[k] = struct{}{}
		}
		for k := range w.Children {
			b.children[k] = struct{}{}
		}
		for k := range w.FileWrites {
			b.fileWrites[k] = struct{}{}
		}
		for k := range w.Syscalls {
			b.syscalls[k] = struct{}{}
		}
	}
	return nil
}

// Score compares one fresh window against the learned baseline. It
// returns a non-nil Verdict only when:
//   - the binary is past warmup,
//   - the window contains at least 1 feature unseen in the baseline,
//   - the feature has been observed-as-new in HysteresisN consecutive
//     scoring calls, and
//   - the unseen features cover at least MinFeatureClasses classes.
//
// Score is goroutine-safe but must only be called once per (binary,
// hour) tuple to keep the hysteresis counter meaningful. The
// aggregator's flush cadence guarantees this.
//
// Implementation note: we hold s.mu (write-lock) for the full body
// rather than the prior RLock/release/Lock pattern. The previous
// release-and-re-acquire created a TOCTOU window where a concurrent
// LoadBaseline() could replace s.baselines mid-Score, leaving the
// `b` pointer detached. Mutations on the orphan would silently
// disappear at the next rebuild. Holding the lock across the body
// is correct; the throughput cost is negligible because Score is
// called from a single goroutine (the flush ticker) in production.
func (s *Scorer) Score(w *Window, now time.Time) *Verdict {
	if w == nil || w.Binary == "" {
		return nil
	}
	if s.cfg.IgnoreBinaries[w.Binary] {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, hasBaseline := s.baselines[w.Binary]

	// Without a baseline we can't score. We DO update the in-memory
	// baseline live so subsequent windows get the benefit of what we
	// just saw — but we don't score this very first window for a
	// binary, since by definition every feature is "new".
	if !hasBaseline {
		s.absorbNewBinaryLocked(w)
		return nil
	}

	// Warmup: reject if the binary has been observed for too short a span.
	hoursSeen := w.Hour.Sub(b.firstSeen).Hours()
	if hoursSeen < float64(s.cfg.WarmupHours) {
		// Update baseline so warmup actually accrues.
		s.absorbIntoLocked(b, w)
		return nil
	}

	// Set-diff per feature class.
	newEndpoints := setDiff(w.Endpoints, b.endpoints)
	newChildren := setDiff(w.Children, b.children)
	newFileWrites := setDiff(w.FileWrites, b.fileWrites)
	newSyscalls := setDiff(w.Syscalls, b.syscalls)

	classes := 0
	if len(newEndpoints) > 0 {
		classes++
	}
	if len(newChildren) > 0 {
		classes++
	}
	if len(newFileWrites) > 0 {
		classes++
	}
	if len(newSyscalls) > 0 {
		classes++
	}

	// Apply hysteresis to each individual feature.
	keptEndpoints := s.applyHysteresisLocked(w.Binary, "endpoint", newEndpoints)
	keptChildren := s.applyHysteresisLocked(w.Binary, "child", newChildren)
	keptFileWrites := s.applyHysteresisLocked(w.Binary, "file_write", newFileWrites)
	keptSyscalls := s.applyHysteresisLocked(w.Binary, "syscall", newSyscalls)

	// Update baseline metadata + absorb known-good features. Features
	// still pending hysteresis stay OUT of the baseline so the next
	// window correctly sees them as "new" again. Once hysteresis
	// confirms (kept[] non-empty), absorb that feature.
	s.absorbConfirmedLocked(b, w, keptEndpoints, keptChildren, keptFileWrites, keptSyscalls)

	// Re-count classes after hysteresis filtering.
	classes = 0
	if len(keptEndpoints) > 0 {
		classes++
	}
	if len(keptChildren) > 0 {
		classes++
	}
	if len(keptFileWrites) > 0 {
		classes++
	}
	if len(keptSyscalls) > 0 {
		classes++
	}
	if classes < s.cfg.MinFeatureClasses {
		return nil
	}

	v := &Verdict{
		Binary:          w.Binary,
		Hour:            w.Hour,
		NewEndpoints:    keptEndpoints,
		NewChildren:     keptChildren,
		NewFileWrites:   keptFileWrites,
		NewSyscalls:     keptSyscalls,
		BaselineWindows: b.totalWindows,
		BaselineEvents:  b.totalEvents,
		HoursSinceFirst: hoursSeen,
	}
	// Cross-reference against the fleet-rare set if the hub has fed
	// us one. Endpoints in both lists are doubly suspicious: new on
	// THIS host, AND uncommon across the fleet.
	// (We're already inside Score's outer s.mu.Lock() — direct map
	// read; the prior RLock here would deadlock under the new locking
	// regime since RWMutex doesn't allow lock-downgrade from write.)
	rare := s.fleetRare[w.Binary]
	if rare != nil {
		for _, ep := range keptEndpoints {
			if _, ok := rare[ep]; ok {
				v.FleetRareEndpoints = append(v.FleetRareEndpoints, ep)
			}
		}
	}
	return v
}

// MarkBenign teaches the scorer that a feature for this binary is
// known-good. Subsequent scoring won't flag it. Callers (operator UI,
// xhub feedback) call this after triaging a Verdict as a false positive.
func (s *Scorer) MarkBenign(binary, featureClass, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.baselines[binary]
	if !ok {
		return
	}
	switch featureClass {
	case "endpoint":
		b.endpoints[value] = struct{}{}
	case "child":
		b.children[value] = struct{}{}
	case "file_write":
		b.fileWrites[value] = struct{}{}
	case "syscall":
		b.syscalls[value] = struct{}{}
	}
}

// Stats reports current scorer state for the dashboard.
type ScorerStats struct {
	Binaries   int
	Warmed     int
	UnderWarmup int
	OldestWindow time.Time
	NewestWindow time.Time
}

func (s *Scorer) Stats(now time.Time) ScorerStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := ScorerStats{Binaries: len(s.baselines)}
	for _, b := range s.baselines {
		hoursSeen := now.Sub(b.firstSeen).Hours()
		if hoursSeen >= float64(s.cfg.WarmupHours) {
			out.Warmed++
		} else {
			out.UnderWarmup++
		}
		if out.OldestWindow.IsZero() || b.firstSeen.Before(out.OldestWindow) {
			out.OldestWindow = b.firstSeen
		}
		if b.lastSeen.After(out.NewestWindow) {
			out.NewestWindow = b.lastSeen
		}
	}
	return out
}

// absorbNewBinaryLocked creates a baseline entry from one window.
// Caller must hold s.mu (write). The entry is "warmup-fresh" — its
// firstSeen is this window's hour, so it won't be scoring-eligible
// until WarmupHours pass.
func (s *Scorer) absorbNewBinaryLocked(w *Window) {
	if _, ok := s.baselines[w.Binary]; ok {
		return
	}
	b := &binaryBaseline{
		binary:     w.Binary,
		firstSeen:  w.Hour,
		lastSeen:   w.Hour,
		endpoints:  map[string]struct{}{},
		children:   map[string]struct{}{},
		fileWrites: map[string]struct{}{},
		syscalls:   map[string]struct{}{},
	}
	for k := range w.Endpoints {
		b.endpoints[k] = struct{}{}
	}
	for k := range w.Children {
		b.children[k] = struct{}{}
	}
	for k := range w.FileWrites {
		b.fileWrites[k] = struct{}{}
	}
	for k := range w.Syscalls {
		b.syscalls[k] = struct{}{}
	}
	b.totalWindows = 1
	b.totalEvents = w.Events
	s.baselines[w.Binary] = b
}

// absorbIntoLocked folds every key of w into b. Caller must hold
// s.mu (write). Used during warmup, when we want the baseline to
// grow as fast as possible — there's no scoring during warmup, so
// over-absorbing is correct.
func (s *Scorer) absorbIntoLocked(b *binaryBaseline, w *Window) {
	if w.Hour.After(b.lastSeen) {
		b.lastSeen = w.Hour
	}
	b.totalWindows++
	b.totalEvents += w.Events
	for k := range w.Endpoints {
		b.endpoints[k] = struct{}{}
	}
	for k := range w.Children {
		b.children[k] = struct{}{}
	}
	for k := range w.FileWrites {
		b.fileWrites[k] = struct{}{}
	}
	for k := range w.Syscalls {
		b.syscalls[k] = struct{}{}
	}
}

// absorbConfirmedLocked updates metadata + absorbs only features
// that are either already in the baseline (untouched) or have just
// been confirmed by hysteresis (newly added). Caller must hold s.mu.
// New-but-pending-hysteresis features are NOT absorbed — that's
// what lets the next window continue to see them as new and
// accumulate hysteresis count.
func (s *Scorer) absorbConfirmedLocked(b *binaryBaseline, w *Window,
	keptEndpoints, keptChildren, keptFileWrites, keptSyscalls []string) {
	if w.Hour.After(b.lastSeen) {
		b.lastSeen = w.Hour
	}
	b.totalWindows++
	b.totalEvents += w.Events
	// Features in the window that ARE already in baseline don't need
	// to be re-added (no-op). The ones we ADD are the kept[] features.
	for _, k := range keptEndpoints {
		b.endpoints[k] = struct{}{}
	}
	for _, k := range keptChildren {
		b.children[k] = struct{}{}
	}
	for _, k := range keptFileWrites {
		b.fileWrites[k] = struct{}{}
	}
	for _, k := range keptSyscalls {
		b.syscalls[k] = struct{}{}
	}
}

// applyHysteresisLocked: a feature value is kept (i.e., reported in
// a Verdict) only after it has appeared as "new" in HysteresisN
// consecutive Score() calls for this binary. State is tracked per
// (binary, feature_class+value). Caller must hold s.mu.
func (s *Scorer) applyHysteresisLocked(binary, class string, candidates []string) []string {
	if s.cfg.HysteresisN <= 1 || len(candidates) == 0 {
		return candidates
	}
	if s.repeats[binary] == nil {
		s.repeats[binary] = map[string]int{}
	}
	rep := s.repeats[binary]
	kept := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		key := class + "|" + c
		seen[key] = struct{}{}
		rep[key]++
		if rep[key] >= s.cfg.HysteresisN {
			kept = append(kept, c)
		}
	}
	// Decay any feature not seen this round (it's no longer "new").
	for key := range rep {
		if _, ok := seen[key]; !ok {
			if strings.HasPrefix(key, class+"|") {
				delete(rep, key)
			}
		}
	}
	return kept
}

// setDiff returns keys in `current` that are not in `baseline`.
// Result is sorted for determinism in alerts.
func setDiff(current map[string]uint64, baseline map[string]struct{}) []string {
	if len(current) == 0 {
		return nil
	}
	var out []string
	for k := range current {
		if _, ok := baseline[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
