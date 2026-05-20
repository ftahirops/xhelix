// Package forensic consolidates Ring 2 deception captures (honey-sh
// command logs, sinkhole beacon bodies, DNS poison events, decoy-FS
// reads, crash-loop events) into a unified IOC store and pushes the
// indicators into the evidence chain + fleet baseline hub for
// cross-host pivoting.
//
// One trapped attacker hardens every other host in the fleet:
// extracted IOCs (their C2 domains, beacon payloads, JA3
// fingerprints, command toolchain) become inputs to other hosts'
// dnspoison known-bad list, netban, and the planner's confidence
// scoring.
//
// See PROTECTED_SERVICES_TRAP.md §7.
//
// Pure Go. CGO_ENABLED=0.
package forensic

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Kind enumerates the IOC types we extract. Wire-stable strings —
// adding a new kind is safe.
type Kind string

const (
	KindURL          Kind = "url"
	KindDomain       Kind = "domain"
	KindIPv4         Kind = "ipv4"
	KindIPv6         Kind = "ipv6"
	KindEmail        Kind = "email"
	KindFilePath     Kind = "file_path"
	KindSHA256       Kind = "sha256"
	KindMD5          Kind = "md5"
	KindJA3          Kind = "ja3"
	KindUserAgent    Kind = "user_agent"
	KindCommand      Kind = "command"        // attacker shell command (first token)
	KindCommandLine  Kind = "command_line"   // full attacker command line
	KindHexPayload   Kind = "hex_payload"    // ≥ 32 byte hex string in attacker traffic
	KindBase64       Kind = "base64_payload" // ≥ 24 byte base64 string
	KindBeaconHost   Kind = "beacon_host"    // HTTP Host: header from sinkhole catch
	KindAWSKey       Kind = "aws_key"        // AKIA... that appeared in attacker traffic
)

// Confidence is the analyst-readable label for an indicator's
// reliability. Strings rather than an enum so new tiers add
// without breaking JSON.
type Confidence string

const (
	ConfidenceDeterministic Confidence = "deterministic" // attacker definitely produced this
	ConfidenceHigh          Confidence = "high"          // very likely an IOC
	ConfidenceMedium        Confidence = "medium"
	ConfidenceLow           Confidence = "low"           // candidate; needs corroboration
)

// IOC is one indicator. The same Value+Kind seen multiple times
// gets a single IOC with FirstSeen / LastSeen / Count updated.
type IOC struct {
	Kind       Kind       `json:"kind"`
	Value      string     `json:"value"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	Count      int        `json:"count"`
	Confidence Confidence `json:"confidence"`

	// Origin tags the deception layer that captured this — useful
	// for filtering (e.g. "show me everything from sinkhole"):
	//   "honeysh", "sinkhole", "dnspoison", "decoyfs", "crashloop"
	Origins []string `json:"origins,omitempty"`

	// Sources are the SessionID/BeaconID values that captured this
	// indicator. Capped at MaxSourcesPerIOC.
	Sources []string `json:"sources,omitempty"`

	// Tags are operator-set labels ("c2-known", "tooling-cobalt",
	// "tooling-metasploit"). Stable across updates.
	Tags []string `json:"tags,omitempty"`
}

// MaxSourcesPerIOC bounds the per-IOC Sources list. Hot attackers
// generate thousands of beacons; we don't need every BeaconID.
const MaxSourcesPerIOC = 64

// Observation is the unit of input into the Store. A single
// extraction may produce multiple Observations (one per Kind+Value
// found in the raw payload).
type Observation struct {
	Kind       Kind
	Value      string
	At         time.Time
	Confidence Confidence
	Origin     string // "honeysh" / "sinkhole" / ...
	Source     string // SessionID / BeaconID
}

// Store is the IOC database — thread-safe, in-memory. Bounded by
// MaxIOCs (oldest evicted on overflow). A SQLite-backed Store may
// land in v2 if operators need persistence; for v1 the JSON-lines
// evidence chain (pkg/chain) holds the durable copy.
type Store struct {
	mu      sync.RWMutex
	byKey   map[storeKey]*IOC
	order   []storeKey // insertion order for eviction
	maxIOCs int
}

type storeKey struct {
	Kind  Kind
	Value string
}

// DefaultMaxIOCs is the per-host IOC cap. Generous — even
// pathological attacker traffic rarely produces more than this.
const DefaultMaxIOCs = 65536

// NewStore returns an empty Store with the default cap.
func NewStore() *Store {
	return &Store{
		byKey:   map[storeKey]*IOC{},
		maxIOCs: DefaultMaxIOCs,
	}
}

// NewStoreWithCap is for tests.
func NewStoreWithCap(n int) *Store {
	if n <= 0 {
		n = DefaultMaxIOCs
	}
	return &Store{
		byKey:   map[storeKey]*IOC{},
		maxIOCs: n,
	}
}

// Add ingests an Observation. Returns the resulting IOC (after
// merge if it already existed).
func (s *Store) Add(o Observation) *IOC {
	if o.Value == "" || o.Kind == "" {
		return nil
	}
	if o.At.IsZero() {
		o.At = time.Now().UTC()
	}
	o.Value = canonicalize(o.Kind, o.Value)
	if o.Value == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := storeKey{Kind: o.Kind, Value: o.Value}
	ioc, exists := s.byKey[key]
	if !exists {
		ioc = &IOC{
			Kind:       o.Kind,
			Value:      o.Value,
			FirstSeen:  o.At,
			LastSeen:   o.At,
			Count:      0,
			Confidence: o.Confidence,
		}
		s.byKey[key] = ioc
		s.order = append(s.order, key)
		s.evictIfNeeded()
	}
	ioc.Count++
	ioc.LastSeen = o.At
	if o.Confidence != "" && rank(o.Confidence) > rank(ioc.Confidence) {
		ioc.Confidence = o.Confidence // upgrade-only
	}
	addUnique(&ioc.Origins, o.Origin)
	if o.Source != "" {
		addUniqueCap(&ioc.Sources, o.Source, MaxSourcesPerIOC)
	}
	// Return a SNAPSHOT (copy) — not the live pointer — so callers
	// can safely read the IOC's fields after Add() releases the
	// lock. Returning the live pointer raced (P-RF.9e found it):
	// ProcessLine reads `ioc.Count == 1` after Add(), and a
	// concurrent Add() would mutate that field. Snapshot semantics
	// keep the API caller-safe without forcing every caller to
	// hold s.mu themselves.
	cp := *ioc
	if ioc.Origins != nil {
		cp.Origins = append([]string(nil), ioc.Origins...)
	}
	if ioc.Sources != nil {
		cp.Sources = append([]string(nil), ioc.Sources...)
	}
	if ioc.Tags != nil {
		cp.Tags = append([]string(nil), ioc.Tags...)
	}
	return &cp
}

// AddBatch is a convenience for many observations.
func (s *Store) AddBatch(obs []Observation) []*IOC {
	out := make([]*IOC, 0, len(obs))
	for _, o := range obs {
		if ioc := s.Add(o); ioc != nil {
			out = append(out, ioc)
		}
	}
	return out
}

// Tag attaches an operator label to an IOC. Idempotent.
func (s *Store) Tag(kind Kind, value, tag string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ioc, ok := s.byKey[storeKey{Kind: kind, Value: canonicalize(kind, value)}]; ok {
		addUnique(&ioc.Tags, tag)
	}
}

// Get returns one IOC by (kind, value), or nil.
func (s *Store) Get(kind Kind, value string) *IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if ioc, ok := s.byKey[storeKey{Kind: kind, Value: canonicalize(kind, value)}]; ok {
		cp := *ioc
		return &cp
	}
	return nil
}

// Len returns the number of distinct IOCs.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey)
}

// Query returns IOCs matching the filter. Empty filter returns all,
// sorted by LastSeen descending.
type Query struct {
	Kinds      []Kind     // empty = all kinds
	Confidence Confidence // minimum confidence; empty = all
	Origin     string     // empty = any
	Since      time.Time  // LastSeen ≥ Since; zero = unbounded
	Limit      int        // 0 = no limit
}

func (s *Store) Query(q Query) []*IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()

	kindSet := map[Kind]struct{}{}
	for _, k := range q.Kinds {
		kindSet[k] = struct{}{}
	}

	var out []*IOC
	for _, ioc := range s.byKey {
		if len(kindSet) > 0 {
			if _, ok := kindSet[ioc.Kind]; !ok {
				continue
			}
		}
		if q.Confidence != "" && rank(ioc.Confidence) < rank(q.Confidence) {
			continue
		}
		if q.Origin != "" {
			found := false
			for _, o := range ioc.Origins {
				if o == q.Origin {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if !q.Since.IsZero() && ioc.LastSeen.Before(q.Since) {
			continue
		}
		cp := *ioc
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out
}

// --- internals ---

func (s *Store) evictIfNeeded() {
	for len(s.byKey) > s.maxIOCs && len(s.order) > 0 {
		key := s.order[0]
		s.order = s.order[1:]
		delete(s.byKey, key)
	}
}

func canonicalize(k Kind, v string) string {
	v = strings.TrimSpace(v)
	switch k {
	case KindDomain, KindEmail, KindBeaconHost, KindUserAgent:
		return strings.ToLower(strings.TrimSuffix(v, "."))
	case KindURL:
		return strings.TrimRight(v, "/")
	case KindSHA256, KindMD5, KindJA3:
		return strings.ToLower(v)
	}
	return v
}

func rank(c Confidence) int {
	switch c {
	case ConfidenceDeterministic:
		return 4
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	}
	return 0
}

func addUnique(slice *[]string, v string) {
	if v == "" {
		return
	}
	for _, x := range *slice {
		if x == v {
			return
		}
	}
	*slice = append(*slice, v)
}

func addUniqueCap(slice *[]string, v string, max int) {
	for _, x := range *slice {
		if x == v {
			return
		}
	}
	if len(*slice) >= max {
		return // silently drop — Count still increments
	}
	*slice = append(*slice, v)
}
