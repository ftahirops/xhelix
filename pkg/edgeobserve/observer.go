// Package edgeobserve accumulates the observed inter-app topology — the
// distinct (from_app → to_app) network edges xhelix sees at runtime, with the
// destinations seen for each. This is the learned "who talks to whom" graph
// (Pillar 2): the raw material an operator reviews and turns into signed BRP
// edges (pkg/brp.Edge). It observes only; it never blocks.
//
// It aggregates by (from_app, to_app, action) and keeps a bounded set of
// destinations per edge, so a busy host with many backend IPs does not grow it
// without limit — the same discipline as the correlator/imagecache caps.
package edgeobserve

import (
	"sort"
	"sync"
	"time"
)

const (
	maxEdges     = 4096
	maxDestsEdge = 64
)

// edge is the internal accumulator for one (from_app, to_app, action) triple.
type edge struct {
	fromApp, toApp, action string
	dests                  map[string]struct{}
	count                  uint64
	lastScore              float64
	lastReason             string
	firstSeen, lastSeen    time.Time
}

// Edge is a snapshot view of one observed inter-app edge.
type Edge struct {
	FromApp   string    `json:"from_app"`
	ToApp     string    `json:"to_app"`
	Action    string    `json:"action"`
	Dests     []string  `json:"dests"`
	Count     uint64    `json:"count"`
	Score     float64   `json:"score"`
	Reason    string    `json:"reason,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Observer accumulates observed edges. Safe for concurrent use.
type Observer struct {
	mu    sync.Mutex
	edges map[string]*edge
}

// New returns an empty Observer.
func New() *Observer { return &Observer{edges: make(map[string]*edge)} }

func key(fromApp, toApp, action string) string {
	return fromApp + "\x00" + toApp + "\x00" + action
}

// Observe records one observed edge. from_app and to_app must be non-empty
// (an unattributed end is not a cross-app edge). now is passed for
// deterministic testing. New edges are dropped once maxEdges is reached
// (existing ones still update) so the map is bounded.
func (o *Observer) Observe(now time.Time, fromApp, toApp, action, dest string, score float64, reason string) {
	if fromApp == "" || toApp == "" {
		return
	}
	k := key(fromApp, toApp, action)
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.edges[k]
	if !ok {
		if len(o.edges) >= maxEdges {
			return
		}
		e = &edge{fromApp: fromApp, toApp: toApp, action: action,
			dests: make(map[string]struct{}), firstSeen: now}
		o.edges[k] = e
	}
	e.count++
	e.lastSeen = now
	e.lastScore = score
	e.lastReason = reason
	if dest != "" && len(e.dests) < maxDestsEdge {
		e.dests[dest] = struct{}{}
	}
}

// Snapshot returns all observed edges, sorted by from_app then descending count.
func (o *Observer) Snapshot() []Edge {
	o.mu.Lock()
	out := make([]Edge, 0, len(o.edges))
	for _, e := range o.edges {
		dests := make([]string, 0, len(e.dests))
		for d := range e.dests {
			dests = append(dests, d)
		}
		sort.Strings(dests)
		out = append(out, Edge{
			FromApp: e.fromApp, ToApp: e.toApp, Action: e.action, Dests: dests,
			Count: e.count, Score: e.lastScore, Reason: e.lastReason,
			FirstSeen: e.firstSeen, LastSeen: e.lastSeen,
		})
	}
	o.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromApp != out[j].FromApp {
			return out[i].FromApp < out[j].FromApp
		}
		return out[i].Count > out[j].Count
	})
	return out
}
