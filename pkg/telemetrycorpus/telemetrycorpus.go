// Package telemetrycorpus is xhelix's curated catalog of known
// non-functional endpoints (telemetry, analytics, crash reporting,
// ads, trackers) used by major OSes, browsers, IDEs, and applications.
//
// Entries are factual — they describe DNS suffixes that the named
// products contact for telemetry purposes. They are catalogued here
// as the project's own reference so the verdict engine can label
// telemetry flows with evidence even when the operator has not yet
// chosen to block them.
//
// Each entry: pattern, product, category (telemetry|analytics|crash|
// ads|tracker), and an optional note describing the role.
package telemetrycorpus

import (
	"sync"

	"github.com/xhelix/xhelix/pkg/verdict"
)

// Category constants.
const (
	CatTelemetry = "telemetry"
	CatAnalytics = "analytics"
	CatCrash     = "crash"
	CatAds       = "ads"
	CatTracker   = "tracker"
)

// Entry catalogs one telemetry/analytics/tracker endpoint.
type Entry struct {
	Pattern  string // exact host or "*.suffix"
	Product  string // short product label ("VSCode", "Firefox", ...)
	Category string // one of the constants above
	Note     string // optional human-readable role
}

// Corpus is a thread-safe matcher.
type Corpus struct {
	mu      sync.RWMutex
	entries []Entry
}

// New returns an empty corpus. Use NewDefault for a seeded one.
func New() *Corpus { return &Corpus{} }

// Add inserts an entry.
func (c *Corpus) Add(e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, e)
}

// Lookup returns the first entry that matches the host (SNI/DNS).
func (c *Corpus) Lookup(host string) (Entry, bool) {
	if host == "" {
		return Entry{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.entries {
		if verdict.MatchHost(e.Pattern, host) {
			return e, true
		}
	}
	return Entry{}, false
}

// Size returns the number of entries loaded.
func (c *Corpus) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Layer adapts a Corpus into a verdict.Layer. By default it does not
// *block* — it tags the flow with evidence and lets later layers
// decide. If BlockFn returns true, the layer turns into a deny.
// BlockFn is a function (not a static flag) so the operator can flip
// it at runtime without rebuilding the engine.
type Layer struct {
	C       *Corpus
	BlockFn func() bool
}

func (Layer) Name() string { return "telemetry" }

func (l Layer) Eval(c verdict.Conn) (bool, verdict.Action, verdict.Confidence, []verdict.Reason) {
	host := c.SNI
	if host == "" {
		host = c.DNSName
	}
	if host == "" {
		return false, "", 0, nil
	}
	e, ok := l.C.Lookup(host)
	if !ok {
		return false, "", 0, nil
	}
	note := e.Product + " " + e.Category + " — " + e.Pattern
	if e.Note != "" {
		note += " (" + e.Note + ")"
	}
	block := l.BlockFn != nil && l.BlockFn()
	if block {
		return true, verdict.ActionDeny, 92, []verdict.Reason{{
			Layer:  "telemetry",
			RuleID: "tlm." + e.Category + "." + e.Product,
			Note:   "blocked: " + note,
		}}
	}
	return false, "", 0, []verdict.Reason{{
		Layer:  "telemetry",
		RuleID: "tlm." + e.Category + "." + e.Product,
		Note:   "tagged: " + note,
	}}
}
