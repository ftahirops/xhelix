// Package verdictcount is a tiny concurrency-safe tally of verdict-engine
// outcomes by tier, drained per hub upload to populate Upload.VerdictSummary.
package verdictcount

import "sync"

type Counter struct {
	mu       sync.Mutex
	critical int
	high     int
	total    int
}

func New() *Counter { return &Counter{} }

// Record adds one verdict of the given tier.
func (c *Counter) Record(tier string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	switch tier {
	case "critical":
		c.critical++
	case "high":
		c.high++
	}
}

// Drain returns the current counts and resets them to zero. Returns
// (0,0,0) if nothing recorded. Callers map this to baselinehub.VerdictSummary.
func (c *Counter) Drain() (critical, high, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	critical, high, total = c.critical, c.high, c.total
	c.critical, c.high, c.total = 0, 0, 0
	return
}
