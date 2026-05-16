package dnsresolver

import (
	"sync"
	"time"
)

// PIDResolver looks up the pid (and optionally exe) that owns a
// given UDP source port. Production callers use ProcNetUDPResolver
// (procnet.go). Tests inject a fake.
type PIDResolver interface {
	// PIDForUDPPort returns (pid, exe, ok). ok=false means no
	// owner could be resolved within the implementation's policy.
	PIDForUDPPort(port uint16) (pid uint32, exe string, ok bool)
}

// Collector accumulates DNS observations, attributes them to pids,
// and forwards them to a Sink.
//
// The dedupe window prevents one DNS exchange from producing
// multiple Observations when a daemon dispatcher feeds both the
// query and the answer separately. Same (qname, qtype, pid) seen
// within DedupeWindow is collapsed.
type Collector struct {
	// PID resolver. Required.
	Resolver PIDResolver

	// Sink callback. Required.
	Sink Sink

	// DedupeWindow is the deduplication horizon. <=0 means 1s.
	DedupeWindow time.Duration

	// AttributionWindow is the maximum acceptable age of a UDP
	// port→pid mapping for late-arriving observations. <=0 means 2s.
	AttributionWindow time.Duration

	mu         sync.Mutex
	recentSeen map[string]time.Time // key: qname+":"+qtype+":"+pid
	now        func() time.Time
}

// NewCollector returns a ready collector. resolver and sink may
// be set later (before any Observe), but production callers
// usually set both up-front.
func NewCollector(resolver PIDResolver, sink Sink) *Collector {
	return &Collector{
		Resolver:          resolver,
		Sink:              sink,
		DedupeWindow:      time.Second,
		AttributionWindow: 2 * time.Second,
		recentSeen:        map[string]time.Time{},
		now:               time.Now,
	}
}

// Observe ingests one Observation. The Collector fills PID and Exe
// via Resolver if Observation.PID is still 0, applies dedupe, and
// invokes Sink. Returns true if the observation was forwarded.
func (c *Collector) Observe(obs Observation) bool {
	if c.Sink == nil {
		return false
	}
	if obs.At.IsZero() {
		obs.At = c.nowFn()()
	}
	// Resolve pid by source port if not yet attributed and we have
	// a non-zero port and the query wasn't encrypted (which would
	// hide the qname anyway and make pid attribution moot).
	if obs.PID == 0 && obs.SrcPort != 0 && c.Resolver != nil {
		if pid, exe, ok := c.Resolver.PIDForUDPPort(obs.SrcPort); ok {
			obs.PID = pid
			if obs.Exe == "" {
				obs.Exe = exe
			}
		}
	}

	if c.isDuplicate(obs) {
		return false
	}
	c.Sink(obs)
	return true
}

// Sweep evicts dedupe entries older than DedupeWindow. Call from a
// periodic goroutine; safe to call concurrently with Observe.
func (c *Collector) Sweep(now time.Time) int {
	if now.IsZero() {
		now = c.nowFn()()
	}
	w := c.DedupeWindow
	if w <= 0 {
		w = time.Second
	}
	cutoff := now.Add(-w * 2)
	removed := 0
	c.mu.Lock()
	for k, t := range c.recentSeen {
		if t.Before(cutoff) {
			delete(c.recentSeen, k)
			removed++
		}
	}
	c.mu.Unlock()
	return removed
}

// isDuplicate returns true if (qname, qtype, pid) was already seen
// within DedupeWindow.
func (c *Collector) isDuplicate(obs Observation) bool {
	w := c.DedupeWindow
	if w <= 0 {
		w = time.Second
	}
	key := dedupeKey(obs)
	c.mu.Lock()
	defer c.mu.Unlock()
	if last, ok := c.recentSeen[key]; ok {
		if obs.At.Sub(last) < w {
			return true
		}
	}
	c.recentSeen[key] = obs.At
	return false
}

func dedupeKey(obs Observation) string {
	// Compact key: 1-3 fields, separated. Allocation-friendly.
	pid := ""
	if obs.PID != 0 {
		pid = itoa(int(obs.PID))
	}
	return obs.QName + "|" + obs.QType + "|" + pid
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func (c *Collector) nowFn() func() time.Time {
	if c.now != nil {
		return c.now
	}
	return time.Now
}
