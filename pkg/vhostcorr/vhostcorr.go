// Package vhostcorr correlates inbound HTTP requests with the outbound
// connects a web worker makes in response. The lifecycle:
//
//  1. A web worker (php-fpm child, nginx upstream worker) receives an
//     inbound TLS request. The dpi sensor extracts the Host header
//     and emits an SSL_READ event with http_host=<vhost>.
//
//  2. Pipeline.Handle calls vhostcorr.Note(pid, vhost, now) for that
//     event. The pid is the worker's PID.
//
//  3. Within TTL (default 2s), the same worker pid issues an outbound
//     connect (DB query, API call). Pipeline.Handle calls
//     vhostcorr.Lookup(pid, now) → returns the vhost. The outbound
//     event is then tagged inbound_vhost=<vhost>, so analytics can
//     answer "how much outbound did site-a generate?"
//
// Best-effort. False-positive cases:
//   - worker handles requests for many vhosts in parallel (rare; most
//     PHP-FPM and similar runtimes are request-per-worker)
//   - a long-running keepalive worker overlaps requests
//   - background outbound (cron-style) inside a worker
//
// Honest accuracy target: ~85%. We accept that imperfect attribution
// is more useful than no attribution for ops dashboards.
package vhostcorr

import (
	"sync"
	"time"
)

// Correlator holds per-pid pending vhost slots, sharded for low contention.
type Correlator struct {
	ttl    time.Duration
	clock  func() time.Time
	shards [16]shard
}

type shard struct {
	mu  sync.Mutex
	pid map[uint32]entry
}

type entry struct {
	host string
	at   time.Time
}

// New constructs a Correlator with the given TTL. Zero TTL → default 2s.
func New(ttl time.Duration) *Correlator {
	if ttl <= 0 {
		ttl = 2 * time.Second
	}
	c := &Correlator{ttl: ttl, clock: time.Now}
	for i := range c.shards {
		c.shards[i].pid = map[uint32]entry{}
	}
	return c
}

// WithClock overrides time.Now (test hook).
func (c *Correlator) WithClock(f func() time.Time) *Correlator { c.clock = f; return c }

func (c *Correlator) shardFor(pid uint32) *shard {
	return &c.shards[pid%uint32(len(c.shards))]
}

// Note records that pid is currently handling a request for vhost.
// Replaces any older entry for the same pid (newest wins).
func (c *Correlator) Note(pid uint32, host string) {
	if pid == 0 || host == "" {
		return
	}
	sh := c.shardFor(pid)
	sh.mu.Lock()
	sh.pid[pid] = entry{host: host, at: c.clock()}
	sh.mu.Unlock()
}

// Lookup returns the most recent vhost for pid, or "" if no entry
// exists or it's older than TTL. Lazy-cleanup: stale entries removed
// on miss.
func (c *Correlator) Lookup(pid uint32) (string, bool) {
	if pid == 0 {
		return "", false
	}
	sh := c.shardFor(pid)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.pid[pid]
	if !ok {
		return "", false
	}
	if c.clock().Sub(e.at) > c.ttl {
		delete(sh.pid, pid)
		return "", false
	}
	return e.host, true
}

// Forget drops state for pid (call on exit).
func (c *Correlator) Forget(pid uint32) {
	sh := c.shardFor(pid)
	sh.mu.Lock()
	delete(sh.pid, pid)
	sh.mu.Unlock()
}

// Sweep removes all entries older than TTL. Cheap to call periodically;
// also auto-prunes on Lookup misses, so explicit sweep is optional.
func (c *Correlator) Sweep() {
	now := c.clock()
	for i := range c.shards {
		sh := &c.shards[i]
		sh.mu.Lock()
		for pid, e := range sh.pid {
			if now.Sub(e.at) > c.ttl {
				delete(sh.pid, pid)
			}
		}
		sh.mu.Unlock()
	}
}
