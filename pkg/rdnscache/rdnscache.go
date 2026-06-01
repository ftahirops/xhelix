// Package rdnscache is a bounded, TTL'd reverse-DNS (PTR) cache. The egress
// dashboard previously issued a fresh LookupAddr on every page load; this
// caches results (including negatives) so repeated views are cheap and a
// single IP is not re-resolved on every refresh.
package rdnscache

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// ResolveFunc performs the actual PTR lookup (e.g. net.DefaultResolver.LookupAddr
// wrapped to return a single name).
type ResolveFunc func(ctx context.Context, ip string) (string, error)

type entry struct {
	name string
	err  bool // true if the underlying lookup failed (negative cache)
	at   time.Time
}

// Cache is a concurrency-safe TTL + soft-cap LRU-ish PTR cache.
type Cache struct {
	mu      sync.Mutex
	entries map[string]entry
	ttl     time.Duration
	cap     int
	now     func() time.Time
	resolve ResolveFunc

	hits   atomic.Uint64
	misses atomic.Uint64
}

// New builds a cache. ttl<=0 defaults to 1h; cap<=0 defaults to 8192.
func New(ttl time.Duration, cap int, resolve ResolveFunc) *Cache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if cap <= 0 {
		cap = 8192
	}
	return &Cache{
		entries: make(map[string]entry, 256),
		ttl:     ttl,
		cap:     cap,
		now:     time.Now,
		resolve: resolve,
	}
}

// Lookup returns the PTR name for ip, using the cache when fresh. A cached
// negative (prior failure) is returned as ("", false) without re-resolving
// until its TTL expires.
func (c *Cache) Lookup(ctx context.Context, ip string) (string, bool) {
	now := c.now()
	c.mu.Lock()
	if e, ok := c.entries[ip]; ok && now.Sub(e.at) < c.ttl {
		c.mu.Unlock()
		c.hits.Add(1)
		if e.err || e.name == "" {
			return "", false
		}
		return e.name, true
	}
	c.mu.Unlock()
	c.misses.Add(1)

	name, err := "", error(nil)
	if c.resolve != nil {
		name, err = c.resolve(ctx, ip)
	}

	c.mu.Lock()
	if len(c.entries) >= c.cap {
		c.evictOldestLocked()
	}
	c.entries[ip] = entry{name: name, err: err != nil, at: now}
	c.mu.Unlock()

	if err != nil || name == "" {
		return "", false
	}
	return name, true
}

// Stats returns (hits, misses).
func (c *Cache) Stats() (uint64, uint64) { return c.hits.Load(), c.misses.Load() }

// evictOldestLocked drops the single oldest entry. Caller holds c.mu.
func (c *Cache) evictOldestLocked() {
	var oldestKey string
	var oldestAt time.Time
	first := true
	for k, e := range c.entries {
		if first || e.at.Before(oldestAt) {
			oldestKey, oldestAt, first = k, e.at, false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
