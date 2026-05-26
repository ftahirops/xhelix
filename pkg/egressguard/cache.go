package egressguard

import (
	"sync"
	"time"
)

// denyCache is a bounded in-memory map keyed by (lineageID, destKey).
// Used by Guard.ApplyDeny to suppress duplicate denies for the same
// lineage+dest within TTL.
//
// Bounded by maxEntries (default 4096) to prevent unbounded growth
// under attack. LRU eviction by insertion order (last add wins).
type denyCache struct {
	mu         sync.Mutex
	entries    map[string]time.Time // key → expiry
	maxEntries int
}

func newDenyCache() *denyCache {
	return &denyCache{
		entries:    make(map[string]time.Time),
		maxEntries: 4096,
	}
}

func cacheKey(lineage uint64, destKey string) string {
	return string(rune(lineage)) + ":" + destKey
}

func (c *denyCache) has(lineage uint64, destKey string) bool {
	if destKey == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.entries[cacheKey(lineage, destKey)]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(c.entries, cacheKey(lineage, destKey))
		return false
	}
	return true
}

func (c *denyCache) add(lineage uint64, destKey string, ttl time.Duration) {
	if destKey == "" || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Bound: if at cap, evict ~10% oldest by re-scanning. Simple.
	if len(c.entries) >= c.maxEntries {
		threshold := time.Now()
		for k, exp := range c.entries {
			if exp.Before(threshold) {
				delete(c.entries, k)
			}
			if len(c.entries) < c.maxEntries*9/10 {
				break
			}
		}
		// If still at cap, drop random until under limit.
		for k := range c.entries {
			if len(c.entries) < c.maxEntries*9/10 {
				break
			}
			delete(c.entries, k)
		}
	}
	c.entries[cacheKey(lineage, destKey)] = time.Now().Add(ttl)
}

// Size returns the current entry count (test/metrics helper).
func (c *denyCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
