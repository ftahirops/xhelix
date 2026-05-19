package canonical

import (
	"sync"
	"sync/atomic"
	"time"
)

// ProcKeyCache is a bounded, TTL-keyed cache for ReadProcKey results.
//
// Per-event lookups during enrichment are the hot path. A cold
// ReadProcKey is ~9.5 µs (single /proc/<pid>/stat read + parse);
// the warm cache path is < 100 ns.
//
// PID-reuse safety: the cached value carries the original StartTicks,
// which is what makes ProcKey PID-reuse-safe in the first place. The
// TTL bounds the stale window for a PID that has died and been
// re-used; for stronger guarantees, callers driving an event source
// (e.g. an eBPF exec sensor) should Invalidate(pid) on exec.
//
// Concurrent-safe via a single mutex. Sub-microsecond operations
// don't suffer meaningfully from contention at expected event rates.
type ProcKeyCache struct {
	mu      sync.Mutex
	entries map[uint32]procKeyEntry
	maxSize int
	ttl     time.Duration

	hits   atomic.Uint64
	misses atomic.Uint64
	evicts atomic.Uint64
}

type procKeyEntry struct {
	key      ProcKey
	cachedAt time.Time
}

// CacheOptions configures a ProcKeyCache. Zero values pick sensible
// defaults (4096 entries / 60 s TTL).
type CacheOptions struct {
	MaxSize int
	TTL     time.Duration
}

// NewProcKeyCache constructs a cache. Defaults: 4096 entries, 60 s TTL.
func NewProcKeyCache(opts CacheOptions) *ProcKeyCache {
	if opts.MaxSize <= 0 {
		opts.MaxSize = 4096
	}
	if opts.TTL <= 0 {
		opts.TTL = 60 * time.Second
	}
	return &ProcKeyCache{
		entries: make(map[uint32]procKeyEntry, opts.MaxSize),
		maxSize: opts.MaxSize,
		ttl:     opts.TTL,
	}
}

// Get returns the cached ProcKey for pid if present and not expired.
// Cache misses (absent or expired) bump the miss counter.
func (c *ProcKeyCache) Get(pid uint32) (ProcKey, bool) {
	c.mu.Lock()
	e, ok := c.entries[pid]
	c.mu.Unlock()
	if !ok {
		c.misses.Add(1)
		return ProcKey{}, false
	}
	if time.Since(e.cachedAt) > c.ttl {
		// Expired — treat as miss. Don't bother deleting here;
		// it'll be evicted on the next Put-driven sweep.
		c.misses.Add(1)
		return ProcKey{}, false
	}
	c.hits.Add(1)
	return e.key, true
}

// Put stores a ProcKey. If the cache is at capacity, expired entries
// are swept first; if still at capacity, one entry is evicted (map
// iteration order — effectively pseudo-random, which is adequate for
// a bounded cache of independent keys).
func (c *ProcKeyCache) Put(pk ProcKey) {
	if pk.PID == 0 {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		// Sweep expired first.
		for pid, e := range c.entries {
			if now.Sub(e.cachedAt) > c.ttl {
				delete(c.entries, pid)
				c.evicts.Add(1)
			}
		}
		// Still over cap? Drop one arbitrary entry.
		if len(c.entries) >= c.maxSize {
			for pid := range c.entries {
				delete(c.entries, pid)
				c.evicts.Add(1)
				break
			}
		}
	}

	c.entries[pk.PID] = procKeyEntry{key: pk, cachedAt: now}
}

// Invalidate drops the entry for pid. Call from sensor code that
// observes a PID transition (e.g. exec, exit), so subsequent
// Resolve() calls re-read /proc rather than returning stale data.
func (c *ProcKeyCache) Invalidate(pid uint32) {
	c.mu.Lock()
	if _, ok := c.entries[pid]; ok {
		delete(c.entries, pid)
		c.evicts.Add(1)
	}
	c.mu.Unlock()
}

// Resolve returns the cached ProcKey for pid, reading /proc on a
// miss. The freshly-read key is stored before returning.
//
// This is the convenience method for callers that don't care whether
// the result came from cache or disk.
func (c *ProcKeyCache) Resolve(pid uint32) (ProcKey, error) {
	if pk, ok := c.Get(pid); ok {
		return pk, nil
	}
	pk, err := ReadProcKey(pid)
	if err != nil {
		return ProcKey{}, err
	}
	c.Put(pk)
	return pk, nil
}

// Size returns the current number of cached entries.
func (c *ProcKeyCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// Stats is the snapshot returned by Stats(). Useful for health.snapshot.
type CacheStats struct {
	Size    int    `json:"size"`
	MaxSize int    `json:"max_size"`
	TTLSecs int    `json:"ttl_secs"`
	Hits    uint64 `json:"hits"`
	Misses  uint64 `json:"misses"`
	Evicts  uint64 `json:"evicts"`
}

// Stats returns a snapshot of the cache counters.
func (c *ProcKeyCache) Stats() CacheStats {
	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	return CacheStats{
		Size:    size,
		MaxSize: c.maxSize,
		TTLSecs: int(c.ttl / time.Second),
		Hits:    c.hits.Load(),
		Misses:  c.misses.Load(),
		Evicts:  c.evicts.Load(),
	}
}

// HitRatio returns hits / (hits+misses). Returns 0 if no lookups yet.
func (c *ProcKeyCache) HitRatio() float64 {
	h := c.hits.Load()
	m := c.misses.Load()
	total := h + m
	if total == 0 {
		return 0
	}
	return float64(h) / float64(total)
}
