package serviceid

import "sync"

// Cache maps cgroup_id → service name. Empty-string value means
// "known not-a-protected-service" (negative cache, so we don't
// re-walk /proc for every non-matching process).
//
// Eviction: bounded LRU of MaxEntries; oldest dropped first. cgroup_ids
// are stable for the lifetime of a cgroup, so re-creating a cgroup
// gets a new id automatically — no explicit invalidation needed for
// process churn.
type Cache struct {
	mu         sync.Mutex
	maxEntries int
	m          map[uint64]string
	order      []uint64 // FIFO eviction
}

// DefaultMaxEntries — generous enough for any single host (you'd
// never have more than a few hundred distinct cgroup ids in flight).
const DefaultMaxEntries = 4096

// NewCache returns an empty cache with the default cap.
func NewCache() *Cache {
	return &Cache{
		maxEntries: DefaultMaxEntries,
		m:          map[uint64]string{},
	}
}

// NewCacheWithCap is for tests that want tight eviction behavior.
func NewCacheWithCap(n int) *Cache {
	if n <= 0 {
		n = DefaultMaxEntries
	}
	return &Cache{
		maxEntries: n,
		m:          map[uint64]string{},
	}
}

// Get returns (name, true) if cached, ("", false) if missing.
// Note: a cached empty-string ("", true) means "negative match".
func (c *Cache) Get(cgroupID uint64) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[cgroupID]
	return v, ok
}

// Set records a mapping. Empty name = negative cache entry.
func (c *Cache) Set(cgroupID uint64, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.m[cgroupID]; !exists {
		c.order = append(c.order, cgroupID)
	}
	c.m[cgroupID] = name

	for len(c.m) > c.maxEntries && len(c.order) > 0 {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.m, evict)
	}
}

// Forget removes an entry. Used after config reload when a service
// disappears (negative cache + positive cache both want clearing).
func (c *Cache) Forget(cgroupID uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, cgroupID)
	for i, id := range c.order {
		if id == cgroupID {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
}

// Reset drops every entry. Called on full config reload.
func (c *Cache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = map[uint64]string{}
	c.order = c.order[:0]
}

// Len returns the current entry count (positive + negative).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.m)
}
