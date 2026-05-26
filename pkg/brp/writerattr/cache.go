// Package writerattr implements a short-window cache that maps file paths
// to recently-observed writers. It exists because the FIM (inotify)
// sensor produces high-fidelity write events with NO writer identity,
// while eBPF file_write events produce writer identity but cannot watch
// arbitrary paths cheaply. By recording writers from eBPF events keyed
// by path, FIM events for the same path can recover the writer if they
// arrive within the time window.
//
// This is the practical bridge from "FIM saw a write to /etc/shadow"
// to "this writer was dpkg" — which is what BRP's protected-path check
// needs to make a Hard-Deny vs Verify decision.
//
// Trade-offs:
//
//   - bounded LRU (default 4096 entries) + TTL (default 5s) keeps memory
//     small and prevents stale attribution from leaking across unrelated
//     writes to the same path.
//   - the window is intentionally short. False attribution is a SECURITY
//     bug (an attacker could exploit a stale entry to bypass protected
//     paths). 5 seconds covers normal kernel-to-userspace event lag plus
//     a generous margin; long-running writes that span >5s will lose
//     attribution and fall back to the unattributed-Verify branch.
//   - matching is by exact path. We do not normalize symlinks or resolve
//     /proc/self — callers should canonicalize before recording.
package writerattr

import (
	"container/list"
	"sync"
	"time"
)

// Writer is the attribution recovered from a recent eBPF write event.
type Writer struct {
	PID     uint32
	Comm    string
	ExePath string
	When    time.Time
}

// Cache is a bounded LRU mapping path → most-recent Writer.
//
// Safe for concurrent use. The size and TTL bounds are absolute — once
// either is exceeded, the oldest entry is evicted.
type Cache struct {
	mu      sync.Mutex
	maxSize int
	ttl     time.Duration
	entries map[string]*list.Element
	lru     *list.List
}

type entry struct {
	path string
	w    Writer
}

// NewCache constructs a Cache with the given bounds. maxSize<=0 → 4096,
// ttl<=0 → 5 seconds.
func NewCache(maxSize int, ttl time.Duration) *Cache {
	if maxSize <= 0 {
		maxSize = 4096
	}
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Cache{
		maxSize: maxSize,
		ttl:     ttl,
		entries: map[string]*list.Element{},
		lru:     list.New(),
	}
}

// Record stores a writer for the given path. An existing entry is
// overwritten (last-writer-wins) — the latest writer is the most likely
// attribution for a FIM event arriving shortly after.
func (c *Cache) Record(path string, w Writer) {
	if path == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.entries[path]; ok {
		el.Value.(*entry).w = w
		c.lru.MoveToFront(el)
		return
	}
	el := c.lru.PushFront(&entry{path: path, w: w})
	c.entries[path] = el
	for c.lru.Len() > c.maxSize {
		oldest := c.lru.Back()
		if oldest == nil {
			break
		}
		c.lru.Remove(oldest)
		delete(c.entries, oldest.Value.(*entry).path)
	}
}

// Lookup returns the most-recent writer for path if recorded within the
// TTL window. (Writer{}, false) when no fresh attribution exists.
func (c *Cache) Lookup(path string, now time.Time) (Writer, bool) {
	if path == "" {
		return Writer{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[path]
	if !ok {
		return Writer{}, false
	}
	w := el.Value.(*entry).w
	if now.Sub(w.When) > c.ttl {
		// Stale — drop and report miss. We MUST NOT return stale
		// attribution; a too-old write event matched to a current
		// FIM event would mis-attribute.
		c.lru.Remove(el)
		delete(c.entries, path)
		return Writer{}, false
	}
	c.lru.MoveToFront(el)
	return w, true
}

// Size returns the current entry count (test helper).
func (c *Cache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Sweep drops entries older than the TTL. Returns the number reclaimed.
// Called periodically by a long-running goroutine to keep memory bounded
// when no fresh writes are arriving.
func (c *Cache) Sweep(now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for el := c.lru.Back(); el != nil; {
		prev := el.Prev()
		e := el.Value.(*entry)
		if now.Sub(e.w.When) > c.ttl {
			c.lru.Remove(el)
			delete(c.entries, e.path)
			n++
		}
		el = prev
	}
	return n
}
