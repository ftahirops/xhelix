// Package cgroupclass classifies a pid by which slice of the system
// it belongs to: user-session app, system daemon, container payload,
// or kernel thread.
//
// This is the axis that lets the UI separate "websites the user
// opened" from "background OS traffic." See docs/NETVISIBILITY.md.
//
// Classification is a single read of /proc/<pid>/cgroup, parsed
// against the well-known systemd v1/v2 path conventions:
//
//	/user.slice/user-1000.slice/...     -> ClassUser
//	/system.slice/<unit>.service        -> ClassSystem
//	/system.slice/docker-<id>.scope     -> ClassContainer
//	/kubepods.slice/...                 -> ClassContainer
//	(no cgroup file, kernel thread)     -> ClassKernel
//
// Results are cached per-pid so repeat lookups are O(1). The cache
// is bounded; oldest entries are evicted on overflow.
package cgroupclass

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"time"
)

// Class is the high-level bucket a pid belongs to.
type Class uint8

const (
	ClassUnknown   Class = 0
	ClassUser      Class = 1
	ClassSystem    Class = 2
	ClassContainer Class = 3
	ClassKernel    Class = 4
)

// String returns a stable lowercase token suitable for tags.
func (c Class) String() string {
	switch c {
	case ClassUser:
		return "user"
	case ClassSystem:
		return "system"
	case ClassContainer:
		return "container"
	case ClassKernel:
		return "kernel"
	}
	return "unknown"
}

// Info is the full classification result for a pid.
type Info struct {
	Class       Class
	Unit        string // systemd unit (e.g. "snapd.service") if any
	ContainerID string // docker/containerd id if container
	UserID      string // "1000" if ClassUser, empty otherwise
	RawPath     string // last cgroup line, for debugging
}

// Classifier resolves pid -> Info with a bounded LRU cache.
type Classifier struct {
	mu    sync.Mutex
	cache map[uint32]cacheEntry
	cap   int
	now   func() time.Time
	read  func(string) ([]byte, error) // injectable for tests
}

type cacheEntry struct {
	info Info
	used time.Time
}

// New returns a Classifier with the given soft cap (cap<=0 -> 4096).
func New(cap int) *Classifier {
	if cap <= 0 {
		cap = 4096
	}
	return &Classifier{
		cache: make(map[uint32]cacheEntry, 256),
		cap:   cap,
		now:   time.Now,
		read:  os.ReadFile,
	}
}

// Classify returns the Info for pid. On any read error it returns
// {Class: ClassUnknown}. A pid with no /proc entry (already exited
// or kernel thread) is reported as ClassKernel when the cgroup file
// is missing — callers that need to distinguish "exited" from
// "kernel" should consult proctree.
func (c *Classifier) Classify(pid uint32) Info {
	c.mu.Lock()
	if e, ok := c.cache[pid]; ok {
		e.used = c.now()
		c.cache[pid] = e
		c.mu.Unlock()
		return e.info
	}
	c.mu.Unlock()

	info := readAndParse(pid, c.read)

	c.mu.Lock()
	if len(c.cache) >= c.cap {
		c.evictLocked()
	}
	c.cache[pid] = cacheEntry{info: info, used: c.now()}
	c.mu.Unlock()
	return info
}

// Forget drops pid from the cache. Call from a proctree OnExit hook
// to keep the cache size proportional to live processes.
func (c *Classifier) Forget(pid uint32) {
	c.mu.Lock()
	delete(c.cache, pid)
	c.mu.Unlock()
}

// Len returns the current cache size.
func (c *Classifier) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

// evictLocked drops ~10% of the oldest entries (at least one).
func (c *Classifier) evictLocked() {
	drop := c.cap / 10
	if drop < 1 {
		drop = 1
	}
	target := c.cap - drop
	if target < 1 {
		target = 1
	}
	if len(c.cache) <= target {
		return
	}
	type kv struct {
		pid  uint32
		used time.Time
	}
	all := make([]kv, 0, len(c.cache))
	for pid, e := range c.cache {
		all = append(all, kv{pid, e.used})
	}
	// Partial sort: just walk and delete the oldest until target.
	// Simpler: full sort is fine at this cap.
	for len(c.cache) > target {
		oldestIdx := 0
		for i := 1; i < len(all); i++ {
			if all[i].used.Before(all[oldestIdx].used) {
				oldestIdx = i
			}
		}
		delete(c.cache, all[oldestIdx].pid)
		all = append(all[:oldestIdx], all[oldestIdx+1:]...)
	}
}

// readAndParse is split out so tests can inject /proc contents.
func readAndParse(pid uint32, read func(string) ([]byte, error)) Info {
	path := "/proc/" + uitoa(pid) + "/cgroup"
	data, err := read(path)
	if err != nil {
		// Most common cause for an alive pid is a kernel thread.
		return Info{Class: ClassKernel}
	}
	return parseCgroupFile(data)
}

// parseCgroupFile applies the path-prefix rules. Exported for tests.
func parseCgroupFile(data []byte) Info {
	var last string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		// Each line: "<hierarchy-id>:<controller>:<path>"
		// We only care about the path (third field).
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		rest := line[idx+1:]
		idx2 := strings.Index(rest, ":")
		if idx2 < 0 {
			continue
		}
		path := rest[idx2+1:]
		// Prefer the v2 unified line (hierarchy-id "0", controller "")
		// but fall back to whichever non-empty path we last saw.
		if path != "" && path != "/" {
			last = path
		}
		if strings.HasPrefix(line, "0::") {
			last = path
			break
		}
	}
	return classifyPath(last)
}

func classifyPath(p string) Info {
	if p == "" || p == "/" {
		return Info{Class: ClassKernel, RawPath: p}
	}
	out := Info{RawPath: p}

	switch {
	case strings.Contains(p, "/kubepods"),
		strings.Contains(p, "/docker"),
		strings.Contains(p, "/containerd"),
		strings.Contains(p, "/lxc/"),
		strings.Contains(p, "/machine.slice/"):
		out.Class = ClassContainer
		out.ContainerID = extractContainerID(p)
		return out

	case strings.HasPrefix(p, "/user.slice/"),
		strings.Contains(p, "/user-"):
		out.Class = ClassUser
		out.UserID = extractUserID(p)
		out.Unit = extractUnit(p)
		return out

	case strings.HasPrefix(p, "/system.slice/"),
		strings.HasPrefix(p, "/init.scope"):
		out.Class = ClassSystem
		out.Unit = extractUnit(p)
		return out
	}

	// Unrecognised slice — treat as system rather than unknown so
	// the UI still has somewhere to put it. The RawPath stays
	// available for forensics.
	out.Class = ClassSystem
	out.Unit = extractUnit(p)
	return out
}

// extractUnit pulls the systemd unit name out of a slice path. For
// "/system.slice/snapd.service" it returns "snapd.service".
func extractUnit(p string) string {
	parts := strings.Split(p, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		seg := parts[i]
		if strings.HasSuffix(seg, ".service") ||
			strings.HasSuffix(seg, ".scope") ||
			strings.HasSuffix(seg, ".socket") ||
			strings.HasSuffix(seg, ".mount") {
			return seg
		}
	}
	return ""
}

// extractUserID pulls "1000" from "/user.slice/user-1000.slice/..."
func extractUserID(p string) string {
	const marker = "/user-"
	i := strings.Index(p, marker)
	if i < 0 {
		return ""
	}
	rest := p[i+len(marker):]
	end := strings.IndexAny(rest, ".:/")
	if end < 0 {
		return rest
	}
	return rest[:end]
}

// extractContainerID pulls the cgroup-encoded container id out of a
// path. Supports docker ("docker-<64hex>.scope") and the kubepods
// pattern ("cri-containerd-<id>.scope" / "<id>.slice").
func extractContainerID(p string) string {
	parts := strings.Split(p, "/")
	last := parts[len(parts)-1]
	// Strip well-known prefixes/suffixes.
	for _, pfx := range []string{"docker-", "cri-containerd-", "crio-"} {
		if strings.HasPrefix(last, pfx) {
			last = strings.TrimPrefix(last, pfx)
			break
		}
	}
	for _, sfx := range []string{".scope", ".slice"} {
		last = strings.TrimSuffix(last, sfx)
	}
	// kubepods sometimes uses an "pod<uuid>" naming — keep as-is.
	return last
}

// uitoa: small int->string without strconv import churn in this file.
func uitoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
