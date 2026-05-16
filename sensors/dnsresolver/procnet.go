package dnsresolver

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcNetUDPResolver implements PIDResolver by reading
// /proc/net/udp{,6} and walking /proc/<pid>/fd to find which pid
// owns the given local UDP port.
//
// Caches the (port → pid) mapping for CacheTTL to amortise the
// O(N) walk. Cache misses fall through to a fresh scan. Production
// callers should set CacheTTL ≥ 500ms; tests often use 0 to
// disable caching.
//
// This is the same trick Portmaster and OpenSnitch use. It's racy
// (the socket may close between scan and lookup) but adequate for
// observation-only mode where occasional misattributions are
// preferred to blocking on the dispatch path.
type ProcNetUDPResolver struct {
	// CacheTTL is how long a port→pid mapping is reused. <=0
	// disables caching.
	CacheTTL time.Duration

	// ProcRoot lets tests substitute a fake /proc tree.
	ProcRoot string

	mu        sync.Mutex
	cache     map[uint16]cacheEntry
	now       func() time.Time
}

type cacheEntry struct {
	pid uint32
	exe string
	at  time.Time
}

// NewProcNetUDPResolver returns a resolver with sane defaults.
func NewProcNetUDPResolver() *ProcNetUDPResolver {
	return &ProcNetUDPResolver{
		CacheTTL: time.Second,
		ProcRoot: "/proc",
		cache:    map[uint16]cacheEntry{},
		now:      time.Now,
	}
}

// PIDForUDPPort implements PIDResolver. Returns (pid, exe, ok).
func (r *ProcNetUDPResolver) PIDForUDPPort(port uint16) (uint32, string, bool) {
	if port == 0 {
		return 0, "", false
	}
	if r.CacheTTL > 0 {
		r.mu.Lock()
		if e, ok := r.cache[port]; ok && r.nowFn()().Sub(e.at) < r.CacheTTL {
			r.mu.Unlock()
			return e.pid, e.exe, e.pid != 0
		}
		r.mu.Unlock()
	}

	inode, ok := r.findInodeForPort(port)
	if !ok {
		return 0, "", false
	}
	pid, exe, ok := r.findPIDForInode(inode)
	if r.CacheTTL > 0 {
		r.mu.Lock()
		r.cache[port] = cacheEntry{pid: pid, exe: exe, at: r.nowFn()()}
		r.mu.Unlock()
	}
	return pid, exe, ok
}

// findInodeForPort scans /proc/net/udp{,6} for a row whose
// local-port column matches port. Returns the socket inode.
func (r *ProcNetUDPResolver) findInodeForPort(port uint16) (string, bool) {
	for _, name := range []string{"net/udp", "net/udp6"} {
		f, err := os.Open(r.ProcRoot + "/" + name)
		if err != nil {
			continue
		}
		inode, ok := scanProcNetUDP(f, port)
		_ = f.Close()
		if ok {
			return inode, true
		}
	}
	return "", false
}

// scanProcNetUDP walks one /proc/net/udp{,6}-style stream.
// Each row has fields:
//
//	sl  local_address:port  rem_address:port  st  ...  inode ...
//
// We need columns 1 (local) for port match and 9 (inode).
func scanProcNetUDP(r io.Reader, port uint16) (string, bool) {
	sc := bufio.NewScanner(r)
	// Skip header
	if !sc.Scan() {
		return "", false
	}
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// fields[1] is "<addr-hex>:<port-hex>"
		idx := strings.LastIndexByte(fields[1], ':')
		if idx < 0 {
			continue
		}
		portStr := fields[1][idx+1:]
		v, err := strconv.ParseUint(portStr, 16, 32)
		if err != nil {
			continue
		}
		if uint16(v) != port {
			continue
		}
		// inode is column 9 in `man 5 proc` numbering (0-based,
		// after "uid", "timeout").
		inode := fields[9]
		return inode, true
	}
	return "", false
}

// findPIDForInode walks /proc/<pid>/fd/ links and returns the pid
// whose fd resolves to socket:[<inode>]. Cheap on a few hundred
// pids; we cap the walk at SystemMaxPids.
func (r *ProcNetUDPResolver) findPIDForInode(inode string) (uint32, string, bool) {
	wantTarget := "socket:[" + inode + "]"
	procRoot := r.ProcRoot

	dir, err := os.Open(procRoot)
	if err != nil {
		return 0, "", false
	}
	defer dir.Close()

	for {
		names, err := dir.Readdirnames(256)
		if err != nil {
			break
		}
		for _, name := range names {
			if len(name) == 0 || name[0] < '0' || name[0] > '9' {
				continue
			}
			pid64, err := strconv.ParseUint(name, 10, 32)
			if err != nil {
				continue
			}
			fdDir := procRoot + "/" + name + "/fd"
			fds, err := os.Open(fdDir)
			if err != nil {
				continue
			}
			fdNames, _ := fds.Readdirnames(-1)
			fds.Close()
			for _, fn := range fdNames {
				link, err := os.Readlink(fdDir + "/" + fn)
				if err != nil {
					continue
				}
				if link == wantTarget {
					exe, _ := os.Readlink(procRoot + "/" + name + "/exe")
					return uint32(pid64), exe, true
				}
			}
		}
	}
	return 0, "", false
}

func (r *ProcNetUDPResolver) nowFn() func() time.Time {
	if r.now != nil {
		return r.now
	}
	return time.Now
}
