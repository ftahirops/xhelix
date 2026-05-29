//go:build linux

// Bootstrap the proctree from the live /proc filesystem on daemon
// startup. Without this, any process that started BEFORE xhelix is
// invisible to the graph until it spawns a child — which means
// ancestor lookups return empty for nginx, sshd, systemd, etc.
//
// Walks /proc once, calls OnSpawn for every running PID with its PPID,
// comm, and exe. Cheap (~5-10 ms on a typical box, <1 s on a 50k-PID
// host). Idempotent — duplicate OnSpawn calls just refresh LastEvent.
package proctree

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// BootstrapFromProc walks /proc and seeds the graph with every
// currently-running process. Errors are best-effort and logged via
// the caller's logger (none in this package; we return a count).
//
// Returns the number of nodes inserted.
func (g *Graph) BootstrapFromProc() int {
	if g == nil {
		return 0
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	now := time.Now()
	count := 0
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid64, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		comm := strings.TrimSpace(readProcFile("/proc/" + name + "/comm"))
		exe, _ := os.Readlink("/proc/" + name + "/exe")
		ppid, uid := readProcStatus(name)
		// Parse cmdline → argv.
		var argv []string
		if cl := readProcFile("/proc/" + name + "/cmdline"); cl != "" {
			parts := strings.Split(strings.TrimRight(cl, "\x00"), "\x00")
			for _, p := range parts {
				if p != "" {
					argv = append(argv, p)
				}
			}
		}
		g.OnSpawn(Node{
			PID:       pid,
			PPID:      ppid,
			Comm:      comm,
			Image:     exe,
			UID:       uid,
			Argv:      argv,
			FirstSeen: now, // best-effort — real start time isn't critical for ancestor lookup
			LastEvent: now,
		})
		count++
	}
	return count
}

func readProcFile(path string) string {
	const max = 4096
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

func readProcStatus(pidStr string) (ppid, uid uint32) {
	body := readProcFile("/proc/" + pidStr + "/status")
	for _, line := range strings.Split(body, "\n") {
		switch {
		case strings.HasPrefix(line, "PPid:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				ppid = uint32(n)
			}
		case strings.HasPrefix(line, "Uid:"):
			fs := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fs) > 0 {
				if n, err := strconv.ParseUint(fs[0], 10, 32); err == nil {
					uid = uint32(n)
				}
			}
		}
	}
	return
}
