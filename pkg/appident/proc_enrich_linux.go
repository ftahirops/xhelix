//go:build linux

package appident

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ResolveCGroupID resolves the cgroup-v2 inode number for pid, which
// the kernel uses as the canonical cgroup identifier. Stable across
// worker restarts within the same cgroup (e.g. all php-fpm workers of
// the same pool share the inode of their pool slice).
//
// Returns 0 on any failure (caller falls back to PID).
func ResolveCGroupID(pid uint32) uint64 {
	cg := readCgroup(pid)
	if cg == "" {
		return 0
	}
	// cgroup v2 unified path is "/sys/fs/cgroup" + the v2 cgroup path.
	// For pid 1 it'd be "/sys/fs/cgroup/" + "/init.scope".
	full := filepath.Join("/sys/fs/cgroup", cg)
	st, err := os.Stat(full)
	if err != nil {
		return 0
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return sys.Ino
}

// EnrichFromProc fills in any empty Signals fields by reading /proc.
// Cheap-but-not-free: ~3 small file reads. Caller should only invoke
// when signals are insufficient and the lineage isn't already cached.
func EnrichFromProc(pid uint32, s Signals) Signals {
	if pid == 0 {
		return s
	}
	if s.CgroupPath == "" {
		s.CgroupPath = readCgroup(pid)
	}
	if s.ExePath == "" {
		if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			s.ExePath = strings.TrimSuffix(link, " (deleted)")
		}
	}
	if s.ArgvJoined == "" {
		s.ArgvJoined = readCmdline(pid)
	}
	return s
}

func readCgroup(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	// cgroup v2 line: "0::/system.slice/php-fpm@site-a.service"
	// cgroup v1 lines: "<id>:<controllers>:<path>"
	// We want the v2 path. If multiple lines, prefer the "0::" one.
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	// v1 fallback — pick the first non-empty path field.
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[2] != "" {
			return parts[2]
		}
	}
	return ""
}

func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// cmdline uses NUL separators between args.
	return string(bytes.ReplaceAll(bytes.TrimRight(data, "\x00"), []byte{0}, []byte{' '}))
}
