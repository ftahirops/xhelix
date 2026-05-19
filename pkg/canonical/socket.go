package canonical

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SocketRef identifies a socket by kernel-assigned inode plus the
// PID that owns the fd. The inode is what `ss`, `lsof`, and
// `/proc/net/tcp` all use as the canonical socket identity.
type SocketRef struct {
	OwnerPID  uint32
	FD        int
	Inode     uint64
}

// IsValid returns true when the SocketRef has a real owner + inode.
func (s SocketRef) IsValid() bool {
	return s.OwnerPID != 0 && s.Inode != 0
}

// String renders as "pid=<n> fd=<n> inode=<n>" for logs.
func (s SocketRef) String() string {
	return fmt.Sprintf("pid=%d fd=%d inode=%d", s.OwnerPID, s.FD, s.Inode)
}

// SocketsForPID enumerates the socket inodes opened by a process by
// scanning /proc/PID/fd/* and parsing symlink targets of the form
// "socket:[<inode>]". Returns one SocketRef per socket fd.
//
// Returns ProcKeyNotFound if the process has exited.
func SocketsForPID(pid uint32) ([]SocketRef, error) {
	if pid == 0 {
		return nil, fmt.Errorf("canonical: pid 0 has no sockets")
	}
	dir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ProcKeyNotFound{PID: pid}
		}
		return nil, fmt.Errorf("canonical: read %s: %w", dir, err)
	}
	var out []SocketRef
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		target, err := os.Readlink(dir + "/" + e.Name())
		if err != nil {
			// fd raced exit — skip
			continue
		}
		inode, ok := parseSocketInodeLink(target)
		if !ok {
			continue
		}
		out = append(out, SocketRef{
			OwnerPID: pid,
			FD:       fd,
			Inode:    inode,
		})
	}
	return out, nil
}

// parseSocketInodeLink parses a readlink result like
// "socket:[12345]" and returns the inode. Returns false for any
// non-socket symlink target (regular files, pipes, eventpolls, etc).
func parseSocketInodeLink(target string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) {
		return 0, false
	}
	if !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inner := target[len(prefix) : len(target)-1]
	n, err := strconv.ParseUint(inner, 10, 64)
	if err != nil {
		return 0, false
	}
	if n == 0 {
		return 0, false
	}
	return n, true
}

// FindOwnerOfSocket looks up which pid currently owns the given
// socket inode by scanning all of /proc/*/fd. Cost is O(processes ×
// fds_per_process); use sparingly. Returns 0 + false when no owner
// is found (socket may have closed, or be owned by a process we
// cannot read).
//
// This is the canonical "given a socket inode in /proc/net/tcp,
// which process holds it?" join. Real systems with strict /proc
// will only let xhelix see fds for processes it can read; that
// limitation is documented, not papered over.
func FindOwnerOfSocket(targetInode uint64) (pid uint32, found bool) {
	if targetInode == 0 {
		return 0, false
	}
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, false
	}
	for _, pe := range procEntries {
		if !pe.IsDir() {
			continue
		}
		pidNum, err := strconv.ParseUint(pe.Name(), 10, 32)
		if err != nil {
			continue
		}
		dir := "/proc/" + pe.Name() + "/fd"
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fe := range entries {
			target, err := os.Readlink(dir + "/" + fe.Name())
			if err != nil {
				continue
			}
			ino, ok := parseSocketInodeLink(target)
			if !ok {
				continue
			}
			if ino == targetInode {
				return uint32(pidNum), true
			}
		}
	}
	return 0, false
}
