package canonical

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// NamespaceSet captures the kernel namespace inodes a process is in.
// Two processes in the same set of namespaces share that kernel
// boundary; a difference means a namespace transition happened.
//
// On older kernels some entries may be 0 if the namespace type is
// not supported.
type NamespaceSet struct {
	PID    uint64 // pid namespace inode
	Mount  uint64 // mount namespace inode
	Net    uint64 // network namespace inode
	User   uint64 // user namespace inode
	UTS    uint64 // UTS namespace inode
	IPC    uint64 // IPC namespace inode
	Cgroup uint64 // cgroup namespace inode
	Time   uint64 // time namespace inode (kernel ≥ 5.6)
}

// IsValid returns true when at least PID + Mount + Net are populated.
// Those are the three xhelix actually needs for container detection.
func (n NamespaceSet) IsValid() bool {
	return n.PID != 0 && n.Mount != 0 && n.Net != 0
}

// Equal returns true when both sets carry identical inodes across
// every namespace type.
func (n NamespaceSet) Equal(other NamespaceSet) bool {
	return n.PID == other.PID &&
		n.Mount == other.Mount &&
		n.Net == other.Net &&
		n.User == other.User &&
		n.UTS == other.UTS &&
		n.IPC == other.IPC &&
		n.Cgroup == other.Cgroup &&
		n.Time == other.Time
}

// SharesPIDNS returns true when both processes are in the same PID
// namespace — a quick container-boundary check.
func (n NamespaceSet) SharesPIDNS(other NamespaceSet) bool {
	return n.PID != 0 && n.PID == other.PID
}

// ReadNamespaces returns the namespace inodes for the given pid.
// Missing namespace types are returned as 0 (older kernels). Returns
// ProcKeyNotFound if the process has exited.
func ReadNamespaces(pid uint32) (NamespaceSet, error) {
	if pid == 0 {
		return NamespaceSet{}, fmt.Errorf("canonical: pid 0")
	}
	var set NamespaceSet
	// /proc/<pid>/ns/<type> is a symlink whose readlink looks like:
	//   "pid:[4026531836]"
	// We need the inode in brackets. os.Stat on the link target
	// returns the kernel's namespace inode (st_ino).
	pairs := []struct {
		nsName string
		dest   *uint64
	}{
		{"pid", &set.PID},
		{"mnt", &set.Mount},
		{"net", &set.Net},
		{"user", &set.User},
		{"uts", &set.UTS},
		{"ipc", &set.IPC},
		{"cgroup", &set.Cgroup},
		{"time", &set.Time},
	}
	for _, p := range pairs {
		ino, err := readNsInode(pid, p.nsName)
		if err != nil {
			// Missing ns types on older kernels are okay; bail only on
			// a complete process-gone scenario.
			if _, ok := err.(ProcKeyNotFound); ok {
				return NamespaceSet{}, err
			}
			continue
		}
		*p.dest = ino
	}
	return set, nil
}

func readNsInode(pid uint32, ns string) (uint64, error) {
	link := fmt.Sprintf("/proc/%d/ns/%s", pid, ns)
	// Stat (not lstat) follows the symlink into the namespace, and
	// the resulting st_ino is the namespace identifier.
	var stat syscall.Stat_t
	if err := syscall.Stat(link, &stat); err != nil {
		// On a missing PID, the parent /proc/<pid> goes away — distinguish.
		if _, errProc := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(errProc) {
			return 0, ProcKeyNotFound{PID: pid}
		}
		return 0, fmt.Errorf("canonical: stat %s: %w", link, err)
	}
	return stat.Ino, nil
}

// parseNsLinkTarget parses readlink output like "pid:[4026531836]"
// and returns the inode. Exposed for direct testing.
func parseNsLinkTarget(target string) (uint64, error) {
	open := strings.IndexByte(target, '[')
	close := strings.IndexByte(target, ']')
	if open < 0 || close < 0 || close <= open+1 {
		return 0, fmt.Errorf("canonical: malformed ns link %q", target)
	}
	return strconv.ParseUint(target[open+1:close], 10, 64)
}
