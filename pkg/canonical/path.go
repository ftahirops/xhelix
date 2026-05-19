package canonical

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// PathID identifies a filesystem object by its stable inode + device
// pair. Two PathID values are equal iff they refer to the same file
// (modulo bind mounts), independent of which symlink path was used.
type PathID struct {
	Path   string // canonical, symlink-resolved absolute path
	Inode  uint64
	Device uint64 // st_dev
}

// IsValid returns true when the PathID identifies a real object.
func (p PathID) IsValid() bool {
	return p.Path != "" && p.Inode != 0
}

// Equal returns true when two PathIDs refer to the same object.
// Compares by (inode, device); the textual path is informational.
func (p PathID) Equal(other PathID) bool {
	return p.Inode == other.Inode && p.Device == other.Device
}

// String renders as "path#device:inode" for logs.
func (p PathID) String() string {
	return fmt.Sprintf("%s#%d:%d", p.Path, p.Device, p.Inode)
}

// CanonicalPath resolves every symlink in p and returns the
// canonical PathID. The returned Path is absolute. If p does not
// exist, returns PathNotFound; any other I/O error is wrapped.
//
// Behaviour for special files:
//   - regular files, directories, FIFOs → as expected
//   - /proc/<pid>/exe → resolves to the real binary path
//   - dangling symlinks → PathNotFound
func CanonicalPath(p string) (PathID, error) {
	if p == "" {
		return PathID{}, fmt.Errorf("canonical: empty path")
	}
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		if os.IsNotExist(err) {
			return PathID{}, PathNotFound{Path: p}
		}
		return PathID{}, fmt.Errorf("canonical: evalsymlinks %q: %w", p, err)
	}
	abs, err := filepath.Abs(real)
	if err != nil {
		return PathID{}, fmt.Errorf("canonical: abs %q: %w", real, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return PathID{}, PathNotFound{Path: p}
		}
		return PathID{}, fmt.Errorf("canonical: stat %q: %w", abs, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Non-unix runtime — fall back to text-only identity.
		return PathID{Path: abs}, nil
	}
	return PathID{
		Path:   abs,
		Inode:  stat.Ino,
		Device: stat.Dev,
	}, nil
}

// PathNotFound indicates the path doesn't exist or resolves to a
// missing target.
type PathNotFound struct {
	Path string
}

func (e PathNotFound) Error() string {
	return fmt.Sprintf("canonical: path %q not found", e.Path)
}

// ProcExePath returns the canonical PathID of the binary backing
// the given pid. Equivalent to CanonicalPath("/proc/<pid>/exe").
func ProcExePath(pid uint32) (PathID, error) {
	return CanonicalPath(fmt.Sprintf("/proc/%d/exe", pid))
}
