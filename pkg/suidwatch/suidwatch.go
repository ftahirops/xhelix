// Package suidwatch inventories every SUID / SGID binary under
// the canonical system paths and reports drift against a baseline.
//
// New SUID binaries appearing post-deployment is a top-tier privesc
// signal — backdoors love this surface because once a binary has
// setuid root, any user-context shell exec gets root for free.
//
// The package is pure-Go and mirrors pkg/persistencewatch's diff
// shape so wiring into the existing dispatch is symmetric.
package suidwatch

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// Entry is one SUID/SGID binary at a point in time.
type Entry struct {
	Path     string
	Mode     uint32   // unix mode bits, including setuid/setgid
	UID      uint32   // file owner uid
	GID      uint32   // file owner gid
	Size     int64
	SHA256   string   // hex; empty when file unhashable or > MaxFileSize
	HasSUID  bool
	HasSGID  bool
}

// Snapshot is the full inventory.
type Snapshot struct {
	Entries []Entry
}

// Diff lists changes between two Snapshots.
type Diff struct {
	Added    []Entry
	Removed  []Entry
	Modified []Modified
}

// Modified pairs old + new for a path whose content changed.
type Modified struct {
	Old, New Entry
}

// IsEmpty reports whether the diff is fully empty.
func (d Diff) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Modified) == 0
}

// Compare returns the change set.
func Compare(base, cur Snapshot) Diff {
	bm := indexByPath(base)
	cm := indexByPath(cur)

	var d Diff
	for _, c := range cur.Entries {
		b, ok := bm[c.Path]
		if !ok {
			d.Added = append(d.Added, c)
			continue
		}
		if differs(b, c) {
			d.Modified = append(d.Modified, Modified{Old: b, New: c})
		}
	}
	for _, b := range base.Entries {
		if _, ok := cm[b.Path]; !ok {
			d.Removed = append(d.Removed, b)
		}
	}
	sortEntries(d.Added)
	sortEntries(d.Removed)
	sort.Slice(d.Modified, func(i, j int) bool {
		return d.Modified[i].New.Path < d.Modified[j].New.Path
	})
	return d
}

// WalkConfig configures the inventory walker.
type WalkConfig struct {
	// Roots is the list of root directories to scan. Default:
	// /usr, /bin, /sbin, /opt.
	Roots []string

	// MaxFileSize bounds the SHA-256 hash size. <=0 = 16MB.
	MaxFileSize int64

	// FollowSymlinks: if false (default), symlinks to SUID binaries
	// are reported by symlink path with no content hash. SUID bit
	// on a symlink doesn't apply per POSIX so we don't follow.
	FollowSymlinks bool
}

// Default scan roots.
var DefaultRoots = []string{"/usr", "/bin", "/sbin", "/opt"}

// Walk produces a Snapshot.
func Walk(cfg WalkConfig) (Snapshot, error) {
	roots := cfg.Roots
	if len(roots) == 0 {
		roots = DefaultRoots
	}
	maxSize := cfg.MaxFileSize
	if maxSize <= 0 {
		maxSize = 16 * 1024 * 1024
	}

	var entries []Entry
	for _, r := range roots {
		_ = filepath.WalkDir(r, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			suid := mode&os.ModeSetuid != 0
			sgid := mode&os.ModeSetgid != 0
			if !suid && !sgid {
				return nil
			}
			if mode&os.ModeSymlink != 0 && !cfg.FollowSymlinks {
				entries = append(entries, Entry{
					Path:    path,
					Mode:    uint32(mode.Perm() | mode&(os.ModeSetuid|os.ModeSetgid)),
					HasSUID: suid, HasSGID: sgid,
				})
				return nil
			}
			e := Entry{
				Path:    path,
				Mode:    uint32(mode.Perm() | mode&(os.ModeSetuid|os.ModeSetgid)),
				Size:    info.Size(),
				HasSUID: suid,
				HasSGID: sgid,
			}
			if st, ok := info.Sys().(interface {
				// avoid syscall.Stat_t direct dep for non-Linux builds
				// keep cross-platform: only Linux supplies these
			}); ok {
				_ = st
			}
			// Linux-specific uid/gid via syscall.Stat_t (build-tagged
			// version would split, but Go stdlib gives us Mode bits
			// portably; uid/gid pulled below if Stat_t present).
			fillOwnerLinux(&e, info)
			if info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= maxSize {
				if h := hashFile(path); h != "" {
					e.SHA256 = h
				}
			}
			entries = append(entries, e)
			return nil
		})
	}
	return Snapshot{Entries: entries}, nil
}

func indexByPath(s Snapshot) map[string]Entry {
	out := make(map[string]Entry, len(s.Entries))
	for _, e := range s.Entries {
		out[e.Path] = e
	}
	return out
}

func differs(a, b Entry) bool {
	if a.SHA256 != "" && b.SHA256 != "" {
		return a.SHA256 != b.SHA256
	}
	return a.Size != b.Size || a.Mode != b.Mode || a.UID != b.UID
}

func sortEntries(e []Entry) {
	sort.Slice(e, func(i, j int) bool { return e[i].Path < e[j].Path })
}

func hashFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
