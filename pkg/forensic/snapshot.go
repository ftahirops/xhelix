// Package forensic captures volatile evidence about a process before
// it is killed.
//
// The snapshot is best-effort: any individual file may be unreadable
// (perm, race, kthread) and that is logged but not fatal. The point is
// to preserve as much as possible before SIGKILL turns the process
// into ash.
//
// Files captured per pid:
//
//	status      - /proc/<pid>/status
//	cmdline     - /proc/<pid>/cmdline (NUL-decoded)
//	environ     - /proc/<pid>/environ (NUL-decoded)
//	maps        - /proc/<pid>/maps
//	exe         - copy of /proc/<pid>/exe (the on-disk binary as seen
//	              by the kernel; survives unlink)
//	fd/         - directory listing of /proc/<pid>/fd with readlink targets
//	stack       - /proc/<pid>/stack (kernel stack, requires CAP_SYS_ADMIN)
//	wchan       - /proc/<pid>/wchan
//	syscall     - /proc/<pid>/syscall
//	stat        - /proc/<pid>/stat
//	net.tcp     - /proc/<pid>/net/tcp + tcp6
//	manifest.json - metadata + sha256 of every captured file
package forensic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Snapshotter writes evidence into a per-pid directory under EvidenceDir.
type Snapshotter struct {
	EvidenceDir string
}

// New returns a snapshotter rooted at dir. The directory is created
// with 0700 if missing.
func New(dir string) (*Snapshotter, error) {
	if dir == "" {
		return nil, fmt.Errorf("forensic: empty evidence dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Snapshotter{EvidenceDir: dir}, nil
}

// Manifest is written as manifest.json in each snapshot dir.
type Manifest struct {
	PID       int               `json:"pid"`
	Comm      string            `json:"comm"`
	RuleID    string            `json:"rule_id"`
	CapturedAt time.Time        `json:"captured_at"`
	Files     map[string]string `json:"files"` // name → sha256
	Errors    map[string]string `json:"errors,omitempty"`
}

// Capture writes a snapshot for pid and returns the directory path.
// rule_id is purely metadata for the manifest.
func (s *Snapshotter) Capture(pid int, comm, ruleID string) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("forensic: invalid pid %d", pid)
	}
	ts := time.Now().UTC().Format("20060102T150405Z")
	dir := filepath.Join(s.EvidenceDir, fmt.Sprintf("%s-pid%d-%s", ts, pid, sanitize(comm)))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	mf := Manifest{
		PID:        pid,
		Comm:       comm,
		RuleID:     ruleID,
		CapturedAt: time.Now().UTC(),
		Files:      map[string]string{},
		Errors:     map[string]string{},
	}

	procDir := fmt.Sprintf("/proc/%d", pid)

	// Plain procfs reads
	for _, name := range []string{"status", "cmdline", "environ", "maps",
		"stack", "wchan", "syscall", "stat", "comm", "loginuid", "sessionid"} {
		src := filepath.Join(procDir, name)
		dst := filepath.Join(dir, name)
		if sum, err := copyFile(src, dst); err == nil {
			mf.Files[name] = sum
		} else {
			mf.Errors[name] = err.Error()
		}
	}

	// /proc/<pid>/exe is a magic symlink — open + copy gets the on-disk
	// bytes the kernel mapped, even if the file was unlinked.
	if sum, err := copyFile(filepath.Join(procDir, "exe"), filepath.Join(dir, "exe.bin")); err == nil {
		mf.Files["exe.bin"] = sum
	} else {
		mf.Errors["exe.bin"] = err.Error()
	}

	// Dump /proc/<pid>/fd/* readlink targets
	if fdSum, err := dumpFDs(procDir, dir); err == nil {
		mf.Files["fd.txt"] = fdSum
	} else {
		mf.Errors["fd.txt"] = err.Error()
	}

	// Network sockets: attempt namespace-aware copy
	for _, name := range []string{"net/tcp", "net/tcp6", "net/udp", "net/unix"} {
		src := filepath.Join(procDir, name)
		dst := filepath.Join(dir, strings.ReplaceAll(name, "/", "."))
		if sum, err := copyFile(src, dst); err == nil {
			mf.Files[strings.ReplaceAll(name, "/", ".")] = sum
		} else {
			mf.Errors[name] = err.Error()
		}
	}

	// Write manifest last so its presence signals "snapshot complete".
	mfPath := filepath.Join(dir, "manifest.json")
	if data, err := json.MarshalIndent(mf, "", "  "); err == nil {
		_ = os.WriteFile(mfPath, data, 0o600)
	}
	return dir, nil
}

func copyFile(src, dst string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, h), in); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func dumpFDs(procDir, outDir string) (string, error) {
	entries, err := os.ReadDir(filepath.Join(procDir, "fd"))
	if err != nil {
		return "", err
	}
	out, err := os.OpenFile(filepath.Join(outDir, "fd.txt"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer out.Close()
	h := sha256.New()
	w := io.MultiWriter(out, h)
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(procDir, "fd", e.Name()))
		if err != nil {
			fmt.Fprintf(w, "%s\t<readlink err: %v>\n", e.Name(), err)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\n", e.Name(), target)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sanitize(s string) string {
	if s == "" {
		return "unknown"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && i < 32; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}
