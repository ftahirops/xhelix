package persistencewatch

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// WalkConfig configures the FS snapshotter.
type WalkConfig struct {
	// Root is the filesystem root to walk. Defaults to "/".
	// Tests inject a tmpdir.
	Root string

	// MaxFileSize bounds how many bytes to SHA-256 per file.
	// Anything larger gets size+mode but no hash. <=0 selects 4MB.
	MaxFileSize int64

	// IncludeUserHomes — if true, walk /home/*/<patterns> and /root.
	// Default true.
	IncludeUserHomes bool

	// Now is the time function (set in tests).
	Now func() int64

	// extraPaths is appended onto the default scan set. Useful in
	// tests or for operator-supplied custom paths.
	ExtraPaths []string
}

// defaultScanPaths is the curated set of single-file or directory
// roots that contain persistence artifacts. Directories are
// walked one level deep (the typical layout for
// /etc/cron.d, /etc/systemd/system, etc.).
var defaultScanPaths = []string{
	// Crontabs
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.monthly",
	"/etc/cron.weekly",
	"/var/spool/cron/crontabs",
	"/var/spool/cron",
	"/var/spool/at",
	// systemd
	"/etc/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
	// Shell init
	"/etc/profile",
	"/etc/profile.d",
	"/etc/bash.bashrc",
	"/etc/zsh/zshrc",
	// rc.local + init.d
	"/etc/rc.local",
	"/etc/init.d",
	// Kernel modules
	"/etc/modules",
	"/etc/modules-load.d",
	// Loader preload
	"/etc/ld.so.preload",
	"/etc/ld.so.conf.d",
	// XDG autostart
	"/etc/xdg/autostart",
	// PAM
	"/etc/pam.d",
	"/lib/security",
	"/usr/lib/security",
}

// userHomeSubpaths are patterns scanned for each home directory.
var userHomeSubpaths = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
	".profile",
	".zshrc", ".zprofile", ".zshenv", ".zlogin",
	".ssh/authorized_keys", ".ssh/authorized_keys2",
}

var userHomeDirs = []string{
	".config/autostart",
	".config/systemd/user",
}

// Walk takes a snapshot of every persistence-mechanism artifact
// under cfg.Root. Returns the Snapshot ready to feed Compare().
func Walk(cfg WalkConfig) (Snapshot, error) {
	root := cfg.Root
	if root == "" {
		root = "/"
	}
	if root == "/" {
		root = ""
	}
	maxSize := cfg.MaxFileSize
	if maxSize <= 0 {
		maxSize = 4 * 1024 * 1024
	}
	now := cfg.Now
	if now == nil {
		now = func() int64 { return 0 }
	}

	var entries []Entry

	// System paths
	for _, p := range defaultScanPaths {
		collectPath(&entries, joinRoot(root, p), maxSize, cfg.Root != "")
	}
	for _, p := range cfg.ExtraPaths {
		collectPath(&entries, joinRoot(root, p), maxSize, cfg.Root != "")
	}

	// User homes
	if cfg.IncludeUserHomes || (!cfg.IncludeUserHomes && cfg.Root != "") {
		for _, h := range homeRoots(joinRoot(root, "/home"), joinRoot(root, "/root")) {
			for _, sub := range userHomeSubpaths {
				collectPath(&entries, filepath.Join(h, sub), maxSize, cfg.Root != "")
			}
			for _, dir := range userHomeDirs {
				collectPath(&entries, filepath.Join(h, dir), maxSize, cfg.Root != "")
			}
		}
	}

	return Snapshot{TakenAt: now(), Entries: entries}, nil
}

// collectPath adds Entry for p (file) or recursively for p (dir).
// rootIsCustom strips a synthetic root prefix from emitted paths
// so tests using a tmpdir get "/etc/crontab" semantics rather
// than "/tmp/abc.../etc/crontab".
func collectPath(out *[]Entry, p string, maxSize int64, rootIsCustom bool) {
	info, err := os.Lstat(p)
	if err != nil {
		return
	}
	if info.IsDir() {
		// Walk directory tree (depth-unbounded; persistence dirs
		// are flat in practice).
		_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			addFile(out, path, maxSize)
			return nil
		})
		return
	}
	if info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		addFile(out, p, maxSize)
	}
}

func addFile(out *[]Entry, p string, maxSize int64) {
	info, err := os.Lstat(p)
	if err != nil {
		return
	}
	e := Entry{
		Path:     p,
		Category: CategoryForPath(stripWalkerRoot(p)),
		Mode:     uint32(info.Mode().Perm()),
		Size:     info.Size(),
	}
	if e.Category == CategoryUnknown {
		// Skip entries whose path mapping fails (likely outside
		// curated paths after symlink chasing).
		return
	}
	if info.Mode().IsRegular() && info.Size() > 0 && info.Size() <= maxSize {
		if h := hashFile(p); h != "" {
			e.SHA256 = h
		}
	}
	if owner := extractOwnerFromPath(stripWalkerRoot(p)); owner != "" {
		e.Owner = owner
	}
	*out = append(*out, e)
}

// hashFile returns the hex-encoded SHA-256 of the file at p, or "".
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

// extractOwnerFromPath returns the home-directory username for
// /home/<user>/... or "root" for /root/...; "" otherwise.
func extractOwnerFromPath(p string) string {
	if strings.HasPrefix(p, "/root/") || p == "/root" {
		return "root"
	}
	const prefix = "/home/"
	if !strings.HasPrefix(p, prefix) {
		return ""
	}
	rest := p[len(prefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}

// homeRoots enumerates direct subdirectories of /home plus /root
// (if present). Used by Walk to find per-user persistence paths.
func homeRoots(homeBase, rootDir string) []string {
	var out []string
	if entries, err := os.ReadDir(homeBase); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join(homeBase, e.Name()))
			}
		}
	}
	if info, err := os.Lstat(rootDir); err == nil && info.IsDir() {
		out = append(out, rootDir)
	}
	return out
}

func joinRoot(root, p string) string {
	if root == "" || root == "/" {
		return p
	}
	return filepath.Join(root, p)
}

// walkerRoot is a process-global stripping prefix used by tests
// to translate walker-absolute paths back to canonical paths
// before they're fed to CategoryForPath. Set via SetWalkerRoot.
var walkerRoot string

// SetWalkerRoot lets tests redirect the canonical-path
// interpretation to a tmpdir. Production callers leave it "".
func SetWalkerRoot(p string) { walkerRoot = p }

func stripWalkerRoot(p string) string {
	if walkerRoot == "" {
		return p
	}
	if strings.HasPrefix(p, walkerRoot) {
		out := strings.TrimPrefix(p, walkerRoot)
		if out == "" {
			return "/"
		}
		if !strings.HasPrefix(out, "/") {
			out = "/" + out
		}
		return out
	}
	return p
}
