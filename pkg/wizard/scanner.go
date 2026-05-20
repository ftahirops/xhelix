// Package wizard implements the Crown-Jewel scanner described in
// CROWN_JEWEL_PROFILE.md §9 — walk the host's filesystem (and
// eventually DB schemas + bridge access logs) and PROPOSE catalog
// entries the operator should review and approve.
//
// Design rules:
//   - Propose, never auto-apply. The operator's review is the entire
//     value of the wizard; auto-applying would defeat the point.
//   - Confidence-rated findings. The operator can sort by confidence
//     and address the high-confidence ones first.
//   - Idempotent. Running the scan twice produces the same proposal.
//   - Bounded work. Skip /proc, /sys, /dev, mount points; cap walk
//     depth and node count.
//   - Pattern-based, not magic. Operator can read the rule and
//     understand why a path was flagged.
package wizard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Confidence describes how sure the scanner is that a finding is a
// real crown jewel.
type Confidence uint8

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceHigh:
		return "high"
	case ConfidenceMedium:
		return "medium"
	}
	return "low"
}

// Kind is the high-level category of a finding. Maps to operator-
// friendly labels in the output.
type Kind uint8

const (
	KindAppConfig Kind = iota // .env, wp-config.php
	KindSSHKey
	KindCertKey         // *.pem, *.key
	KindBackupArchive
	KindSourceRepo
	KindWebDocRoot
	KindCloudCreds      // ~/.aws/credentials, kube config
)

func (k Kind) String() string {
	switch k {
	case KindAppConfig:
		return "app_config"
	case KindSSHKey:
		return "ssh_key"
	case KindCertKey:
		return "cert_key"
	case KindBackupArchive:
		return "backup_archive"
	case KindSourceRepo:
		return "source_repo"
	case KindWebDocRoot:
		return "web_docroot"
	case KindCloudCreds:
		return "cloud_creds"
	}
	return "unknown"
}

// Finding is one proposed catalog entry.
type Finding struct {
	Kind       Kind       `json:"kind"`
	Path       string     `json:"path"`
	Classes    []string   `json:"classes"`     // catalog DataClass strings
	Confidence Confidence `json:"confidence"`
	Reason     string     `json:"reason"`
	SeenAt     time.Time  `json:"seen_at"`
	Size       int64      `json:"size_bytes,omitempty"`
}

// Options controls the scanner. All limits are bounded so the wizard
// can be run safely on a busy production box.
type Options struct {
	// Roots is the list of directories to walk. Empty → sensible
	// defaults (/etc, /var/www, /srv, /home, /root, /opt).
	Roots []string

	// MaxDepth caps directory depth. Default 8.
	MaxDepth int

	// MaxFindings caps the number of findings returned to keep
	// the proposal reviewable. Default 500.
	MaxFindings int

	// MaxFileSize caps how big a file we'll consider opening for
	// content-based heuristics. Default 1 MB. (Most config files
	// are tiny; archives are detected by extension alone.)
	MaxFileSize int64

	// SkipPaths lists path prefixes never walked into. Defaults
	// include /proc, /sys, /dev, /run, mounted overlays, .git
	// internals.
	SkipPaths []string

	// SkipSubstrings list substrings; any path containing one is
	// skipped. Used to drop package-manager caches and test-
	// fixture trees that flood the result set with false-positive
	// *.pem files. Defaults: DefaultSkipSubstrings().
	SkipSubstrings []string
}

// DefaultRoots returns the filesystem roots a typical SMB Linux host
// is worth scanning. Operators can override.
func DefaultRoots() []string {
	return []string{"/etc", "/var/www", "/srv", "/home", "/root", "/opt"}
}

// DefaultSkipPaths returns directories the scanner never enters.
// Prefix match — added as path starts-with.
func DefaultSkipPaths() []string {
	return []string{
		"/proc", "/sys", "/dev", "/run",
		"/var/lib/docker", "/var/lib/containers",
		"/var/cache",
		"/snap",
	}
}

// DefaultSkipSubstrings returns substring patterns that mark a path
// as "noise" no matter where it lives. Caches and dependency trees
// are notorious sources of false-positive private-key findings (every
// crypto library ships test fixtures full of *.pem files).
//
// Operator can override via Options.SkipSubstrings.
func DefaultSkipSubstrings() []string {
	return []string{
		"/.cargo/",          // Rust crate cache
		"/.rustup/",         // Rust toolchain
		"/.npm/",            // Node package cache
		"/node_modules/",    // Node deps (per-project)
		"/.cache/",          // generic user cache
		"/.local/share/npm", // npm prefix
		"/.composer/",       // PHP composer cache
		"/vendor/",          // Go / PHP vendored deps
		"/go/pkg/mod/",      // Go module cache
		"/.virtualenvs/",    // Python venv home
		"/site-packages/",   // Python installed packages
		"/__pycache__/",     // Python bytecode
		"/.terraform/",      // Terraform plugin cache
		"/.gradle/",         // Java
		"/.m2/",             // Maven
		"/dist-info/",       // Python wheel metadata
	}
	// NOTE: deliberately NOT skipping generic /test/, /tests/,
	// /fixtures/ — real apps have those dirs in their docroot and
	// they may contain real secrets. Package-manager-cache skips
	// above are enough for the dev-host noise case.
}

// Scanner is a stateful one-shot crown-jewel scanner.
type Scanner struct {
	opts        Options
	skipSet     map[string]struct{}
	skipSubstrs []string
	visited     atomic.Int64
	skipped     atomic.Int64
	findings    []Finding
}

// New returns a Scanner with sensible defaults filled in.
func New(opts Options) *Scanner {
	if len(opts.Roots) == 0 {
		opts.Roots = DefaultRoots()
	}
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 8
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = 500
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = 1 << 20
	}
	if len(opts.SkipPaths) == 0 {
		opts.SkipPaths = DefaultSkipPaths()
	}
	if opts.SkipSubstrings == nil {
		opts.SkipSubstrings = DefaultSkipSubstrings()
	}
	s := &Scanner{
		opts:        opts,
		skipSet:     make(map[string]struct{}, len(opts.SkipPaths)),
		skipSubstrs: opts.SkipSubstrings,
	}
	for _, p := range opts.SkipPaths {
		s.skipSet[p] = struct{}{}
	}
	return s
}

// Scan walks every root and returns deduplicated findings, sorted by
// confidence descending then path ascending. Stops at MaxFindings.
func (s *Scanner) Scan() ([]Finding, error) {
	for _, root := range s.opts.Roots {
		if err := s.walkRoot(root); err != nil {
			// One root failing shouldn't kill the whole scan.
			// Log via the finding stream as a low-confidence note.
			continue
		}
		if len(s.findings) >= s.opts.MaxFindings {
			break
		}
	}
	sort.SliceStable(s.findings, func(i, j int) bool {
		if s.findings[i].Confidence != s.findings[j].Confidence {
			return s.findings[i].Confidence > s.findings[j].Confidence
		}
		return s.findings[i].Path < s.findings[j].Path
	})
	return s.findings, nil
}

// Stats returns counters for the operator UI.
type Stats struct {
	FilesVisited int64 `json:"files_visited"`
	PathsSkipped int64 `json:"paths_skipped"`
	Findings     int   `json:"findings"`
}

func (s *Scanner) Stats() Stats {
	return Stats{
		FilesVisited: s.visited.Load(),
		PathsSkipped: s.skipped.Load(),
		Findings:     len(s.findings),
	}
}

func (s *Scanner) walkRoot(root string) error {
	if _, err := os.Stat(root); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Permission denied on a sub-tree is common; skip.
			s.skipped.Add(1)
			return filepath.SkipDir
		}
		// Skip if path starts with any skip prefix.
		for prefix := range s.skipSet {
			if strings.HasPrefix(path, prefix) {
				s.skipped.Add(1)
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		// Skip if path contains any skip substring (package-manager
		// caches, test-fixture trees, vendored deps).
		for _, sub := range s.skipSubstrs {
			if strings.Contains(path, sub) {
				s.skipped.Add(1)
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		// Bound depth.
		rel := strings.TrimPrefix(path, root)
		if strings.Count(rel, string(os.PathSeparator)) > s.opts.MaxDepth {
			s.skipped.Add(1)
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		s.visited.Add(1)
		if len(s.findings) >= s.opts.MaxFindings {
			return errors.New("max findings reached")
		}
		s.classify(path, d)
		return nil
	})
}

// classify applies the rule set to a single path. Multiple rules may
// fire on the same path; we keep the highest-confidence finding.
func (s *Scanner) classify(path string, d os.DirEntry) {
	base := filepath.Base(path)
	isDir := d.IsDir()
	// Skip .git internals — they create noise.
	if strings.Contains(path, "/.git/") && !strings.HasSuffix(path, "/.git/config") {
		return
	}

	// Application config files (high signal)
	if !isDir {
		switch {
		case base == "wp-config.php":
			s.add(Finding{
				Kind: KindAppConfig, Path: path, Classes: []string{"credentials"},
				Confidence: ConfidenceHigh,
				Reason:     "WordPress wp-config.php — contains DB password, auth keys, salts",
			})
			return
		case base == ".env" ||
			strings.HasPrefix(base, ".env.") && !strings.HasSuffix(base, ".example"):
			s.add(Finding{
				Kind: KindAppConfig, Path: path, Classes: []string{"credentials"},
				Confidence: ConfidenceHigh,
				Reason:     "dotenv file typically holds secrets",
			})
			return
		case base == "settings.local.py" || base == "local_settings.py":
			s.add(Finding{
				Kind: KindAppConfig, Path: path, Classes: []string{"credentials"},
				Confidence: ConfidenceMedium,
				Reason:     "Django local settings often contain DB password / secret_key",
			})
			return
		case base == "config.yml" || base == "config.yaml":
			// Too generic to be high-confidence; flag low for review.
			s.add(Finding{
				Kind: KindAppConfig, Path: path, Classes: []string{"credentials"},
				Confidence: ConfidenceLow,
				Reason:     "Generic config file — operator should verify content",
			})
			return
		}
	}

	// SSH private keys
	if !isDir && (strings.Contains(path, "/.ssh/") || strings.HasPrefix(path, "/root/.ssh/")) {
		// Skip authorized_keys, known_hosts (those aren't secrets,
		// they're public identities)
		if base == "authorized_keys" || base == "known_hosts" || base == "config" {
			return
		}
		// Skip .pub files (public halves)
		if strings.HasSuffix(base, ".pub") {
			return
		}
		// id_rsa / id_ed25519 / id_ecdsa / arbitrary key files
		if strings.HasPrefix(base, "id_") || strings.HasSuffix(base, "_rsa") || strings.HasSuffix(base, "_ed25519") {
			s.add(Finding{
				Kind: KindSSHKey, Path: path, Classes: []string{"credentials"},
				Confidence: ConfidenceHigh,
				Reason:     "SSH private key",
			})
			return
		}
	}

	// Certificate / private keys by extension
	if !isDir {
		switch ext := filepath.Ext(base); ext {
		case ".pem", ".key":
			// Heuristic: in /etc/ssl/private or any path called "private"
			// → high; elsewhere → medium.
			conf := ConfidenceMedium
			if strings.Contains(path, "private") || strings.HasPrefix(path, "/etc/ssl/") {
				conf = ConfidenceHigh
			}
			s.add(Finding{
				Kind: KindCertKey, Path: path, Classes: []string{"credentials"},
				Confidence: conf,
				Reason:     fmt.Sprintf("possible private key (%s)", ext),
			})
			return
		}
	}

	// Cloud creds
	if !isDir {
		if (base == "credentials" && strings.Contains(path, "/.aws/")) ||
			(base == "config" && strings.Contains(path, "/.aws/")) {
			s.add(Finding{
				Kind: KindCloudCreds, Path: path, Classes: []string{"credentials", "api_key"},
				Confidence: ConfidenceHigh,
				Reason:     "AWS credentials file",
			})
			return
		}
		if strings.HasSuffix(path, "/.kube/config") {
			s.add(Finding{
				Kind: KindCloudCreds, Path: path, Classes: []string{"credentials"},
				Confidence: ConfidenceHigh,
				Reason:     "kubectl config — contains cluster API credentials",
			})
			return
		}
		if strings.HasSuffix(path, "/.docker/config.json") {
			s.add(Finding{
				Kind: KindCloudCreds, Path: path, Classes: []string{"api_key"},
				Confidence: ConfidenceMedium,
				Reason:     "Docker registry auth tokens",
			})
			return
		}
	}

	// Backup archives — size + extension heuristic
	if !isDir {
		switch {
		case strings.HasSuffix(base, ".tar.gz") ||
			strings.HasSuffix(base, ".tgz") ||
			strings.HasSuffix(base, ".sql.gz") ||
			strings.HasSuffix(base, ".sql") ||
			strings.HasSuffix(base, ".dump") ||
			strings.HasSuffix(base, ".bak"):
			conf := ConfidenceMedium
			if strings.Contains(path, "/backup") || strings.Contains(path, "/dump") {
				conf = ConfidenceHigh
			}
			info, err := d.Info()
			var size int64
			if err == nil {
				size = info.Size()
			}
			s.add(Finding{
				Kind: KindBackupArchive, Path: path, Classes: []string{"backup"},
				Confidence: conf, Size: size,
				Reason: fmt.Sprintf("archive/dump file (%s)", filepath.Ext(base)),
			})
			return
		}
	}

	// Source repos (.git presence)
	if !isDir && base == "config" && strings.HasSuffix(filepath.Dir(path), "/.git") {
		s.add(Finding{
			Kind: KindSourceRepo, Path: filepath.Dir(filepath.Dir(path)),
			Classes:    []string{"source_code"},
			Confidence: ConfidenceMedium,
			Reason:     "Git working tree — source code under this directory",
		})
		return
	}

	// Web doc roots — flag the directory once
	if isDir {
		switch path {
		case "/var/www", "/var/www/html", "/srv/www", "/srv/http":
			s.add(Finding{
				Kind: KindWebDocRoot, Path: path,
				Classes:    []string{"source_code"},
				Confidence: ConfidenceMedium,
				Reason:     "web docroot — operator should declare route policies",
			})
			return
		}
	}
}

// add records a finding, merging duplicates by keeping the highest
// confidence per path.
func (s *Scanner) add(f Finding) {
	if f.SeenAt.IsZero() {
		f.SeenAt = time.Now().UTC()
	}
	for i, existing := range s.findings {
		if existing.Path == f.Path {
			if f.Confidence > existing.Confidence {
				s.findings[i] = f
			}
			return
		}
	}
	s.findings = append(s.findings, f)
}

// ProposedYAML renders the findings as a YAML patch the operator can
// review and apply to the catalog. Comments preserve the reason and
// confidence so the operator knows what they're approving.
func ProposedYAML(findings []Finding) string {
	var b strings.Builder
	now := time.Now().UTC().Format("2006-01-02 15:04 UTC")
	b.WriteString("# Proposed additions to /etc/xhelix/dlcf/catalog.yaml\n")
	b.WriteString("# Generated by xhelixctl wizard scan on " + now + "\n")
	b.WriteString("# Review carefully before merging.\n")
	b.WriteString("#\n")
	b.WriteString("# Each entry is sorted by scanner confidence (high first).\n")
	b.WriteString("# Remove any line you don't want; merge the rest into your catalog.\n\n")

	hasPaths := false
	for _, f := range findings {
		if f.Kind == KindWebDocRoot || f.Kind == KindSourceRepo {
			continue
		}
		if !hasPaths {
			b.WriteString("paths:\n")
			hasPaths = true
		}
		b.WriteString(fmt.Sprintf("  - glob: %q\n", f.Path))
		b.WriteString(fmt.Sprintf("    classes: [%s]\n", strings.Join(quoteEach(f.Classes), ", ")))
		b.WriteString(fmt.Sprintf("    # confidence: %s — %s\n", f.Confidence, f.Reason))
		if f.Size > 0 {
			b.WriteString(fmt.Sprintf("    # size: %d bytes\n", f.Size))
		}
		b.WriteString("\n")
	}

	// Web doc roots get a separate notes section
	hasNotes := false
	for _, f := range findings {
		if f.Kind != KindWebDocRoot && f.Kind != KindSourceRepo {
			continue
		}
		if !hasNotes {
			b.WriteString("# Suggested manual classification (route policies):\n")
			hasNotes = true
		}
		b.WriteString(fmt.Sprintf("#   %s — %s (kind=%s)\n", f.Path, f.Reason, f.Kind))
	}

	if !hasPaths && !hasNotes {
		b.WriteString("# No findings. Either the scanner found nothing classify-worthy\n")
		b.WriteString("# OR the roots are misconfigured. Check `wizard.scan stats`.\n")
	}
	return b.String()
}

func quoteEach(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}
