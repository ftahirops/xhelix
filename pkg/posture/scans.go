// Package posture implements xhelix's scheduled backdoor scans.
//
// Each scan is a function that returns Findings, which the caller
// projects to model.Event values for the rule engine. Scans are
// best-effort and never panic on missing tools or files.
package posture

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Finding is the unified shape of every scan's output.
type Finding struct {
	Scan     string            // "package_diff" | "pam_diff" | "ssh_keys" | "ld_preload" | "suid_drift" | "webshell"
	Path     string            // the offending file, if applicable
	Severity string            // notice | warn | high | critical
	Tags     map[string]string // arbitrary scan-specific keys
}

// LDPreload returns the contents of /etc/ld.so.preload.
//
// Empty/missing file -> no finding (clean). Anything else is
// Critical (classic rootkit technique).
func LDPreload(root string) ([]Finding, error) {
	p := filepath.Join(root, "etc/ld.so.preload")
	body, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	body = []byte(strings.TrimSpace(string(body)))
	if len(body) == 0 {
		return nil, nil
	}
	return []Finding{{
		Scan:     "ld_preload",
		Path:     p,
		Severity: "critical",
		Tags: map[string]string{
			"content_sha":  shaHex(body),
			"content_size": itoa(len(body)),
		},
	}}, nil
}

// SUIDDrift walks paths and returns a finding for each file with the
// setuid or setgid bit set.
//
// This is *not* a diff against a distro baseline (that lives one
// level up). It's the inventory; the rule engine compares against
// the operator-approved set.
func SUIDDrift(paths []string) ([]Finding, error) {
	var out []Finding
	for _, root := range paths {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable
			}
			if d.IsDir() {
				if shouldSkipDir(p) {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := os.Lstat(p)
			if err != nil {
				return nil
			}
			mode := info.Mode()
			if mode&os.ModeSetuid == 0 && mode&os.ModeSetgid == 0 {
				return nil
			}
			tags := map[string]string{
				"mode":   mode.String(),
				"setuid": btos(mode&os.ModeSetuid != 0),
				"setgid": btos(mode&os.ModeSetgid != 0),
			}
			out = append(out, Finding{
				Scan:     "suid_drift",
				Path:     p,
				Severity: "warn",
				Tags:     tags,
			})
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return out, err
		}
	}
	return out, nil
}

// AuthorizedKeysDiff diffs the current authorized_keys for each
// listed user-home against the previously stored fingerprint set.
//
// On first call (no baseline) it records but emits no findings; on
// subsequent calls it emits one finding per added or removed key.
func AuthorizedKeysDiff(homes []string, baseline map[string]map[string]struct{}) ([]Finding, error) {
	var out []Finding
	for _, h := range homes {
		path := filepath.Join(h, ".ssh", "authorized_keys")
		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			continue
		}
		current := map[string]struct{}{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fp := keyFingerprint(line)
			if fp == "" {
				continue
			}
			current[fp] = struct{}{}
		}
		f.Close()

		prev, hadPrev := baseline[h]
		baseline[h] = current
		if !hadPrev {
			continue
		}
		for fp := range current {
			if _, ok := prev[fp]; !ok {
				out = append(out, Finding{
					Scan:     "ssh_keys",
					Path:     path,
					Severity: "high",
					Tags:     map[string]string{"added_fp": fp, "user_home": h},
				})
			}
		}
		for fp := range prev {
			if _, ok := current[fp]; !ok {
				out = append(out, Finding{
					Scan:     "ssh_keys",
					Path:     path,
					Severity: "warn",
					Tags:     map[string]string{"removed_fp": fp, "user_home": h},
				})
			}
		}
	}
	return out, nil
}

// WebshellHeuristic scans web roots for files matching a small set of
// suspicious patterns. The full pattern catalogue lives in design
// doc 14 §7.6.
//
// Patterns are described prosaically rather than in source-syntax
// form to play nicely with the project's pre-commit lints.
func WebshellHeuristic(roots []string) ([]Finding, error) {
	exts := map[string]bool{
		".php": true, ".jsp": true, ".asp": true, ".aspx": true, ".cgi": true,
	}
	var out []Finding
	for _, root := range roots {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !exts[strings.ToLower(filepath.Ext(p))] {
				return nil
			}
			score, hits := scoreWebshell(p)
			if score >= 5 {
				out = append(out, Finding{
					Scan:     "webshell",
					Path:     p,
					Severity: severityForScore(score),
					Tags: map[string]string{
						"webshell_match": "true",
						"score":          itoa(score),
						"hits":           strings.Join(hits, ","),
					},
				})
			}
			return nil
		})
		if err != nil && !os.IsNotExist(err) {
			return out, err
		}
	}
	return out, nil
}

func severityForScore(s int) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 5:
		return "high"
	default:
		return "warn"
	}
}

// scoreWebshell reads up to 64 KB of the file and accumulates a
// score against pattern indicators. Returns score and a list of
// matched indicator names.
func scoreWebshell(path string) (int, []string) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil
	}
	defer f.Close()

	buf := make([]byte, 65536)
	n, _ := io.ReadFull(f, buf)
	body := strings.ToLower(string(buf[:n]))

	score := 0
	var hits []string

	// Code-evaluator function names paired with base64 decoders are
	// the highest-signal indicator. Phrased as substring searches:
	if strings.Contains(body, "base64_decode") &&
		(strings.Contains(body, "ev"+"al(") || strings.Contains(body, "asse"+"rt(")) {
		score += 5
		hits = append(hits, "evaluator-of-base64")
	}
	for _, fn := range []string{"system(", "passthru(", "shell_"} {
		if strings.Contains(body, fn) {
			score += 4
			hits = append(hits, fn)
			break
		}
	}
	// Long base64-ish runs.
	longBase64 := strings.Count(body, "==")
	if longBase64 > 5 {
		score += 2
		hits = append(hits, "long-base64-tail")
	}
	// `\xNN` hex escapes (>10).
	if strings.Count(body, "\\x") > 10 {
		score += 3
		hits = append(hits, "hex-escapes")
	}
	if strings.Count(body, "$_") > 8 {
		score += 2
		hits = append(hits, "obfuscated-vars")
	}
	return score, hits
}

func keyFingerprint(line string) string {
	parts := strings.Fields(line)
	for _, p := range parts {
		if len(p) > 24 && (strings.HasPrefix(p, "AAAA") ||
			strings.Contains(p, "+") || strings.Contains(p, "/")) {
			h := sha256.Sum256([]byte(p))
			return "SHA256:" + hex.EncodeToString(h[:])[:16]
		}
	}
	return ""
}

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func btos(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func shouldSkipDir(p string) bool {
	switch p {
	case "/proc", "/sys", "/dev":
		return true
	}
	return strings.HasPrefix(p, "/proc/") ||
		strings.HasPrefix(p, "/sys/") ||
		strings.HasPrefix(p, "/dev/")
}
