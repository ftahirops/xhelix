//go:build linux

package apparmor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// DefaultProfileDir is the canonical apparmor.d location.
const DefaultProfileDir = "/etc/apparmor.d"

// Install writes the profile to disk and loads it via apparmor_parser.
//
// Returns:
//   - filesystem error if the write fails
//   - exec error if apparmor_parser isn't found or rejects the profile
//
// dryRun=true writes the file but does NOT call apparmor_parser —
// useful for letting an operator review before live load.
func (p Profile) Install(dir string, dryRun bool) (Profile, error) {
	if dir == "" {
		dir = DefaultProfileDir
	}
	if p.Body == "" {
		return p, fmt.Errorf("apparmor: empty profile body")
	}
	if p.Name == "" {
		return p, fmt.Errorf("apparmor: empty profile name")
	}

	path := filepath.Join(dir, p.Name)
	// Atomic write: write-temp + rename. Avoids a half-written
	// profile being parsed if we get interrupted.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(p.Body), 0o644); err != nil {
		return p, fmt.Errorf("apparmor: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return p, fmt.Errorf("apparmor: rename %s → %s: %w", tmp, path, err)
	}
	p.Path = path

	if dryRun {
		return p, nil
	}

	// apparmor_parser -r reloads if already loaded, loads otherwise.
	// Some distros use apparmor_parser, some have it under
	// /sbin/apparmor_parser only.
	parser, err := findParser()
	if err != nil {
		return p, err
	}
	cmd := exec.Command(parser, "-r", "--write-cache", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return p, fmt.Errorf("apparmor_parser -r %s: %w (%s)", path, err, string(out))
	}
	return p, nil
}

// Unload removes the profile from the kernel and deletes the file.
// Returns nil if the profile wasn't loaded.
func Unload(dir, name string) error {
	if dir == "" {
		dir = DefaultProfileDir
	}
	path := filepath.Join(dir, name)
	if _, err := os.Stat(path); err == nil {
		parser, err := findParser()
		if err == nil {
			cmd := exec.Command(parser, "-R", path)
			if out, e2 := cmd.CombinedOutput(); e2 != nil {
				return fmt.Errorf("apparmor_parser -R %s: %w (%s)", path, e2, string(out))
			}
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("apparmor: remove %s: %w", path, err)
		}
	}
	return nil
}

// Available reports whether AppArmor is usable on this host. Used
// by CapabilitySet probes at daemon startup.
func Available() bool {
	// /sys/kernel/security/apparmor exists iff AppArmor is built into
	// the kernel and enabled at boot.
	_, err := os.Stat("/sys/kernel/security/apparmor")
	if err != nil {
		return false
	}
	if _, err := findParser(); err != nil {
		return false
	}
	return true
}

func findParser() (string, error) {
	for _, p := range []string{
		"/usr/sbin/apparmor_parser",
		"/sbin/apparmor_parser",
		"/usr/bin/apparmor_parser",
	} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	if p, err := exec.LookPath("apparmor_parser"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("apparmor_parser: not found in standard paths")
}
