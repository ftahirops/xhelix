package appregistry

import (
	"fmt"
	"strings"
)

// validModes is the closed set of enforcement modes. Anything outside it
// is rejected at the registry boundary so a typo'd/forged mode can never
// silently disable enforcement (an unrecognized mode would fall through
// the compiler's mode switch and skip the policy entirely).
var validModes = map[EnforcementMode]bool{
	ModeObserve: true, ModeShadow: true, ModeGuarded: true,
	ModeLocked: true, ModeSealed: true,
}

// ValidMode reports whether m is one of the five canonical modes.
func ValidMode(m EnforcementMode) bool { return validModes[m] }

// validateApp checks every operator-supplied field that later flows into
// a filesystem path, a systemd unit argument, or an enforcement decision.
// This is the single chokepoint that prevents path traversal (app name →
// artifact dir; unit name → drop-in dir), systemctl flag smuggling, and
// enforcement-bypass via a bogus mode.
func validateApp(a App) error {
	if !validSlug(a.Name) {
		return fmt.Errorf("appregistry: invalid app name %q (allowed: a-z 0-9 _ - . , 1-64 chars, no leading dash/dot)", a.Name)
	}
	if a.Mode != "" && !ValidMode(a.Mode) {
		return fmt.Errorf("appregistry: invalid mode %q", a.Mode)
	}
	for i, svc := range a.Services {
		// The unit name that reaches systemd is UnitName, falling back to
		// the service Name (see Create). Both must be safe.
		if svc.UnitName != "" && !validUnitName(svc.UnitName) {
			return fmt.Errorf("appregistry: service %d: invalid unit_name %q", i, svc.UnitName)
		}
		if svc.Name != "" && !validUnitName(svc.Name) {
			return fmt.Errorf("appregistry: service %d: invalid name %q", i, svc.Name)
		}
		if svc.CgroupMatch != "" && !validCgroupPath(svc.CgroupMatch) {
			return fmt.Errorf("appregistry: service %d: invalid cgroup_match %q (must be an absolute /-rooted path, no '..')", i, svc.CgroupMatch)
		}
		if svc.BinaryPath != "" && !validBinaryPath(svc.BinaryPath) {
			return fmt.Errorf("appregistry: service %d: invalid binary_path %q (must be an absolute path, no '..')", i, svc.BinaryPath)
		}
	}
	return nil
}

// validSlug allows app names: lower/upper alnum plus -_. , no path
// separators, no leading dot/dash, length 1..64. Used for the artifact
// directory component and the drop-in filename.
func validSlug(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	if s[0] == '.' || s[0] == '-' {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// validUnitName allows the character set systemd permits in unit names
// (alnum and . _ - @ :), length 1..128, no path separators, no '..', and
// no leading '-' (which systemctl would treat as a flag).
func validUnitName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	if s[0] == '-' || strings.Contains(s, "..") || strings.ContainsAny(s, "/ ") {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == '@' || c == ':':
		default:
			return false
		}
	}
	return true
}

// validCgroupPath requires an absolute, /-rooted cgroup v2 path with no
// '..' traversal. The slash anchor is what cgroup prefix matching relies
// on for its security invariant.
func validCgroupPath(s string) bool {
	if s == "" || len(s) > 512 || s[0] != '/' {
		return false
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, " \t\n") {
		return false
	}
	return true
}

// validBinaryPath requires an absolute path with no traversal. Used in
// the exec allowlist; kept strict so a relative or '..'-bearing path can
// never widen the allowlist unexpectedly.
func validBinaryPath(s string) bool {
	if s == "" || len(s) > 512 || s[0] != '/' {
		return false
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, " \t\n") {
		return false
	}
	return true
}
