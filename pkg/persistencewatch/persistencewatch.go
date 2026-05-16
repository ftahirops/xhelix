// Package persistencewatch detects changes to Linux persistence
// mechanisms by diffing a snapshot against a baseline.
//
// Persistence mechanisms covered:
//
//   - Crontabs (/etc/crontab, /etc/cron.{d,daily,hourly,monthly,weekly}/*, user crontabs)
//   - At jobs (/var/spool/at/*)
//   - systemd unit files (/etc/systemd/system/*, /usr/lib/systemd/system/*, ~/.config/systemd/user/*)
//   - systemd timers (.timer units)
//   - Shell init files (/etc/profile, /etc/profile.d/*, /etc/bash.bashrc,
//     ~/.bashrc, ~/.profile, ~/.bash_profile, ~/.zshrc)
//   - Rc init (/etc/rc.local, /etc/init.d/*)
//   - Kernel module autoload (/etc/modules, /etc/modules-load.d/*)
//   - Dynamic loader preload (/etc/ld.so.preload, /etc/ld.so.conf.d/*)
//   - XDG autostart (/etc/xdg/autostart/*, ~/.config/autostart/*)
//   - PAM modules (/etc/pam.d/*, /lib/security/pam_*.so — hash only)
//   - SSH authorized_keys (~/.ssh/authorized_keys for every user)
//
// The package itself is pure: it operates on Snapshot structs. The
// caller is responsible for filesystem walks; helpers in this
// package can be plugged into a scheduler/runner upstream.
package persistencewatch

import (
	"sort"
)

// Category groups entries by the persistence mechanism class.
type Category uint8

const (
	CategoryUnknown        Category = 0
	CategoryCron           Category = 1
	CategoryAtJob          Category = 2
	CategorySystemdUnit    Category = 3
	CategorySystemdTimer   Category = 4
	CategoryShellInit      Category = 5
	CategoryRcInit         Category = 6
	CategoryKernelModule   Category = 7
	CategoryLdPreload      Category = 8
	CategoryXDGAutostart   Category = 9
	CategoryPAM            Category = 10
	CategorySSHAuthKeys    Category = 11
)

// String returns a stable lowercase token.
func (c Category) String() string {
	switch c {
	case CategoryCron:
		return "cron"
	case CategoryAtJob:
		return "at"
	case CategorySystemdUnit:
		return "systemd-unit"
	case CategorySystemdTimer:
		return "systemd-timer"
	case CategoryShellInit:
		return "shell-init"
	case CategoryRcInit:
		return "rc-init"
	case CategoryKernelModule:
		return "kernel-module"
	case CategoryLdPreload:
		return "ld-preload"
	case CategoryXDGAutostart:
		return "xdg-autostart"
	case CategoryPAM:
		return "pam"
	case CategorySSHAuthKeys:
		return "ssh-authorized-keys"
	}
	return "unknown"
}

// Severity reflects how high-signal a category is. /etc/ld.so.preload
// is the single highest-signal because legitimate use is essentially
// nil. Cron / systemd timers are common but rarely *new* on stable
// systems. PAM module changes are critical (top backdoor surface).
func (c Category) Severity() string {
	switch c {
	case CategoryLdPreload, CategoryPAM, CategorySSHAuthKeys:
		return "critical"
	case CategorySystemdUnit, CategorySystemdTimer, CategoryRcInit,
		CategoryKernelModule:
		return "high"
	case CategoryCron, CategoryAtJob, CategoryXDGAutostart:
		return "medium"
	case CategoryShellInit:
		return "low"
	}
	return "info"
}

// Entry is one persistence-mechanism artifact at a point in time.
type Entry struct {
	Category Category
	Path     string // absolute path
	Owner    string // username, when the artifact is per-user
	SHA256   string // content hash; empty if directory or symlink
	Mode     uint32 // unix mode bits
	Size     int64
}

// Snapshot is the full set of Entries observed at a point in time.
// Empty Path is invalid; Entries are keyed by Path internally.
type Snapshot struct {
	TakenAt int64 // unix seconds; informational only
	Entries []Entry
}

// Diff describes how a current Snapshot differs from a baseline.
// Each list is sorted by Path for stable output.
type Diff struct {
	Added    []Entry      // present in current, absent from baseline
	Removed  []Entry      // present in baseline, absent from current
	Modified []ModifiedEntry // present in both, content changed
}

// ModifiedEntry shows old vs new for a path whose hash or size changed.
type ModifiedEntry struct {
	Old Entry
	New Entry
}

// CountBySeverity returns a string→int map of severity → number
// of diff entries falling in that bucket. Useful for ranking
// alerts in the UI.
func (d Diff) CountBySeverity() map[string]int {
	out := map[string]int{}
	count := func(e Entry) { out[e.Category.Severity()]++ }
	for _, e := range d.Added {
		count(e)
	}
	for _, e := range d.Removed {
		count(e)
	}
	for _, m := range d.Modified {
		count(m.New)
	}
	return out
}

// IsEmpty reports whether the diff is fully empty.
func (d Diff) IsEmpty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Modified) == 0
}

// Compare returns the Diff between baseline and current.
//
// Semantics:
//   - An entry whose Path is in current but not baseline → Added.
//   - An entry whose Path is in baseline but not current → Removed.
//   - An entry whose Path is in both but whose SHA256 or Size or
//     Mode differs → Modified. (SHA256 is the primary key; if both
//     are empty fall back to size+mode.)
//
// Two Snapshot lists are O(N+M) to diff; we sort and walk.
func Compare(baseline, current Snapshot) Diff {
	bByPath := indexByPath(baseline)
	cByPath := indexByPath(current)

	var d Diff

	// Walk current → Added or Modified
	for _, c := range current.Entries {
		b, ok := bByPath[c.Path]
		if !ok {
			d.Added = append(d.Added, c)
			continue
		}
		if entryDiffers(b, c) {
			d.Modified = append(d.Modified, ModifiedEntry{Old: b, New: c})
		}
	}
	// Walk baseline → Removed
	for _, b := range baseline.Entries {
		if _, ok := cByPath[b.Path]; !ok {
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

// entryDiffers returns true if b and c represent meaningfully
// different content. SHA256 is authoritative when both have it;
// otherwise size+mode is the fallback.
func entryDiffers(b, c Entry) bool {
	if b.SHA256 != "" && c.SHA256 != "" {
		return b.SHA256 != c.SHA256
	}
	return b.Size != c.Size || b.Mode != c.Mode
}

func indexByPath(s Snapshot) map[string]Entry {
	out := make(map[string]Entry, len(s.Entries))
	for _, e := range s.Entries {
		out[e.Path] = e
	}
	return out
}

func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool { return es[i].Path < es[j].Path })
}

// CategoryForPath returns the best Category for an absolute path
// based on filename and parent-directory conventions. Unknown
// paths return CategoryUnknown. The caller decides whether to
// skip unknown paths from snapshotting.
//
// This is the canonical mapping; the file-system walker upstream
// should use it to label entries as it discovers them.
func CategoryForPath(p string) Category {
	if p == "" {
		return CategoryUnknown
	}
	switch p {
	case "/etc/crontab":
		return CategoryCron
	case "/etc/rc.local":
		return CategoryRcInit
	case "/etc/ld.so.preload":
		return CategoryLdPreload
	case "/etc/modules":
		return CategoryKernelModule
	case "/etc/profile", "/etc/bash.bashrc", "/etc/zsh/zshrc":
		return CategoryShellInit
	}
	// Suffix rules first — .timer is more specific than its
	// containing directory.
	for suffix, cat := range pathSuffixCategory {
		if hasSuffix(p, suffix) {
			return cat
		}
	}
	for prefix, cat := range pathPrefixCategory {
		if hasPrefix(p, prefix) {
			return cat
		}
	}
	// Per-user
	if isUserBashrc(p) || isUserProfile(p) || isUserZshrc(p) {
		return CategoryShellInit
	}
	if isUserAutostart(p) {
		return CategoryXDGAutostart
	}
	if isUserAuthorizedKeys(p) {
		return CategorySSHAuthKeys
	}
	if isUserCrontab(p) {
		return CategoryCron
	}
	if isUserSystemdUnit(p) {
		return CategorySystemdUnit
	}
	return CategoryUnknown
}

var pathPrefixCategory = map[string]Category{
	"/etc/cron.d/":               CategoryCron,
	"/etc/cron.daily/":           CategoryCron,
	"/etc/cron.hourly/":          CategoryCron,
	"/etc/cron.monthly/":         CategoryCron,
	"/etc/cron.weekly/":          CategoryCron,
	"/var/spool/cron/":           CategoryCron,
	"/var/spool/at/":             CategoryAtJob,
	"/etc/systemd/system/":       CategorySystemdUnit,
	"/usr/lib/systemd/system/":   CategorySystemdUnit,
	"/lib/systemd/system/":       CategorySystemdUnit,
	"/etc/profile.d/":            CategoryShellInit,
	"/etc/init.d/":               CategoryRcInit,
	"/etc/modules-load.d/":       CategoryKernelModule,
	"/etc/ld.so.conf.d/":         CategoryLdPreload,
	"/etc/xdg/autostart/":        CategoryXDGAutostart,
	"/etc/pam.d/":                CategoryPAM,
	"/lib/security/":             CategoryPAM,
	"/lib/x86_64-linux-gnu/security/": CategoryPAM,
	"/usr/lib/security/":         CategoryPAM,
}

var pathSuffixCategory = map[string]Category{
	".timer": CategorySystemdTimer,
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
func hasSuffix(s, p string) bool { return len(s) >= len(p) && s[len(s)-len(p):] == p }

// isUserBashrc matches "/home/<u>/.bashrc" or "/root/.bashrc".
func isUserBashrc(p string) bool {
	return matchUserHome(p, ".bashrc") || matchUserHome(p, ".bash_profile") ||
		matchUserHome(p, ".bash_login") || matchUserHome(p, ".bash_logout")
}
func isUserProfile(p string) bool {
	return matchUserHome(p, ".profile")
}
func isUserZshrc(p string) bool {
	return matchUserHome(p, ".zshrc") || matchUserHome(p, ".zprofile") ||
		matchUserHome(p, ".zshenv") || matchUserHome(p, ".zlogin")
}
func isUserAutostart(p string) bool {
	return matchUserHomePrefix(p, ".config/autostart/")
}
func isUserAuthorizedKeys(p string) bool {
	return matchUserHome(p, ".ssh/authorized_keys") ||
		matchUserHome(p, ".ssh/authorized_keys2")
}
func isUserCrontab(p string) bool {
	return hasPrefix(p, "/var/spool/cron/crontabs/")
}
func isUserSystemdUnit(p string) bool {
	// /home/<u>/.config/systemd/user/<name>.{service,timer,socket}
	return matchUserHomePrefix(p, ".config/systemd/user/")
}

// matchUserHome returns true if p == "/home/<anyone>/<suffix>" or
// "/root/<suffix>".
func matchUserHome(p, suffix string) bool {
	if hasPrefix(p, "/root/") && p[6:] == suffix {
		return true
	}
	if !hasPrefix(p, "/home/") {
		return false
	}
	rest := p[6:]
	// rest = "<user>/<suffix>"; find first '/'.
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[i+1:] == suffix
		}
	}
	return false
}

func matchUserHomePrefix(p, suffix string) bool {
	if hasPrefix(p, "/root/") {
		return hasPrefix(p[6:], suffix)
	}
	if !hasPrefix(p, "/home/") {
		return false
	}
	rest := p[6:]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return hasPrefix(rest[i+1:], suffix)
		}
	}
	return false
}
