// Package brp implements the Behavioral Reference Profile system:
// signed JSON profiles describing what each role/version/OS variant of
// an app may legitimately do at runtime, plus the runtime matcher that
// resolves a binary to a profile and enforces its envelope.
//
// This file (protected.go) holds the immutable list of system paths
// that NO profile — signed, curated, or otherwise — may ever grant
// write/exec/quarantine access to. It is the v2 "protect-our-own"
// backstop: a malicious or buggy profile cannot direct xhelix to touch
// critical OS state.
//
// The list is intentionally narrow: paths whose corruption breaks the
// host's ability to authenticate users, run scheduled tasks, install
// packages, or boot. It is shared by:
//
//   - pkg/brp.LoadProfile — refuses to load a profile whose WriteRoots
//     or ExecAllowed intersect this list.
//   - pkg/enforce / pkg/remediate — refuse to quarantine or modify
//     paths matching this list, regardless of which rule fires.
//   - pkg/verify — the hard-deny plane consults this list as a
//     terminal invariant.
//
// Adding entries here is a CONSERVATIVE expansion (more protection,
// never less). Removing entries requires a deliberate code change and
// a release.
package brp

import "strings"

// ProtectedSystemPaths lists path prefixes (directories must end with
// "/") and exact files that xhelix's own enforcement actions and any
// signed profile are FORBIDDEN from writing, deleting, or quarantining.
//
// Rationale per entry — useful for audit:
//
//   - /etc/passwd, /etc/shadow, /etc/gshadow, /etc/sudoers,
//     /etc/sudoers.d/ — credential / authorisation backbone of the host
//   - /etc/psa/, /usr/local/psa/, /var/lib/psa/ — Plesk control panel
//     (added 2026-05-23 after a non-xhelix incident that demonstrated
//     how easy losing /etc/psa/.psa.shadow is to lock the operator out
//     of the panel and DB)
//   - /var/lib/mysql/, /var/lib/postgresql/, /var/lib/mariadb/ — live
//     database storage; deletion = total data loss
//   - /var/lib/dpkg/, /var/lib/rpm/, /var/lib/apt/lists/ — package
//     manager state; corruption = no future updates
//   - /boot/, /lib/modules/ — kernel image and modules
//   - /etc/systemd/system/, /etc/systemd/network/ — service definitions
//   - /etc/cron.d/, /etc/cron.daily/, /etc/cron.hourly/, /etc/cron.weekly/,
//     /etc/cron.monthly/, /etc/crontab, /var/spool/cron/ — scheduled
//     tasks
//   - /root/.ssh/, /etc/ssh/sshd_config, /etc/ssh/ssh_host_* — root
//     access pathways
//   - /etc/fstab, /etc/hosts, /etc/resolv.conf — mount + name resolution
//   - /etc/network/, /etc/netplan/ — networking config
//
// The list is consulted via IsProtectedPath which does a longest-prefix
// match.
var ProtectedSystemPaths = []string{
	// auth / privilege
	"/etc/passwd",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/pam.d/",
	"/etc/security/",

	// Plesk control panel (post-2026-05-23 protection)
	"/etc/psa/",
	"/usr/local/psa/",
	"/var/lib/psa/",
	"/opt/psa/",

	// Database storage
	"/var/lib/mysql/",
	"/var/lib/mariadb/",
	"/var/lib/postgresql/",
	"/var/lib/mongodb/",
	"/var/lib/redis/",

	// Package manager state
	"/var/lib/dpkg/",
	"/var/lib/rpm/",
	"/var/lib/apt/lists/",
	"/var/cache/apt/archives/",

	// Boot + kernel
	"/boot/",
	"/lib/modules/",
	"/usr/lib/modules/",

	// Service definitions.
	//
	// /etc/systemd/system/ + /lib/systemd/system/ + /usr/lib/systemd/system/
	// are intentionally NOT in this list. Snap, dpkg, apt, systemctl, and
	// many legitimate package operations write here as routine system
	// administration — protecting these dirs produced a FP storm during
	// live-fire testing (snap-aws-cli install on 2026-05-23). Custom unit
	// files dropped by an attacker are still detected by the systemd-unit
	// rules in ruleset/core/, which see actor + content, not just path.
	//
	// /etc/systemd/network/ stays protected because it is rarely modified
	// outside of explicit operator action and is a privileged-network
	// override surface.
	"/etc/systemd/network/",

	// Scheduled tasks
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.hourly/",
	"/etc/cron.weekly/",
	"/etc/cron.monthly/",
	"/etc/crontab",
	"/var/spool/cron/",

	// SSH access pathways
	"/root/.ssh/",
	"/etc/ssh/sshd_config",
	"/etc/ssh/sshd_config.d/",
	"/etc/ssh/ssh_host_rsa_key",
	"/etc/ssh/ssh_host_ed25519_key",
	"/etc/ssh/ssh_host_ecdsa_key",
	"/etc/ssh/ssh_host_dsa_key",

	// Mount + name resolution + network
	"/etc/fstab",
	"/etc/hosts",
	"/etc/hostname",
	"/etc/resolv.conf",
	"/etc/network/",
	"/etc/netplan/",
	"/etc/NetworkManager/",
}

// IsProtectedPath returns true if path is at or under any entry in
// ProtectedSystemPaths. Used by:
//
//   - profile loading: reject any profile claiming write/exec access here
//   - containment actions: reject any quarantine/modify targeting these paths
//   - hard-deny invariants: terminal "never auto-learn, always deny" rule
//
// Matching semantics:
//
//   - entries ending in "/" are directory prefixes (matches the dir
//     itself and anything below it)
//   - entries without trailing "/" are exact-file matches
//
// An empty path returns false. Symlink resolution is NOT performed
// here — callers that care about symlink confusion must resolve paths
// before calling.
func IsProtectedPath(path string) bool {
	if path == "" {
		return false
	}
	for _, p := range ProtectedSystemPaths {
		if strings.HasSuffix(p, "/") {
			// Directory prefix: also match the bare dir without trailing slash.
			if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

// IntersectsProtected returns the first protected path entry that
// matches any of the supplied roots. Returns "" if no intersection.
// Used by profile loading to give operators a specific reason on
// rejection ("profile would grant write to /etc/shadow").
func IntersectsProtected(roots []string) string {
	for _, r := range roots {
		if r == "" {
			continue
		}
		if IsProtectedPath(r) {
			return r
		}
		// Also reject roots that are PARENTS of protected entries
		// (a profile granting write to /etc/ would implicitly grant
		// access to /etc/shadow).
		for _, p := range ProtectedSystemPaths {
			if strings.HasSuffix(r, "/") && strings.HasPrefix(p, r) {
				return p
			}
			if !strings.HasSuffix(r, "/") && (p == r || strings.HasPrefix(p, r+"/")) {
				return p
			}
		}
	}
	return ""
}
