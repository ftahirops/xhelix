// Package landlock installs a Linux Landlock filesystem ACL on the
// xhelix daemon at startup. Phase G.3.
//
// Landlock is a stackable LSM (kernel ≥ 5.13) that lets an unprivileged
// process restrict its OWN future filesystem access. Once restricted,
// the restriction is irreversible for the process and is inherited by
// fork+execve. This is defense-in-depth on top of the BRP runtime + FIM
// observation layers: even if an attacker gains code execution in the
// daemon, they cannot write to /etc/passwd, /root/.ssh/, /etc/cron.d/,
// or any path outside xhelix's declared write surface.
//
// Three modes:
//
//	ModeOff      — no restriction (default; safest)
//	ModeDryRun   — compute the ruleset and log it; do NOT call
//	               landlock_restrict_self. Useful for operator
//	               preview before enforce.
//	ModeEnforce  — install the ruleset + restrict the process.
//	               IRREVERSIBLE. If the allowlist is wrong, the
//	               daemon will fail to write its own state and
//	               crash on the next file operation.
//
// We deliberately don't expose a "kill on denial" mode — landlock
// returns EACCES at syscall time, and the calling code's response is
// whatever EACCES means in context (write fails, alert logged).
//
// Kernel version handling: probe via landlock_create_ruleset with
// LANDLOCK_CREATE_RULESET_VERSION flag. Returns the highest ABI
// version supported; we compile a ruleset for the OLDEST features
// only (v1) so an older kernel can still load it. Newer access types
// (REFER v2, TRUNCATE v3) are conditionally added.
//
// CGO_ENABLED=0 compatible — pure-Go syscall wrappers via
// golang.org/x/sys/unix.
package landlock

import (
	"fmt"
	"log/slog"
)

// Mode is the install policy.
type Mode int

const (
	ModeOff Mode = iota
	ModeDryRun
	ModeEnforce
)

// String renders for logging.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeDryRun:
		return "dry-run"
	case ModeEnforce:
		return "enforce"
	}
	return "unknown"
}

// ParseMode parses an operator-supplied string into a Mode. Empty or
// unrecognized → ModeOff (the safe default).
func ParseMode(s string) Mode {
	switch s {
	case "dry-run", "dryrun", "audit":
		return ModeDryRun
	case "enforce":
		return ModeEnforce
	}
	return ModeOff
}

// Policy describes the filesystem surface xhelix needs.
// Paths must exist before Apply — landlock_add_rule requires open(O_PATH)
// on each path. Missing paths are logged + skipped (NOT a hard error).
type Policy struct {
	// ReadOnly paths the daemon may read + execute from. Typically:
	// /usr, /etc, /lib, /lib64, /bin, /sbin, /opt, /proc, /sys.
	ReadOnly []string

	// ReadWrite paths the daemon may read + write. Typically:
	// /var/lib/xhelix, /var/log/xhelix, /run/xhelix, /tmp.
	ReadWrite []string
}

// DefaultPolicy returns the baseline xhelix landlock allowlist.
// Operator can extend via /etc/xhelix/landlock.d/*.yaml in a follow-up
// (not in v1).
func DefaultPolicy() Policy {
	return Policy{
		ReadOnly: []string{
			// System roots — code + config
			"/usr", "/etc", "/lib", "/lib64", "/bin", "/sbin", "/opt",
			// Pseudo-filesystems
			"/proc", "/sys", "/dev",
			// Log files xhelix tails (read-only)
			"/var/log/auth.log",
			"/var/log/audit",
			"/var/log/apt",
			"/var/log/dpkg.log",
			"/var/log/syslog",
			"/var/log/secure",
			"/var/log/messages",
			"/var/log/journal",
			// Package state (for provenance checks)
			"/var/lib/dpkg",
			"/var/lib/snapd",
			"/var/cache/apt",
			// Home dirs (read-only — secret-taint observes file_open
			// of credential paths; landlock doesn't need write to home)
			"/home",
			"/root",
		},
		ReadWrite: []string{
			// xhelix's own state
			"/var/lib/xhelix",
			"/var/log/xhelix",
			"/run/xhelix",
			// Forensic snapshot dir
			"/var/lib/xhelix/forensic",
			// Temp scratch — Go runtime + helper subprocess writes
			"/tmp",
			"/var/tmp",
			// Lock files for helpers (nft, chattr) — usually under /run
			"/run/lock",
		},
	}
}

// Apply enforces or dry-runs the Landlock policy. ModeOff is a no-op.
// ModeDryRun logs what would be allowed without restricting.
// ModeEnforce installs the ruleset + calls landlock_restrict_self
// (IRREVERSIBLE for the calling process and its future descendants).
//
// Returns an error if landlock isn't supported by the running kernel
// OR if rule installation fails. Caller decides whether to abort
// startup; default policy in cmd/xhelix is to log + continue without
// restriction (fail-open).
func Apply(p Policy, mode Mode, log *slog.Logger) error {
	if mode == ModeOff {
		if log != nil {
			log.Info("landlock: mode=off; no filesystem restriction installed")
		}
		return nil
	}
	abi, err := probeABI()
	if err != nil {
		return fmt.Errorf("landlock: kernel does not support landlock: %w", err)
	}
	if log != nil {
		log.Info("landlock: kernel ABI probe", "abi_version", abi)
	}
	if mode == ModeDryRun {
		if log != nil {
			log.Info("landlock: dry-run — computing allowlist; NOT restricting",
				"read_only_paths", len(p.ReadOnly),
				"read_write_paths", len(p.ReadWrite))
			for _, path := range p.ReadOnly {
				log.Info("landlock: would allow read", "path", path)
			}
			for _, path := range p.ReadWrite {
				log.Info("landlock: would allow read+write", "path", path)
			}
		}
		return nil
	}
	// ModeEnforce — actually restrict.
	return enforce(p, abi, log)
}
