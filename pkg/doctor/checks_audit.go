package doctor

import (
	"context"
	"strings"
)

// auditChecks ensure the host has the basic plumbing every IR
// engagement needs: time sync, persistent logs, audit subsystem.
// xhelix observes events; auditd is the tamper-resistant fallback if
// xhelix itself is compromised or stopped.
func auditChecks() []Check {
	return []Check{
		{
			ID:       "audit.auditd_active",
			Title:    "auditd is installed and active",
			Category: "audit",
			Severity: SeverityMedium,
			Description: "auditd is the kernel audit subsystem's userspace daemon. It runs alongside xhelix as a redundant log channel — if xhelix is stopped or compromised, auditd still logs.",
			Impact:      "If xhelix is the only sensor and an attacker disables it, the host is blind. auditd in tamper-evident mode is independent.",
			Recommendation: "Install auditd: `apt-get install -y auditd` (or dnf equivalent), then `systemctl enable --now auditd`.",
			FixCommand:     "apt-get install -y auditd && systemctl enable --now auditd",
			Risky:          true,
			Run: func(ctx context.Context) Result {
				if !commandExists("auditctl") {
					return FailResult("auditd not installed")
				}
				out, err := runOutput(ctx, "systemctl", "is-active", "auditd")
				if err != nil || !strings.Contains(out, "active") {
					return FailResult("auditd installed but not active: " + out)
				}
				return PassResult("auditd active")
			},
		},
		{
			ID:       "audit.time_sync",
			Title:    "Time is synchronised (chrony / systemd-timesyncd / ntpd)",
			Category: "audit",
			Severity: SeverityMedium,
			Description: "Forensic timeline correlation needs accurate clocks. A skewed clock makes log correlation across hosts unreliable and is itself an indicator of tampering.",
			Impact:      "Without time sync, comparing logs across hosts during an incident becomes guesswork. Some auth protocols (Kerberos) also break.",
			Recommendation: "Install chrony or enable systemd-timesyncd: `timedatectl set-ntp true`.",
			FixCommand:     "timedatectl set-ntp true",
			Run: func(ctx context.Context) Result {
				out, err := runOutput(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value")
				if err != nil {
					return SkipResult("timedatectl not available")
				}
				if strings.TrimSpace(out) == "yes" {
					return PassResult("NTP synchronised")
				}
				return FailResult("NTP not synchronised")
			},
		},
		{
			ID:       "audit.journal_persistent",
			Title:    "systemd-journald has persistent storage",
			Category: "audit",
			Severity: SeverityMedium,
			Description: "By default journald keeps logs in tmpfs, which means logs vanish on reboot. After an incident, you want logs that survive the reboot the attacker may have triggered.",
			Impact:      "Volatile journals lose evidence as soon as the box reboots — exactly when you most need it.",
			Recommendation: "`mkdir -p /var/log/journal && systemctl restart systemd-journald` to enable persistent storage.",
			FixCommand:     "mkdir -p /var/log/journal && systemctl restart systemd-journald",
			Run: func(_ context.Context) Result {
				if pathExists("/var/log/journal") {
					return PassResult("/var/log/journal exists")
				}
				return FailResult("/var/log/journal missing — journals are volatile")
			},
			Apply: func(ctx context.Context) error {
				_, err := runCombined(ctx, "mkdir", "-p", "/var/log/journal")
				if err != nil {
					return err
				}
				_, err = runCombined(ctx, "systemctl", "restart", "systemd-journald")
				return err
			},
		},
		{
			ID:       "audit.coredump_off_or_safe",
			Title:    "Coredumps are restricted (no world-readable cores)",
			Category: "audit",
			Severity: SeverityLow,
			Description: "Setuid coredumps can leak hashed credentials, keys, and other secrets from the dumping process's address space. Default configs suppress them but verify.",
			Impact:      "A crashing privileged process could drop a core file containing memory the attacker isn't supposed to see.",
			Recommendation: "Set fs.suid_dumpable=0 and ensure /etc/security/limits.conf has `* hard core 0` if coredumps aren't needed.",
			FixCommand:     "sysctl -w fs.suid_dumpable=0",
			Run: func(_ context.Context) Result {
				v, err := readSysctl("fs.suid_dumpable")
				if err != nil {
					return ErrorResult(err)
				}
				if v == "0" {
					return PassResult("fs.suid_dumpable = 0")
				}
				return WarnResult("fs.suid_dumpable = " + v + " (want 0)")
			},
			Apply: func(_ context.Context) error {
				return applySysctl("fs.suid_dumpable", "0")
			},
		},
	}
}
