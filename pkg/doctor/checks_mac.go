package doctor

import (
	"context"
	"os"
	"strings"
)

// macChecks audit AppArmor / SELinux state. Either MAC is the second
// containment layer — discretionary perms (uid/gid) say "this is
// allowed", MAC says "but only in this confined way".
func macChecks() []Check {
	return []Check{
		{
			ID:       "mac.apparmor_enabled",
			Title:    "AppArmor is enabled (kernel module loaded)",
			Category: "mac",
			Severity: SeverityHigh,
			Description: "AppArmor is the standard MAC layer on Debian/Ubuntu. Without it, every service runs unconfined regardless of how good your sshd_config is.",
			Impact:      "An exploited daemon with no MAC profile can read every file the user account can. With a profile, it's restricted to its own namespaces.",
			Recommendation: "Enable AppArmor: `aa-status` should report `apparmor module is loaded`. If your kernel doesn't support it, switch to a kernel that does or use SELinux.",
			Run: func(_ context.Context) Result {
				if pathExists("/sys/module/apparmor") {
					return PassResult("apparmor module loaded")
				}
				if pathExists("/sys/fs/selinux") {
					return SkipResult("SELinux system; AppArmor not applicable")
				}
				return FailResult("apparmor module not loaded and no SELinux")
			},
		},
		{
			ID:       "mac.apparmor_profiles",
			Title:    "AppArmor has profiles loaded",
			Category: "mac",
			Severity: SeverityMedium,
			Description: "Module loaded ≠ anything is enforced. Profiles must be loaded and in enforce mode for the layer to do work.",
			Impact:      "Profiles in 'complain' mode log violations but allow them. An attacker is unrestricted; you just see them in logs.",
			Recommendation: "`aa-enforce /etc/apparmor.d/*` and check `aa-status` reports profiles in enforce mode.",
			Run: func(ctx context.Context) Result {
				if !pathExists("/sys/module/apparmor") {
					return SkipResult("apparmor not loaded")
				}
				out, err := runOutput(ctx, "aa-status", "--json")
				if err != nil {
					// Fall back to plain aa-status
					out, err = runOutput(ctx, "aa-status")
					if err != nil {
						return SkipResult("aa-status not available")
					}
				}
				if strings.Contains(out, "profiles are loaded") || strings.Contains(out, "profiles_count") {
					if strings.Contains(out, "0 profiles are loaded") {
						return FailResult("0 profiles loaded")
					}
					line := firstLine(out, "profiles are loaded")
					if line == "" {
						line = "profiles loaded"
					}
					return PassResult(line)
				}
				return WarnResult(strings.SplitN(out, "\n", 2)[0])
			},
		},
		{
			ID:       "mac.selinux_state",
			Title:    "SELinux is enforcing (if installed)",
			Category: "mac",
			Severity: SeverityHigh,
			Description: "SELinux is the standard MAC layer on RHEL family. Permissive mode logs violations without blocking; that's reconnaissance fuel for the attacker, not protection.",
			Impact:      "Permissive SELinux is the same as no SELinux for prevention, with extra log noise.",
			Recommendation: "Set `SELINUX=enforcing` in /etc/selinux/config and reboot. If applications break, investigate with `audit2allow` rather than disabling.",
			Run: func(ctx context.Context) Result {
				if !pathExists("/sys/fs/selinux") {
					return SkipResult("SELinux not installed")
				}
				if v, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
					switch strings.TrimSpace(string(v)) {
					case "1":
						return PassResult("enforcing")
					case "0":
						return FailResult("permissive")
					}
				}
				return WarnResult("state unknown")
			},
		},
		{
			ID:       "mac.lockdown",
			Title:    "Linux Lockdown LSM is enabled",
			Category: "mac",
			Severity: SeverityMedium,
			Description: "Lockdown restricts root from arbitrary kernel reads/writes (kexec, MSRs, /dev/mem, modify_ldt). Even root shouldn't reach into the kernel directly.",
			Impact:      "Without lockdown, an attacker who reaches root can install rootkits via /dev/mem, kprobes, or kexec. Lockdown forces them through harder paths.",
			Recommendation: "Boot with `lockdown=integrity` (kernel cmdline) or use a distro that ships it on by default (Ubuntu 22.04+, Fedora).",
			Run: func(_ context.Context) Result {
				p := "/sys/kernel/security/lockdown"
				body, err := os.ReadFile(p)
				if err != nil {
					return SkipResult("lockdown not available")
				}
				v := strings.TrimSpace(string(body))
				// Format: "[none] integrity confidentiality" with current in brackets.
				if strings.Contains(v, "[integrity]") || strings.Contains(v, "[confidentiality]") {
					return PassResult("lockdown = " + v)
				}
				return WarnResult("lockdown = " + v)
			},
		},
	}
}

func firstLine(s, contains string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, contains) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
