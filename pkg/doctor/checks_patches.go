package doctor

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// patchChecks audit how recent the system is. Concrete CVE
// enumeration is out of scope (would require a CVE database); we
// answer the higher-leverage question: "is the operator behind on
// updates, and is a reboot pending?"
func patchChecks() []Check {
	return []Check{
		{
			ID:       "patches.apt_pending",
			Title:    "No pending apt security updates",
			Category: "patches",
			Severity: SeverityHigh,
			Description: "apt-get -s upgrade reports packages with new versions in the configured archives. If the security archive has packages waiting, those are CVEs you don't have.",
			Impact:      "Every day a security update sits unapplied is a day with a known-public exploit. Internet-facing hosts get scanned for these within hours.",
			Recommendation: "`apt-get update && apt-get -y upgrade` (or `unattended-upgrades` for automatic security-only).",
			FixCommand:     "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade",
			Risky:          true, // upgrade can restart services
			Run: func(ctx context.Context) Result {
				if !commandExists("apt-get") {
					return SkipResult("apt not present (non-Debian system)")
				}
				out, err := runOutput(ctx, "apt-get", "-s", "-q", "upgrade")
				if err != nil {
					return ErrorResult(err)
				}
				n := countUpgradable(out)
				if n == 0 {
					return PassResult("no pending upgrades")
				}
				if n <= 5 {
					return WarnResult(fmt.Sprintf("%d package upgrades pending", n))
				}
				return FailResult(fmt.Sprintf("%d package upgrades pending", n))
			},
		},
		{
			ID:       "patches.dnf_pending",
			Title:    "No pending dnf/yum security updates",
			Category: "patches",
			Severity: SeverityHigh,
			Description: "dnf check-update reports packages with new versions. --security narrows to security-flagged updates.",
			Impact:      "Same as apt: missed security updates are known CVEs you've left exposed.",
			Recommendation: "`dnf upgrade --security` (or use dnf-automatic for automatic security upgrades).",
			FixCommand:     "dnf -y upgrade --security",
			Risky:          true,
			Run: func(ctx context.Context) Result {
				if !commandExists("dnf") && !commandExists("yum") {
					return SkipResult("dnf/yum not present")
				}
				cmd := "dnf"
				if !commandExists("dnf") {
					cmd = "yum"
				}
				out, _ := runOutput(ctx, cmd, "check-update", "--security", "-q")
				lines := nonEmptyLines(out)
				if len(lines) == 0 {
					return PassResult("no security updates pending")
				}
				return FailResult(fmt.Sprintf("%d security packages pending", len(lines)))
			},
		},
		{
			ID:       "patches.reboot_required",
			Title:    "No pending kernel/glibc reboot",
			Category: "patches",
			Severity: SeverityMedium,
			Description: "Kernel and glibc updates need a reboot to take effect. The flag file `/var/run/reboot-required` (Debian) or `needs-restarting -r` (Red Hat) tracks this.",
			Impact:      "Running an old kernel after the patched one is installed leaves the CVE in place. Some kernel CVEs are weaponised within hours of disclosure.",
			Recommendation: "Schedule a reboot during a maintenance window. `livepatch` (Ubuntu Pro) / `kpatch` / `kgraft` can avoid the reboot for some classes of fix.",
			Run: func(_ context.Context) Result {
				if pathExists("/var/run/reboot-required") {
					b, _ := os.ReadFile("/var/run/reboot-required.pkgs")
					pkgs := strings.TrimSpace(string(b))
					if pkgs == "" {
						pkgs = "(unspecified packages)"
					}
					return FailResult("reboot required for: " + pkgs)
				}
				return PassResult("no reboot-required flag")
			},
		},
		{
			ID:       "patches.last_apt_update",
			Title:    "apt cache refreshed in the last 7 days",
			Category: "patches",
			Severity: SeverityLow,
			Description: "If apt-get update hasn't been run recently, the upgrade-pending check above is stale.",
			Impact:      "Stale apt cache means you can't see the security updates published this week.",
			Recommendation: "Schedule a daily `apt-get update` (the unattended-upgrades package does this automatically).",
			FixCommand:     "apt-get update",
			Run: func(_ context.Context) Result {
				if !commandExists("apt-get") {
					return SkipResult("apt not present")
				}
				st, err := os.Stat("/var/lib/apt/periodic/update-success-stamp")
				if err != nil {
					st, err = os.Stat("/var/cache/apt/pkgcache.bin")
				}
				if err != nil {
					return WarnResult("apt cache age unknown")
				}
				age := time.Since(st.ModTime())
				if age < 7*24*time.Hour {
					return PassResult(fmt.Sprintf("apt cache age = %s", age.Round(time.Hour)))
				}
				return FailResult(fmt.Sprintf("apt cache age = %s (> 7d)", age.Round(time.Hour)))
			},
		},
	}
}

// countUpgradable parses `apt-get -s upgrade` output:
// "N upgraded, M newly installed, K to remove and L not upgraded."
func countUpgradable(out string) int {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "upgraded,") && strings.Contains(line, "newly installed") {
			fields := strings.Fields(line)
			if len(fields) >= 1 {
				var n int
				if _, err := fmt.Sscanf(fields[0], "%d", &n); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}
