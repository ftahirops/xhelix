package doctor

import (
	"context"
	"fmt"
	"strings"

	"github.com/xhelix/xhelix/pkg/config"
)

// xhelixSelfChecks audit the running xhelix daemon's configuration
// for footguns. The most common operator mistakes — UI bound on a
// public address without TLS, response engine never enabled, evidence
// dir world-readable — go here.
//
// These checks need the loaded Config, so they're built lazily via
// XhelixSelfChecks(cfg) rather than baked into AllChecks().
func XhelixSelfChecks(cfg config.Config) []Check {
	return []Check{
		{
			ID:       "xhelix.ui_tls_required_if_public",
			Title:    "xhelix UI does not bind a public IP without TLS",
			Category: "xhelix",
			Severity: SeverityCritical,
			Description: "The UI ships a one-shot bearer token. Without TLS, that token is sniffable on the wire — game over for the dashboard.",
			Impact:      "Anyone in the network path can capture the token and impersonate the operator.",
			Recommendation: "Either bind to 127.0.0.1 only, or enable tls_enabled: true (the daemon will auto-generate a self-signed cert).",
			Run: func(_ context.Context) Result {
				if !cfg.UI.Enabled {
					return SkipResult("UI not enabled")
				}
				bind := cfg.UI.Bind
				if bind == "" {
					bind = "127.0.0.1:18443"
				}
				if cfg.UI.TLSEnabled {
					return PassResult("UI TLS enabled, bind=" + bind)
				}
				if strings.HasPrefix(bind, "127.") || strings.HasPrefix(bind, "[::1]") {
					return PassResult("UI bound loopback-only, TLS off is acceptable")
				}
				return FailResult("UI bind=" + bind + " with TLS off — token is sniffable")
			},
		},
		{
			ID:       "xhelix.ui_allowlist_or_ssh_detect",
			Title:    "xhelix UI has IP allow-list or auto_detect_ssh enabled",
			Category: "xhelix",
			Severity: SeverityHigh,
			Description: "Without an IP allow-list, the bearer token alone protects the UI. Two-factor (token + IP) is strictly better.",
			Impact:      "If the token leaks, an attacker from anywhere can use it. With an allow-list, they need network position too.",
			Recommendation: "Set ui.allow_ips: [<your mgmt IP>] OR ui.auto_detect_ssh: true.",
			Run: func(_ context.Context) Result {
				if !cfg.UI.Enabled {
					return SkipResult("UI not enabled")
				}
				if cfg.UI.AutoDetectSSH || len(cfg.UI.AllowIPs) > 0 {
					return PassResult(fmt.Sprintf("auto_ssh=%t, allow_ips=%d",
						cfg.UI.AutoDetectSSH, len(cfg.UI.AllowIPs)))
				}
				return FailResult("no allow_ips and auto_detect_ssh disabled — token is the only gate")
			},
		},
		{
			ID:       "xhelix.response_engine_enabled",
			Title:    "xhelix response engine is enabled",
			Category: "xhelix",
			Severity: SeverityMedium,
			Description: "Without the response engine, xhelix is detect-only. Alerts go to the bus; nothing kills the offending process or bans the source IP.",
			Impact:      "Detect-only mode buys the operator time to respond manually. If you're the only operator, that may be too slow.",
			Recommendation: "Set response.enabled: true after running detect-only for 7-30 days to validate rules don't false-positive on your workload.",
			Run: func(_ context.Context) Result {
				if cfg.Response.Enabled {
					return PassResult("response engine enabled")
				}
				return WarnResult("response engine disabled — detect-only mode")
			},
		},
		{
			ID:       "xhelix.fim_enabled",
			Title:    "FIM sensor is enabled",
			Category: "xhelix",
			Severity: SeverityHigh,
			Description: "File integrity monitoring catches /etc/passwd, /etc/shadow, ld.so.preload, ssh authorized_keys mods. Disabling it removes one of the highest-signal detections.",
			Impact:      "Without FIM, the persistence techniques in MITRE T1098 (Account Manipulation) and T1547 (Boot or Logon Autostart) are silent.",
			Recommendation: "Set sensors.fim.enabled: true.",
			Run: func(_ context.Context) Result {
				if cfg.Sensors.FIM.Enabled {
					return PassResult("FIM enabled")
				}
				return FailResult("FIM disabled — persistence detection is offline")
			},
		},
		{
			ID:       "xhelix.ebpf_enabled",
			Title:    "eBPF sensor plane is enabled",
			Category: "xhelix",
			Severity: SeverityHigh,
			Description: "eBPF is the workhorse sensor — every process exec, every dangerous syscall, every privilege transition flows through it. With eBPF off, xhelix relies on FIM and decoys only.",
			Impact:      "No process behaviour visibility. You catch persistence (FIM) and curiosity (decoys), miss exec.",
			Recommendation: "Set sensors.ebpf.enabled: true. Requires kernel ≥5.7 with BTF.",
			Run: func(_ context.Context) Result {
				if cfg.Sensors.EBPF.Enabled {
					return PassResult("eBPF enabled")
				}
				return FailResult("eBPF disabled — process-level detection is offline")
			},
		},
		{
			ID:       "xhelix.execguard_enabled",
			Title:    "execguard (fanotify exec-deny) is enabled",
			Category: "xhelix",
			Severity: SeverityMedium,
			Description: "execguard prevents exec from /tmp, /dev/shm, /proc/self/fd/*, etc. before the binary runs. The closest thing to LSM enforcement we ship from userspace.",
			Impact:      "Without execguard, /tmp-staged exploits run for the milliseconds it takes the response engine to react.",
			Recommendation: "Set execguard.enabled: true. Requires CAP_SYS_ADMIN and a kernel with CONFIG_FANOTIFY_ACCESS_PERMISSIONS.",
			Run: func(_ context.Context) Result {
				if cfg.ExecGuard.Enabled {
					return PassResult("execguard enabled")
				}
				return WarnResult("execguard disabled — pre-exec deny offline")
			},
		},
		{
			ID:       "xhelix.evidence_dir_safe",
			Title:    "Forensic evidence dir is restrictive (root-owned, mode 0700)",
			Category: "xhelix",
			Severity: SeverityMedium,
			Description: "Evidence captures contain memory dumps and process state. World-readable evidence is a credential leak.",
			Impact:      "An attacker who reaches non-root user can read other processes' memory dumps captured by xhelix.",
			Recommendation: "`chown root:root <evidence_dir> && chmod 0700 <evidence_dir>`",
			Run: func(_ context.Context) Result {
				if !cfg.Forensic.Enabled {
					return SkipResult("forensic snapshotter not enabled")
				}
				dir := cfg.Forensic.EvidenceDir
				if dir == "" {
					dir = cfg.Agent.StateDir + "/evidence"
				}
				if !pathExists(dir) {
					return SkipResult("evidence dir does not yet exist")
				}
				return checkFilePerms(dir, 0o700)
			},
		},
	}
}
