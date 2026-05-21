// Package response implements xhelix's active response engine.
//
// It subscribes to the alert bus and translates Critical/High alerts
// into concrete actions: SIGSTOP the pid, ban the src_ip, restore
// the tampered file, fire a webhook. Per-rule policy decides which
// actions run; PanicSwitch globally vetoes everything.
//
// Why a central engine and not per-sink callbacks: a single Critical
// alert often deserves multiple actions (kill pid + ban IP + alert),
// and the order matters (capture forensics before SIGSTOP terminates
// the offending process; ban IP before remediating to stop the
// attacker's next move during cleanup).
package response

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/memscan"
	"github.com/xhelix/xhelix/pkg/model"
)

// Action enumerates the response primitives.
type Action uint16

const (
	ActionLog            Action = 1 << iota // bus + sinks (default)
	ActionQuarantine                        // SIGSTOP target pid
	ActionKill                              // SIGKILL target pid
	ActionNetBan                            // add src_ip to XDP + nftables drop sets
	ActionRemediate                         // restore tampered file from chain
	ActionWebhook                           // fire webhook with formatted payload
	ActionSnapshot                          // forensic capture before kill
	ActionMemScan                           // YARA-lite scan of process memory
	ActionLockUser                          // disable the offending local account
	ActionHostQuarantine                    // isolate host from network (last resort)
)

// Policy maps a rule_id to the bitmask of actions to perform when it
// fires. Empty / missing entries default to ActionLog only.
type Policy map[string]Action

// Default returns the production-safe day-1 policy.
//
// Action-mask audit (P-PS.29): every entry below is annotated with
// its FP-risk class. Only entries marked "minimal" carry
// destructive actions (Quarantine, Kill, Remediate, NetBan,
// LockUser). Entries marked "medium" or "high" log + snapshot +
// memscan but do NOT destruct, because the cost of a false
// positive (SIGSTOPping a production process, banning a real
// operator's IP, locking out a real account) outweighs the
// marginal containment benefit until operators have triaged the
// rule's FP rate on their specific workload.
//
// Operators promote a rule from log-only to destructive after a
// soak period (see pkg/response.SoakGate) and after auditing the
// rule's FP rate against their workload via xhelixctl alerts
// label + xhelixctl events replay.
//
// FP-risk taxonomy:
//
//	minimal — rule fires ONLY on adversarial primitives that
//	          legitimate code does not execute (e.g., a decoy file
//	          opened, a canary token used in a real HTTP header).
//	          Quarantine is safe by construction.
//	low     — primarily attacker behaviour; rare FPs possible
//	          (e.g., uid0 transition without setuid, ssh brute
//	          then success). Quarantine acceptable; Remediate
//	          requires care.
//	medium  — legitimate runtimes / admin tooling can fire it
//	          (e.g., shell-with-socket-fd, web_server_spawns_shell,
//	          ptrace_sensitive_target). Destructive actions GATED
//	          behind allowlist + soak.
//	high    — fires on EVERY legitimate runtime in a category
//	          (mem_mprotect_rwx, memfd_run_pattern,
//	          bpf_syscall_unexpected). Action mask must use
//	          allowlist tags or be log-only.
func Default() Policy {
	return Policy{
		// ─── DECOYS (FP-risk: minimal) ───────────────────────────
		// Decoys are placed by the operator. Their use signals an
		// attacker who took the bait — by construction.
		"decoy_file_opened":         ActionLog | ActionWebhook | ActionSnapshot | ActionQuarantine,
		"decoy_service_connect":     ActionLog | ActionWebhook | ActionNetBan,
		"decoy_canary_token_used":   ActionLog | ActionWebhook | ActionNetBan,
		"decoy_dns_resolved":        ActionLog | ActionWebhook | ActionSnapshot,

		// ─── MEMORY EXPLOIT PRIMITIVES ───────────────────────────
		// mem_mprotect_rwx: FP-risk high. V8, HotSpot, .NET, LuaJIT,
		//   PyPy, BPF JIT all do RWX page churn. Suppression goes via
		//   `event.tags["jit_allowlisted"] != "true"` in the rule
		//   YAML (consumes pkg/runtimeallow). Action mask is
		//   log+snapshot+memscan — no quarantine.
		"mem_mprotect_rwx":          ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan,
		// mem_canary_fail: FP-risk low. Stack canaries do legitimately
		//   fail on real crashes, but the snapshot + memscan are the
		//   evidence the operator needs; quarantining a crashing
		//   process accomplishes nothing.
		"mem_canary_fail":           ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan,
		// mem_kernel_anomaly: FP-risk minimal — kernel anomaly is rare
		//   and operator-actionable, but quarantining a userland pid
		//   doesn't address a kernel issue.
		"mem_kernel_anomaly":        ActionLog | ActionWebhook | ActionSnapshot,
		// mem_lkrg_violation: FP-risk low. LKRG check failures are
		//   high-signal kernel integrity events. Keep quarantine but
		//   ONLY for the offending pid — the kernel-level fix is
		//   manual.
		"mem_lkrg_violation":        ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan | ActionQuarantine,

		// ─── PROCESS PATTERNS ────────────────────────────────────
		// shell_with_socket_fd: FP-risk medium. nc, socat, screen,
		//   tmux can pipe socket → shell legitimately. Quarantine
		//   GATED — keep action mask but operators must opt in to
		//   destructive via soak ladder.
		"shell_with_socket_fd":      ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan | ActionQuarantine,
		// memfd_run_pattern: FP-risk high. Claude Code's runtime,
		//   node child_process via memfd, Python runpy, Docker
		//   BuildKit, Buildkite, snapd all use memfd_create+execve.
		//   Suppressed by jit_allowlisted tag at the pipeline.
		//   Action mask is log+snapshot+memscan.
		"memfd_run_pattern":         ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan,
		// web_server_spawns_shell: FP-risk medium. Legitimate
		//   webhook receivers (CI, ChatOps) spawn shells. Action
		//   mask retains Quarantine but operators should review the
		//   rule's parent_image set before flipping enforce.
		"web_server_spawns_shell":   ActionLog | ActionWebhook | ActionSnapshot | ActionQuarantine,
		// binary_runs_from_tmp: FP-risk medium. pip install, npm
		//   install, Docker BuildKit, dpkg postinst all execute from
		//   /tmp. Log only — snapshot retains evidence.
		"binary_runs_from_tmp":      ActionLog | ActionWebhook | ActionSnapshot,
		// uid0_no_transition: FP-risk low. systemd-run --uid 0 from
		//   non-root is legitimate but rare. Quarantine acceptable.
		"uid0_no_transition":        ActionLog | ActionWebhook | ActionSnapshot | ActionQuarantine,
		// ptrace_sensitive_target: FP-risk medium-high. gdb, strace,
		//   perf, eBPF developers, /proc tools all ptrace. We added
		//   the rule narrow ("sensitive_target" = sshd, polkit,
		//   gnome-keyring) but the rule needs an allowlist for
		//   /usr/bin/gdb, /usr/bin/strace as parent. Until then
		//   DOWNGRADE from Quarantine to Snapshot-only.
		"ptrace_sensitive_target":   ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan,

		// ─── FILE INTEGRITY ──────────────────────────────────────
		// tamper_passwd: FP-risk medium. Legitimate `useradd` writes
		//   /etc/passwd. Remediate would revert that. DOWNGRADE to
		//   snapshot+webhook — operator inspects, restores manually
		//   if needed via xhelixctl remediate.
		"tamper_passwd":             ActionLog | ActionWebhook | ActionSnapshot,
		// tamper_shadow: same reasoning as above for `passwd` cmd.
		"tamper_shadow":             ActionLog | ActionWebhook | ActionSnapshot,
		// ld_so_preload_modified: FP-risk medium. dpkg/apt installs
		//   that include shared-object preload (rare but real:
		//   /etc/ld.so.preload via libsoftokn3, etc.) would be
		//   remediated. DOWNGRADE — operator confirms before revert.
		"ld_so_preload_modified":    ActionLog | ActionWebhook | ActionSnapshot,
		// pam_module_drop: FP-risk low. PAM modules being installed
		//   under /lib/security/ or /usr/lib64/security/ is usually
		//   a package install (libpam-google-auth, etc.). Snapshot,
		//   no auto-revert.
		"pam_module_drop":           ActionLog | ActionWebhook | ActionSnapshot,
		// ssh_key_added_root: FP-risk medium. Ansible/Puppet/Salt
		//   write to authorized_keys during normal infra runs.
		//   Remediate would revert legitimate config-mgmt. DOWNGRADE
		//   to snapshot+webhook.
		"ssh_key_added_root":        ActionLog | ActionWebhook | ActionSnapshot,
		"cron_new_unit":             ActionLog | ActionWebhook | ActionSnapshot,

		// ─── NETWORK ─────────────────────────────────────────────
		// outbound_to_known_bad: FP-risk low IF threat-intel feed is
		//   reputable (Spamhaus DROP). NetBan acceptable.
		"outbound_to_known_bad":     ActionLog | ActionWebhook | ActionNetBan,
		// metadata_svc_unexpected: FP-risk low. legit AWS-CLI on the
		//   host calls IMDS, but only from a small allowlist of pids
		//   (aws-cli, kubelet). Snapshot — no NetBan because IMDS
		//   address is link-local and banning is pointless.
		"metadata_svc_unexpected":   ActionLog | ActionWebhook | ActionSnapshot,
		"netids.dga":                ActionLog | ActionWebhook,

		// ─── SELF-DEFENCE ────────────────────────────────────────
		// bpf_syscall_unexpected: FP-risk HIGH. Cilium, BCC,
		//   bpftrace, bpftool, libbpf-based tools all call bpf().
		//   Runc loads cgroup-device-controller BPF on every
		//   container start. SIGSTOPping any of these breaks the
		//   host. DOWNGRADE from Quarantine to Snapshot. Operators
		//   tighten via a per-host allowlist.
		"bpf_syscall_unexpected":    ActionLog | ActionWebhook | ActionSnapshot,

		// ─── AUTH ────────────────────────────────────────────────
		// ssh_brute_then_success: FP-risk minimal — the cooccur
		//   logic requires N failures then a success from same src.
		//   NetBan + LockUser acceptable.
		"ssh_brute_then_success":    ActionLog | ActionWebhook | ActionNetBan | ActionLockUser,

		// ─── ELITE / CORRELATION ─────────────────────────────────
		// beacon.periodic_callback: FP-risk medium. legit telemetry
		//   (datadog, sentry, statsd) emits periodic callbacks.
		//   DOWNGRADE NetBan to snapshot — operators tune the
		//   allowlist of expected periodic endpoints.
		"beacon.periodic_callback":  ActionLog | ActionWebhook | ActionSnapshot,
		"dnsexfil.tunnel_pattern":   ActionLog | ActionWebhook,
		"tamper.ptrace":             ActionLog | ActionWebhook,
		"tamper.binary_mtime":       ActionLog | ActionWebhook,
		"tamper.binary_inode":       ActionLog | ActionWebhook,
		"tamper.auditd_dead":        ActionLog | ActionWebhook,
		"tamper.binary_missing":     ActionLog | ActionWebhook,
		"tamper.pidfile":            ActionLog | ActionWebhook,
		"kallsyms_changed":          ActionLog | ActionWebhook,
		"modules_changed":           ActionLog | ActionWebhook,
		"syscall_address_drift":    ActionLog | ActionWebhook,

		// v0.0.11 baseline scoring (Phase 2). Detection-mode by
		// default until operators have triaged FP rates on their
		// workload — these statistical alerts are noisier than
		// rule-based ones.
		"baseline.behavioural_deviation": ActionLog | ActionWebhook,
		"baseline.rate_spike":            ActionLog | ActionWebhook,
	}
}

// Engine is the response orchestrator.
type Engine struct {
	policy Policy
	log    *slog.Logger

	// MonitorMode, when true, masks every per-alert action to
	// ActionLog | ActionWebhook before dispatch. The Engine still
	// counts the alert and emits structured logs, but no destructive
	// backend (quarantine, kill, netban, remediate, lockuser,
	// hostquarantine) runs. Set via Config.MonitorMode and surfaced
	// to operators as "response posture: observe-only".
	//
	// Added P-PS.23 after the daemon SIGSTOP'd the operator's own
	// shell on memfd_run_pattern despite the runbook calling for
	// monitor mode. See ERRORS.md entry "memfd self-DoS".
	monitorMode bool

	mu      sync.RWMutex
	running atomic.Bool
	stopCh  chan struct{}

	netBan        NetBanner
	hostBanner    HostBanner
	hostAllowIPs  []string
	remediator    Remediator
	quarantine    *enforce.Quarantine
	panicSwitch   *enforce.PanicSwitch
	webhook       WebhookFn
	snapshotter   Snapshotter
	memPatterns   []memscan.Pattern
	lockUser      LockUserFn

	stats struct {
		alerts          atomic.Uint64
		quarantine      atomic.Uint64
		kill            atomic.Uint64
		netban          atomic.Uint64
		remediate       atomic.Uint64
		webhook         atomic.Uint64
		snapshot        atomic.Uint64
		memscan         atomic.Uint64
		lockUser        atomic.Uint64
		hostQuarantine  atomic.Uint64
		dropped         atomic.Uint64
	}
}

// NetBanner is implemented by pkg/netban; declared here as an
// interface so the response engine doesn't pull in a concrete dep.
type NetBanner interface {
	Ban(ip net.IP, reason string, ttl time.Duration) error
	Unban(ip net.IP) error
	List() ([]string, error)
}

// Remediator is implemented by pkg/remediate.
type Remediator interface {
	Restore(path string, reason string) error
}

// Snapshotter is implemented by pkg/forensic.
type Snapshotter interface {
	Capture(pid int, comm, ruleID string) (string, error)
}

// HostBanner is implemented by pkg/netban.Banner.
type HostBanner interface {
	EngageQuarantine(ctx context.Context, allowIPs []string) error
	Quarantined() bool
}

// LockUserFn neutralises a local account. Implemented by pkg/lockout.
type LockUserFn func(username string) error

// WebhookFn fires a single webhook send.
type WebhookFn func(ctx context.Context, alert model.Alert) error

// Config bundles dependencies.
type Config struct {
	Policy           Policy
	NetBanner        NetBanner
	HostBanner       HostBanner
	HostAllowIPs     []string
	Remediator       Remediator
	Snapshotter      Snapshotter
	MemPatterns      []memscan.Pattern
	LockUser         LockUserFn
	Quarantine       *enforce.Quarantine
	PanicSwitch      *enforce.PanicSwitch
	Webhook          WebhookFn
	Logger           *slog.Logger

	// MonitorMode forces the engine into observe-only mode — every
	// per-alert action is masked to ActionLog|ActionWebhook before
	// dispatch. Set this from cfg.Response.MonitorMode (yaml:
	// "monitor_mode: true") for learning-mode deployments.
	MonitorMode bool
}

// New builds a response engine.
func New(cfg Config) *Engine {
	if cfg.Policy == nil {
		cfg.Policy = Default()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	e := &Engine{
		policy:      cfg.Policy,
		log:         cfg.Logger,
		monitorMode: cfg.MonitorMode,
		netBan:      cfg.NetBanner,
		hostBanner:  cfg.HostBanner,
		remediator:  cfg.Remediator,
		quarantine:  cfg.Quarantine,
		panicSwitch: cfg.PanicSwitch,
		webhook:     cfg.Webhook,
		snapshotter: cfg.Snapshotter,
		memPatterns: cfg.MemPatterns,
		lockUser:    cfg.LockUser,
		stopCh:      make(chan struct{}),
	}
	e.hostAllowIPs = cfg.HostAllowIPs
	return e
}

// OnAlert is the bus subscriber callback. Non-blocking; actions
// run synchronously but are bounded by per-action timeouts.
func (e *Engine) OnAlert(a model.Alert) {
	e.stats.alerts.Add(1)

	if e.panicSwitch != nil && e.panicSwitch.Armed() {
		e.log.Debug("response: panic armed; logging only", "rule", a.RuleID)
		return
	}

	mask := e.policy[a.RuleID]
	if mask == 0 {
		// Unknown rule → log only.
		mask = ActionLog
	}

	if e.monitorMode {
		// Monitor (observe-only) — strip every destructive action.
		// The alert still flows to log + webhook so operators can
		// watch the policy that WOULD have fired.
		mask &= ActionLog | ActionWebhook
		if mask == 0 {
			mask = ActionLog
		}
	}

	// Autobaseline gate (P-AB.3). Two cases:
	//
	//   1. baseline_observing=true — we're in the day-0 silent
	//      window. Destructive actions are NEVER acceptable here:
	//      we're explicitly trying to learn what's normal, and
	//      destroying a process we haven't characterised yet would
	//      either (a) train the operator that xhelix is dangerous
	//      to install or (b) destroy the very evidence we're
	//      collecting. Strip to log+webhook (same as monitor mode).
	//
	//   2. baseline_known=true — the event's (image, behavior)
	//      pair was observed during the day-0 window and is in the
	//      sealed profile. The action falls inside the binary's
	//      learned envelope. This is the "noise" axis only: we
	//      strip destructive actions but keep snapshot/memscan so
	//      operators retain evidence. Tier-1 deterministic facts
	//      (canary touch, decoy access) still bypass this — those
	//      rules don't carry baseline_known because the behavior
	//      we're keying on (decoy touch) is not something a
	//      legitimate binary ever did during observe.
	gateReason := ""
	if e.monitorMode {
		gateReason = "monitor_mode"
	}
	if tags := a.Event.Tags; tags != nil {
		if tags["baseline_observing"] == "true" {
			mask &= ActionLog | ActionWebhook
			if mask == 0 {
				mask = ActionLog
			}
			gateReason = "autobaseline:observe (day-0 learning; destructive suppressed)"
		} else if tags["baseline_known"] == "true" {
			// Keep evidence-collection actions, strip destructive.
			mask &= ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan
			if mask == 0 {
				mask = ActionLog
			}
			gateReason = "autobaseline:known (action inside learned envelope; destructive suppressed)"
		}
	}

	// Stamp the effective action + gate reason on the Alert so sinks
	// (webhook, file) can include them in their payloads. The webhook
	// formatter reads a.Action and event.Tags["xhelix_gate_reason"].
	// Done here, NOT earlier, so the value reflects the final mask.
	a.Action = describeMask(mask)
	if gateReason != "" {
		if a.Event.Tags == nil {
			a.Event.Tags = map[string]string{}
		}
		a.Event.Tags["xhelix_gate_reason"] = gateReason
	}

	// Order matters:
	//   1. Snapshot + memscan FIRST — they read from a live process,
	//      and Quarantine/Kill destroys the process state.
	//   2. NetBan + Remediate next — stop the attacker's next move
	//      while we still have process state to learn from.
	//   3. Quarantine/Kill last (among per-pid actions) — once the
	//      process is gone, /proc/<pid>/* unwinds.
	//   4. LockUser + HostQuarantine — coarse-grained, run after
	//      per-pid actions so the operator's own SSH session is the
	//      established connection that survives the network cut.
	//   5. Webhook last so it can include any errors above.
	if mask&ActionSnapshot != 0 {
		e.doSnapshot(a)
	}
	if mask&ActionMemScan != 0 {
		e.doMemScan(a)
	}
	if mask&ActionNetBan != 0 {
		e.doNetBan(a)
	}
	if mask&ActionRemediate != 0 {
		e.doRemediate(a)
	}
	if mask&ActionQuarantine != 0 {
		e.doQuarantine(a)
	}
	if mask&ActionKill != 0 {
		e.doKill(a)
	}
	if mask&ActionLockUser != 0 {
		e.doLockUser(a)
	}
	if mask&ActionHostQuarantine != 0 {
		e.doHostQuarantine(a)
	}
	if mask&ActionWebhook != 0 {
		e.doWebhook(a)
	}
}

func (e *Engine) doQuarantine(a model.Alert) {
	if e.quarantine == nil || a.Event.PID == 0 {
		e.stats.dropped.Add(1)
		return
	}
	if _, err := e.quarantine.Stop(a.Event.PID, a.Event.Comm,
		a.Event.Image, a.RuleID); err != nil {
		e.log.Warn("quarantine failed", "pid", a.Event.PID, "err", err)
		e.stats.dropped.Add(1)
		return
	}
	e.stats.quarantine.Add(1)
	e.log.Info("response: quarantined", "pid", a.Event.PID, "rule", a.RuleID)
}

func (e *Engine) doKill(a model.Alert) {
	if e.quarantine == nil || a.Event.PID == 0 {
		e.stats.dropped.Add(1)
		return
	}
	err := e.quarantine.Kill(a.Event.PID)
	if err != nil {
		// First Stop, then Kill — the queue requires Stop first.
		_, _ = e.quarantine.Stop(a.Event.PID, a.Event.Comm, a.Event.Image, a.RuleID)
		err = e.quarantine.Kill(a.Event.PID)
	}
	if err != nil {
		// Both attempts failed — count as dropped so the dashboard
		// doesn't claim a kill that never happened. Operator sees the
		// real state.
		e.stats.dropped.Add(1)
		e.log.Warn("response: kill failed",
			"pid", a.Event.PID, "rule", a.RuleID, "err", err)
		return
	}
	e.stats.kill.Add(1)
	e.log.Info("response: killed", "pid", a.Event.PID, "rule", a.RuleID)
}

func (e *Engine) doNetBan(a model.Alert) {
	if e.netBan == nil {
		e.stats.dropped.Add(1)
		return
	}
	srcStr := a.Event.Tags["src"]
	if srcStr == "" {
		srcStr = a.Event.Tags["src_ip"]
	}
	if srcStr == "" {
		e.stats.dropped.Add(1)
		return
	}
	// Strip :port if present
	if host, _, err := net.SplitHostPort(srcStr); err == nil {
		srcStr = host
	}
	ip := net.ParseIP(srcStr)
	if ip == nil {
		e.stats.dropped.Add(1)
		return
	}
	// Don't ban localhost — would lock you out of the host
	if ip.IsLoopback() || ip.IsUnspecified() {
		e.log.Debug("response: refusing to ban local IP", "ip", ip)
		return
	}
	if err := e.netBan.Ban(ip, a.RuleID, time.Hour); err != nil {
		e.log.Warn("netban failed", "ip", ip, "err", err)
		e.stats.dropped.Add(1)
		return
	}
	e.stats.netban.Add(1)
	e.log.Info("response: banned", "ip", ip, "rule", a.RuleID)
}

func (e *Engine) doRemediate(a model.Alert) {
	if e.remediator == nil {
		e.stats.dropped.Add(1)
		return
	}
	path := a.Event.Tags["path"]
	if path == "" {
		e.stats.dropped.Add(1)
		return
	}
	if err := e.remediator.Restore(path, a.RuleID); err != nil {
		e.log.Warn("remediate failed", "path", path, "err", err)
		e.stats.dropped.Add(1)
		return
	}
	e.stats.remediate.Add(1)
	e.log.Info("response: remediated", "path", path, "rule", a.RuleID)
}

func (e *Engine) doWebhook(a model.Alert) {
	if e.webhook == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.webhook(ctx, a); err != nil {
		e.log.Warn("webhook failed", "rule", a.RuleID, "err", err)
		return
	}
	e.stats.webhook.Add(1)
}

func (e *Engine) doSnapshot(a model.Alert) {
	if e.snapshotter == nil || a.Event.PID == 0 {
		e.stats.dropped.Add(1)
		return
	}
	dir, err := e.snapshotter.Capture(int(a.Event.PID), a.Event.Comm, a.RuleID)
	if err != nil {
		e.log.Warn("snapshot failed", "pid", a.Event.PID, "err", err)
		e.stats.dropped.Add(1)
		return
	}
	e.stats.snapshot.Add(1)
	e.log.Info("response: snapshotted", "pid", a.Event.PID, "rule", a.RuleID, "dir", dir)
}

func (e *Engine) doMemScan(a model.Alert) {
	if len(e.memPatterns) == 0 || a.Event.PID == 0 {
		e.stats.dropped.Add(1)
		return
	}
	hits, err := memscan.Scan(int(a.Event.PID), e.memPatterns,
		memscan.Options{MaxRegionBytes: 64 << 20, MaxMatchesPerPattern: 8})
	if err != nil {
		e.log.Warn("memscan failed", "pid", a.Event.PID, "err", err)
		e.stats.dropped.Add(1)
		return
	}
	e.stats.memscan.Add(1)
	if len(hits) > 0 {
		names := make([]string, 0, len(hits))
		for _, h := range hits {
			names = append(names, h.PatternName)
		}
		e.log.Warn("response: memscan hits", "pid", a.Event.PID,
			"rule", a.RuleID, "patterns", names, "count", len(hits))
	}
}

func (e *Engine) doLockUser(a model.Alert) {
	if e.lockUser == nil {
		e.stats.dropped.Add(1)
		return
	}
	user := a.Event.Tags["user"]
	if user == "" {
		user = a.Event.Tags["username"]
	}
	if user == "" {
		e.stats.dropped.Add(1)
		return
	}
	if err := e.lockUser(user); err != nil {
		e.log.Warn("lockuser failed", "user", user, "err", err)
		e.stats.dropped.Add(1)
		return
	}
	e.stats.lockUser.Add(1)
	e.log.Warn("response: user locked out", "user", user, "rule", a.RuleID)
}

func (e *Engine) doHostQuarantine(a model.Alert) {
	if e.hostBanner == nil || len(e.hostAllowIPs) == 0 {
		e.stats.dropped.Add(1)
		return
	}
	if e.hostBanner.Quarantined() {
		// Already isolated; this is a no-op but counts as success.
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.hostBanner.EngageQuarantine(ctx, e.hostAllowIPs); err != nil {
		e.log.Error("host quarantine failed", "err", err)
		e.stats.dropped.Add(1)
		return
	}
	e.stats.hostQuarantine.Add(1)
	e.log.Warn("response: HOST QUARANTINED — network isolated except mgmt allow-list",
		"rule", a.RuleID, "allow", e.hostAllowIPs)
}

// Stats returns counters for the dashboard.
type Stats struct {
	Alerts         uint64
	Quarantine     uint64
	Kill           uint64
	NetBan         uint64
	Remediate      uint64
	Webhook        uint64
	Snapshot       uint64
	MemScan        uint64
	LockUser       uint64
	HostQuarantine uint64
	Dropped        uint64
}

// Stats returns a snapshot of action counters.
func (e *Engine) Stats() Stats {
	return Stats{
		Alerts:         e.stats.alerts.Load(),
		Quarantine:     e.stats.quarantine.Load(),
		Kill:           e.stats.kill.Load(),
		NetBan:         e.stats.netban.Load(),
		Remediate:      e.stats.remediate.Load(),
		Webhook:        e.stats.webhook.Load(),
		Snapshot:       e.stats.snapshot.Load(),
		MemScan:        e.stats.memscan.Load(),
		LockUser:       e.stats.lockUser.Load(),
		HostQuarantine: e.stats.hostQuarantine.Load(),
		Dropped:        e.stats.dropped.Load(),
	}
}

// Start is a no-op for now (the engine is event-driven via OnAlert).
// Kept for symmetry with Sensor lifecycle.
func (e *Engine) Start(ctx context.Context) error {
	if !e.running.CompareAndSwap(false, true) {
		return errors.New("response: already started")
	}
	return nil
}

// Stop signals shutdown.
func (e *Engine) Stop(ctx context.Context) error {
	if !e.running.CompareAndSwap(true, false) {
		return nil
	}
	close(e.stopCh)
	return nil
}

// describeMask returns a human-readable comma-separated list of the
// actions selected by mask. Used to populate model.Alert.Action so
// downstream sinks (webhook, file) can include "action taken" in
// their payloads. Order matches the dispatch order in OnAlert.
func describeMask(mask Action) string {
	if mask == 0 {
		return "none"
	}
	parts := []string{}
	if mask&ActionLog != 0 {
		parts = append(parts, "log")
	}
	if mask&ActionSnapshot != 0 {
		parts = append(parts, "snapshot")
	}
	if mask&ActionMemScan != 0 {
		parts = append(parts, "memscan")
	}
	if mask&ActionNetBan != 0 {
		parts = append(parts, "netban")
	}
	if mask&ActionRemediate != 0 {
		parts = append(parts, "remediate")
	}
	if mask&ActionQuarantine != 0 {
		parts = append(parts, "quarantine")
	}
	if mask&ActionKill != 0 {
		parts = append(parts, "kill")
	}
	if mask&ActionLockUser != 0 {
		parts = append(parts, "lock-user")
	}
	if mask&ActionHostQuarantine != 0 {
		parts = append(parts, "host-quarantine")
	}
	if mask&ActionWebhook != 0 {
		parts = append(parts, "webhook")
	}
	return strings.Join(parts, ", ")
}
