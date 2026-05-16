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

// Default returns a sensible day-1 policy: Critical decoy / file /
// cred / memory rules quarantine the offending pid; Critical net
// rules ban the src_ip; high-severity FIM rules trigger remediate.
//
// Operators tune this in config.yaml; this is the safe baseline.
func Default() Policy {
	return Policy{
		// Decoys → ban the src + quarantine if a local pid was
		// involved (e.g., honey service connect from inside the host)
		"decoy_file_opened":         ActionLog | ActionWebhook | ActionQuarantine,
		"decoy_service_connect":     ActionLog | ActionWebhook | ActionNetBan,
		"decoy_canary_token_used":   ActionLog | ActionWebhook | ActionNetBan,
		"decoy_dns_resolved":        ActionLog | ActionWebhook,

		// Memory exploit primitives — snapshot, scan memory, quarantine
		"mem_mprotect_rwx":          ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan | ActionQuarantine,
		"mem_canary_fail":           ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan | ActionQuarantine,
		"mem_kernel_anomaly":        ActionLog | ActionWebhook | ActionSnapshot,
		"mem_lkrg_violation":        ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan | ActionQuarantine,

		// Process patterns
		"shell_with_socket_fd":      ActionLog | ActionWebhook | ActionSnapshot | ActionQuarantine,
		"memfd_run_pattern":         ActionLog | ActionWebhook | ActionSnapshot | ActionMemScan | ActionQuarantine,
		"web_server_spawns_shell":   ActionLog | ActionWebhook | ActionSnapshot | ActionQuarantine,
		"binary_runs_from_tmp":      ActionLog | ActionWebhook | ActionSnapshot,
		"uid0_no_transition":        ActionLog | ActionWebhook | ActionSnapshot | ActionQuarantine,
		"ptrace_sensitive_target":   ActionLog | ActionWebhook | ActionSnapshot | ActionQuarantine,

		// File integrity → remediate from chain when possible
		"tamper_passwd":             ActionLog | ActionWebhook | ActionRemediate,
		"tamper_shadow":             ActionLog | ActionWebhook | ActionRemediate,
		"ld_so_preload_modified":    ActionLog | ActionWebhook | ActionRemediate,
		"pam_module_drop":           ActionLog | ActionWebhook | ActionRemediate,
		"ssh_key_added_root":        ActionLog | ActionWebhook | ActionRemediate,
		"cron_new_unit":             ActionLog | ActionWebhook,

		// Network — ban the source
		"outbound_to_known_bad":     ActionLog | ActionWebhook | ActionNetBan,
		"metadata_svc_unexpected":   ActionLog | ActionWebhook,
		"netids.dga":                ActionLog | ActionWebhook,

		// Self-defence — ban + quarantine
		"bpf_syscall_unexpected":    ActionLog | ActionWebhook | ActionQuarantine,

		// Brute-force correlation — ban + lock the account that just
		// "succeeded" since the success itself is the indicator.
		"ssh_brute_then_success":    ActionLog | ActionWebhook | ActionNetBan | ActionLockUser,

		// v0.0.9 elite-tier
		"beacon.periodic_callback":  ActionLog | ActionWebhook | ActionSnapshot | ActionNetBan,
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
