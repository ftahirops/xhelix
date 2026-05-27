package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/activity"
	"github.com/xhelix/xhelix/pkg/alert"
	"github.com/xhelix/xhelix/pkg/alertdedupe"
	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/beacon"
	"github.com/xhelix/xhelix/pkg/brandcheck"
	"github.com/xhelix/xhelix/pkg/catalog"
	"github.com/xhelix/xhelix/pkg/cgroupclass"
	"github.com/xhelix/xhelix/pkg/chain"
	"github.com/xhelix/xhelix/pkg/coldstore"
	"github.com/xhelix/xhelix/pkg/config"
	"github.com/xhelix/xhelix/pkg/configaudit"
	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/snicheck"
	"github.com/xhelix/xhelix/pkg/assetclass"
	"github.com/xhelix/xhelix/pkg/brp"
	brpphase "github.com/xhelix/xhelix/pkg/brp/phase"
	"github.com/xhelix/xhelix/pkg/brp/writerattr"
	"github.com/xhelix/xhelix/pkg/egressguard"
	"github.com/xhelix/xhelix/pkg/incidentgraph"
	"github.com/xhelix/xhelix/pkg/pkgmgr"
	"github.com/xhelix/xhelix/pkg/secrettaint"
	"github.com/xhelix/xhelix/pkg/sshbrute"
	"github.com/xhelix/xhelix/pkg/source"
	"github.com/xhelix/xhelix/pkg/verify"
	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/daemon/forensicingest"
	"github.com/xhelix/xhelix/pkg/daemon/wire"
	"github.com/xhelix/xhelix/pkg/forensicapi"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
	"github.com/xhelix/xhelix/pkg/protectsvcapi"
	"github.com/xhelix/xhelix/pkg/appident"
	"github.com/xhelix/xhelix/pkg/destclass"
	"github.com/xhelix/xhelix/pkg/diskwarden"
	"github.com/xhelix/xhelix/pkg/dnsexfil"
	"github.com/xhelix/xhelix/pkg/egressmon"
	"github.com/xhelix/xhelix/pkg/vhostcorr"
	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/execguard"
	"github.com/xhelix/xhelix/pkg/forensic"
	"github.com/xhelix/xhelix/pkg/geoip"
	"github.com/xhelix/xhelix/pkg/idlehint"
	"github.com/xhelix/xhelix/pkg/imagecache"
	"github.com/xhelix/xhelix/pkg/integrity"
	"github.com/xhelix/xhelix/pkg/intel"
	"github.com/xhelix/xhelix/pkg/kintegrity"
	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/lockout"
	"github.com/xhelix/xhelix/pkg/memscan"
	"github.com/xhelix/xhelix/pkg/ml"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/netban"
	"github.com/xhelix/xhelix/pkg/pipeline"
	"github.com/xhelix/xhelix/pkg/posture"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/remediate"
	"github.com/xhelix/xhelix/pkg/response"
	"github.com/xhelix/xhelix/pkg/rules"
	"github.com/xhelix/xhelix/pkg/autobaseline"
	"github.com/xhelix/xhelix/pkg/burstdet"
	"github.com/xhelix/xhelix/pkg/credbroker"
	"github.com/xhelix/xhelix/pkg/runtimeallow"
	"github.com/xhelix/xhelix/pkg/vendorcatalog"
	"github.com/xhelix/xhelix/pkg/vhostdiscovery"
	"github.com/xhelix/xhelix/pkg/sbom"
	"github.com/xhelix/xhelix/pkg/bpflsm"
	"github.com/xhelix/xhelix/pkg/landlock"
	"github.com/xhelix/xhelix/pkg/cdndetect"
	"github.com/xhelix/xhelix/pkg/containment"
	"github.com/xhelix/xhelix/pkg/endpointscore"
	"github.com/xhelix/xhelix/pkg/firerate"
	"github.com/xhelix/xhelix/pkg/flowstats"
	"github.com/xhelix/xhelix/pkg/longwindow"
	"github.com/xhelix/xhelix/pkg/memhardening"
	posturehost "github.com/xhelix/xhelix/pkg/posture/host"
	"github.com/xhelix/xhelix/pkg/selfprotect"
	"github.com/xhelix/xhelix/pkg/selfseccomp"
	"github.com/xhelix/xhelix/pkg/session"
	"github.com/xhelix/xhelix/pkg/shmguard"
	"github.com/xhelix/xhelix/pkg/store"
	storehistory "github.com/xhelix/xhelix/pkg/store/history"
	"github.com/xhelix/xhelix/pkg/suppression"
	"github.com/xhelix/xhelix/pkg/tamperguard"
	"github.com/xhelix/xhelix/pkg/threatintel"
	"github.com/xhelix/xhelix/pkg/version"
	"github.com/xhelix/xhelix/pkg/yara"
	"github.com/xhelix/xhelix/sensors"
	"github.com/xhelix/xhelix/sensors/decoy"
	"github.com/xhelix/xhelix/sensors/dnsresolver"
	dpisensor "github.com/xhelix/xhelix/sensors/dpi"
	ebpfsensor "github.com/xhelix/xhelix/sensors/ebpf"
	fimsensor "github.com/xhelix/xhelix/sensors/fim"
	"github.com/xhelix/xhelix/sensors/heartbeat"
	"github.com/xhelix/xhelix/sensors/identity"
	"github.com/xhelix/xhelix/sensors/lsmaudit"
	"github.com/xhelix/xhelix/sensors/memory"
	memdiffsensor "github.com/xhelix/xhelix/sensors/memdiff"
	procmemsensor "github.com/xhelix/xhelix/sensors/procmem"
	procscrapesensor "github.com/xhelix/xhelix/sensors/procscrape"
	netidssensor "github.com/xhelix/xhelix/sensors/netids"
	"github.com/xhelix/xhelix/ui/web"
)

func newRunCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the xhelix daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "/etc/xhelix/xhelix.yaml",
		"path to configuration file")
	return cmd
}

func runDaemon(parent context.Context, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := newLogger(cfg.Logging)

	// Config-audit witness — every consumer of a config field calls
	// cfgAudit.Witness() so we can detect declared-but-not-consumed
	// knobs at startup. Fixes the recurring class of bug logged in
	// ERRORS.md (FileSink rotation, hot.db retention, etc.).
	cfgAudit := configaudit.New()
	// Pre-declare known keys so they only show up as "unwitnessed"
	// when no consumer registers, not "unknown".
	for _, k := range []string{
		"agent.state_dir", "agent.heartbeat_url", "agent.heartbeat_interval",
		"storage.hot.path", "storage.hot.retention_hours", "storage.hot.max_size_mb",
		"storage.warm.enabled", "storage.cold.enabled",
		"ruleset.bundled", "ruleset.custom_dir", "ruleset.reload_on_change",
		"alerts.severity_threshold",
		"response.enabled", "response.soak_days",
		"netban.enabled", "netban.use_nftables",
		"remediate.enabled", "remediate.backup_dir",
		"intel.enabled",
		"chain.enabled", "chain.dir", "chain.key_path",
		"logging.level", "logging.format",
		// P-RF.9b takeover knobs
		"takeover.active", "takeover.tick_interval", "takeover.min_score",
		"takeover.bastion_available", "takeover.off_host_mirror",
		// P-RF.9d protected-services loader
		"protected_services.enabled", "protected_services.services",
		// P-RF.9e forensic ingest
		"forensic_ingest.enabled", "forensic_ingest.dir",
		"forensic_ingest.scan_interval", "forensic_ingest.poll_interval",
	} {
		cfgAudit.Declare(k)
	}
	// Singleton check — refuse to start if another xhelix is already
	// running, identified by the PID file. Added P-PS.25 after the
	// mixed-traffic drill found three daemons racing on hot.db.
	// PID-file write happens here so subsequent xhelix's see us.
	if pidPath := cfg.Agent.PIDFile; pidPath != "" {
		if data, err := os.ReadFile(pidPath); err == nil {
			pidStr := strings.TrimSpace(string(data))
			if pidStr != "" {
				if existing, err := strconv.Atoi(pidStr); err == nil && existing > 0 {
					if commData, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", existing)); err == nil {
						if strings.TrimSpace(string(commData)) == "xhelix" {
							return fmt.Errorf("xhelix already running (pid %d via %s); refuse to start second instance", existing, pidPath)
						}
					}
				}
			}
		}
		if err := os.MkdirAll(filepath.Dir(pidPath), 0o750); err == nil {
			if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
				log.Warn("could not write pidfile", "path", pidPath, "err", err)
			} else {
				defer os.Remove(pidPath)
			}
		}
		cfgAudit.Witness("agent.pid_file", "singleton-check")
	}

	log.Info("xhelix starting",
		"preset", cfg.Preset,
		"config", cfgPath,
		"version", version.Version,
		"commit", version.Commit,
	)

	// Phase G.1 unconditional process hardening — runs even when
	// selfprotect.Enabled=false because the prctls have no
	// operational cost and their absence is a security regression.
	selfprotect.ApplyProcessHardening(log)

	// Phase G.2 self-seccomp filter. Default mode = "off"; operator
	// promotes via hardening.seccomp.mode in xhelix.yaml. Filter is
	// applied AFTER prctl(NO_NEW_PRIVS) above and BEFORE any sensors
	// start — keeps the kernel's seccomp_data.arch check meaningful
	// and avoids racing the eBPF sensor's startup syscalls.
	{
		mode := selfseccomp.ParseMode(cfg.Hardening.Seccomp.Mode)
		if mode != selfseccomp.ModeOff {
			a := selfseccomp.BaselineAllowList()
			a.Mode = mode
			if err := selfseccomp.Apply(a, log); err != nil {
				log.Error("selfseccomp: install failed; continuing without filter",
					"mode", mode.String(), "err", err)
			}
		} else {
			log.Info("selfseccomp: mode=off (default); no filter installed",
				"hint", "set hardening.seccomp.mode: audit in /etc/xhelix/xhelix.yaml to start soak")
		}
	}

	// Phase G.3 Linux Landlock filesystem ACL. Default mode = "off";
	// operator promotes via hardening.landlock.mode in xhelix.yaml.
	// Applied AFTER seccomp (which itself runs after G.1 prctls).
	// Landlock is irreversible per-process in enforce mode — same
	// self-DoS risk as G.2 seccomp enforce. Use dry-run first to
	// preview the allowlist.
	{
		mode := landlock.ParseMode(cfg.Hardening.Landlock.Mode)
		if mode != landlock.ModeOff {
			p := landlock.DefaultPolicy()
			p.ReadOnly = append(p.ReadOnly, cfg.Hardening.Landlock.ExtraReadOnly...)
			p.ReadWrite = append(p.ReadWrite, cfg.Hardening.Landlock.ExtraReadWrite...)
			if err := landlock.Apply(p, mode, log); err != nil {
				log.Error("landlock: install failed; continuing without restriction",
					"mode", mode.String(), "err", err)
			}
		} else {
			log.Info("landlock: mode=off (default); no filesystem restriction",
				"hint", "set hardening.landlock.mode: dry-run in /etc/xhelix/xhelix.yaml to preview allowlist; then enforce after review")
		}
	}

	// Phase G.5 host posture snapshot. Read-only; logs score + any
	// FAIL rows so operators see the hardening gap on every restart.
	{
		rep := posturehost.Inspect()
		pass, warn, fail, unk := rep.Counts()
		log.Info("host-posture: snapshot",
			"score", rep.Score(),
			"pass", pass, "warn", warn, "fail", fail, "unknown", unk)
		for _, c := range rep.Checks {
			if c.Status == posturehost.StatusFail {
				log.Warn("host-posture: FAIL",
					"check", c.Name, "value", c.Value,
					"expected", c.Expected, "hint", c.Hint)
			}
		}
	}

	// Phase G.4 Go-runtime memory hardening. No-op if config zero-valued.
	memhardening.Apply(memhardening.Config{
		MemoryLimitMB: cfg.Hardening.MemHardening.MemoryLimitMB,
		GCPercent:     cfg.Hardening.MemHardening.GCPercent,
	}, log)

	// Phase I BPF-LSM synchronous deny. Default mode = "off".
	// HARD prerequisite: kernel cmdline `lsm=...,bpf`. Probe() refuses
	// to load if absent and returns an operator-actionable error.
	// Fail-open: on any load/attach error, log + continue without
	// BPF-LSM (daemon doesn't crash).
	{
		mode := bpflsm.ParseMode(cfg.Hardening.BPFLSM.Mode)
		if mode != bpflsm.ModeOff {
			progPath := cfg.Hardening.BPFLSM.ObjectPath
			if progPath == "" {
				progPath = "/usr/lib/xhelix/xhelix-lsm.o"
			}
			loader, err := bpflsm.Apply(progPath, mode, log)
			if err != nil {
				log.Error("bpflsm: install failed; continuing without BPF-LSM",
					"mode", mode.String(), "err", err)
			} else if loader != nil {
				// Seed the deny map with operator-supplied paths.
				for _, p := range cfg.Hardening.BPFLSM.DenyPaths {
					if err := loader.DenyPath(p); err != nil {
						log.Warn("bpflsm: seed deny path failed", "path", p, "err", err)
					} else {
						log.Info("bpflsm: deny path seeded", "path", p)
					}
				}
				// Loader lives for daemon lifetime; cilium/ebpf
				// closes the collection when GC'd. Explicit close
				// path is via the operator CLI in a follow-on.
				_ = loader
			}
		} else {
			active, _ := bpflsm.Probe()
			log.Info("bpflsm: mode=off (default); no synchronous deny",
				"kernel_bpf_lsm_active", active,
				"hint", "set hardening.bpflsm.mode: load in /etc/xhelix/xhelix.yaml to preview (requires kernel lsm=...,bpf)")
		}
	}

	// Self-protection
	var protector *selfprotect.Protector
	if cfg.SelfProtect.Enabled {
		protector = selfprotect.NewProtector(cfg.Agent.StateDir, log)
		protector.Harden()
		if cfg.SelfProtect.Immutable {
			if err := protector.SetImmutable(); err != nil {
				log.Warn("selfprotect: immutable failed", "err", err)
			}
		}
		if !selfprotect.IsRunningUnderSystemd() {
			log.Warn("selfprotect: not running under systemd; recommend service unit for restart protection")
		}
	}

	// Hot store
	hotPath := cfg.Storage.Hot.Path
	if hotPath == "" {
		hotPath = ":memory:"
	}
	hot, err := store.OpenHot(hotPath)
	if err != nil {
		log.Warn("hot store unavailable; falling back to in-memory", "err", err)
		hot, err = store.OpenHot(":memory:")
		if err != nil {
			return fmt.Errorf("open in-memory store: %w", err)
		}
	}
	defer hot.Close()
	cfgAudit.Witness("storage.hot.path", "OpenHot")

	// Alert sinks
	sinks := buildSinks(cfg.Alerts.Sinks, log)
	// Always-on ring buffer for the TUI Alerts view. Independent of
	// operator-configured sinks; holds last 1024 alerts in memory.
	alertRing := alert.NewRingSink(1024)
	sinks = append(sinks, alertRing)
	// Soak tracker — single instance shared between the bus sink
	// (advances Track on every alert), the web UI, and the
	// LocalAPI handler that xhelixctl queries. Persisted to disk
	// every minute so per-rule clean-day counters survive restart.
	soakDays := uint(30)
	if cfg.Response.SoakDays > 0 {
		soakDays = cfg.Response.SoakDays
	}
	soak := enforce.NewSoak(soakDays)
	soakPath := filepath.Join(cfg.Agent.StateDir, "soak.json")
	if err := soak.LoadFrom(soakPath); err != nil {
		log.Warn("soak load failed (starting fresh)", "err", err, "path", soakPath)
	}
	ss := newSoakSink(soak, soakPath)
	sinks = append(sinks, ss)
	bus := alert.NewBus(sinks, 4096, log)

	ctx, cancel := signal.NotifyContext(parent,
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	go ss.runFlusher(ctx, time.Minute)

	// Phase-1 evidence-truth primitives: EAC + lineage + canonical self.
	// Constructed early so they're available to every subsystem.
	foundation, err := newFoundationContext(ctx)
	if err != nil {
		return fmt.Errorf("foundation: %w", err)
	}
	defer foundation.Stop()
	log.Info("foundation primitives started",
		"self_pid", foundation.SelfProcKey.PID,
		"self_start_ticks", foundation.SelfProcKey.StartTicks)

	// Phase C.3: apply operator-configured egressguard mode. Foundation
	// constructed the guard in OBSERVE mode by default; the config can
	// promote to SHADOW or ENFORCE. Re-construction is needed because
	// Mode() is locked at NewGuard time (build-spec discipline — mode
	// changes force operator awareness).
	if foundation.EgressGuard != nil && cfg.Hardening.Egressguard.Mode != "" {
		mode := parseEgressguardMode(cfg.Hardening.Egressguard.Mode)
		if mode != egressguard.ModeObserve {
			backend, name := egressguard.SelectBackend(mode)
			profiles := egressguard.NewBRPProfileLookup(foundation.BRPMatcher)
			foundation.EgressGuard = egressguard.NewGuard(backend, profiles, mode)
			log.Info("egressguard mode promoted from config",
				"mode", mode.String(), "backend", name)
		}
	}

	// Bus pump
	go bus.Run(ctx)

	// Phase H.2.1 — long-window threshold poller wired to the bus.
	// Foundation owns the SQLite store + sweeper; here we start the
	// per-minute evaluator with an Emit closure that publishes
	// model.Alert into the bus so the full alert pipeline (chain
	// log, response engine, sinks) sees threshold breaches.
	if foundation != nil && foundation.LongWindow != nil {
		go func() {
			p := &longwindow.Poller{
				Store: foundation.LongWindow,
				Rules: LongWindowRules(),
				Tick:  time.Minute,
				Log:   log,
				Emit: func(h longwindow.Hit) {
					bus.Send(model.Alert{
						RuleID: h.Rule.ID,
						Reason: h.Rule.Desc,
						Mode:   model.ModeDetect,
						Event: model.Event{
							Time:     h.At,
							Sensor:   "longwindow",
							Severity: model.SeverityHigh,
							Image:    h.Group,
							Tags: map[string]string{
								"kind":   "long_window_threshold",
								"image":  h.Group,
								"count":  strconv.Itoa(h.Count),
								"window": h.Rule.Window.String(),
							},
						},
					})
				},
			}
			stop := make(chan struct{})
			go func() { <-ctx.Done(); close(stop) }()
			p.Run(stop)
		}()
	}

	// Enforcement plane
	quarantine := enforce.NewQuarantine(enforce.DefaultSignalFn)
	// soak constructed earlier alongside the bus sinks.
	_ = soak
	panicSwitch := enforce.NewPanicSwitch("")

	// Session tracker — "who is doing what" timeline.
	var sessionTracker *session.Tracker
	if cfg.Session.Enabled {
		max := cfg.Session.MaxEventsPerSession
		if max == 0 {
			max = 1024
		}
		sessionTracker = session.New(max)
		log.Info("session tracker enabled", "max_events", max)
	}

	// Network ban — XDP drop set + nftables. The XDP map handle is
	// attached after the eBPF backend starts (see below).
	var banner *netban.Banner
	if cfg.Netban.Enabled {
		banner = netban.NewBanner(nil, cfg.Netban.UseNFTables)
		if cfg.Netban.UseNFTables {
			if err := banner.EnsureNFT(ctx); err != nil {
				log.Warn("netban: nft setup failed (continuing without nft)", "err", err)
			}
		}
		log.Info("netban enabled", "nft", cfg.Netban.UseNFTables)
	}

	// File remediator — restore tampered files from a backup vault.
	var remediator *remediate.Remediator
	if cfg.Remediate.Enabled {
		bdir := cfg.Remediate.BackupDir
		if bdir == "" {
			bdir = filepath.Join(cfg.Agent.StateDir, "remediate", "backup")
		}
		qdir := cfg.Remediate.QuarantineDir
		if qdir == "" {
			qdir = filepath.Join(cfg.Agent.StateDir, "remediate", "quarantine")
		}
		var rerr error
		remediator, rerr = remediate.New(bdir, qdir)
		if rerr != nil {
			log.Warn("remediator init failed", "err", rerr)
			remediator = nil
		} else {
			for _, p := range cfg.Remediate.BackupPaths {
				if err := remediator.Backup(p); err != nil {
					log.Warn("remediator backup failed", "path", p, "err", err)
				} else {
					log.Info("remediator backup ok", "path", p)
				}
			}
		}
	}

	// Webhook for the response engine.
	var webhookSink *alert.WebhookSink
	if cfg.Webhook.Enabled && cfg.Webhook.URL != "" {
		webhookSink = alert.NewWebhookSink(cfg.Webhook.URL, hostnameOrEmpty())
		log.Info("webhook enabled", "url", cfg.Webhook.URL)
	}

	// Forensic snapshotter — captures /proc/<pid>/* before kill so the
	// IR team has evidence after the offending process is gone.
	var snapshotter *forensic.Snapshotter
	if cfg.ForensicIngest.Enabled {
		dir := cfg.Forensic.EvidenceDir
		if dir == "" {
			dir = filepath.Join(cfg.Agent.StateDir, "evidence")
		}
		s, ferr := forensic.New(dir)
		if ferr != nil {
			log.Warn("forensic snapshotter init failed", "err", ferr)
		} else {
			snapshotter = s
			log.Info("forensic snapshotter enabled", "dir", dir)
		}
	}

	// Memscan patterns — used by ActionMemScan to look for shellcode
	// signatures in suspect process memory before kill.
	var memPatterns []memscan.Pattern
	if cfg.MemScan.Enabled {
		memPatterns = memscan.DefaultPatterns()
		log.Info("memscan enabled", "patterns", len(memPatterns))
	}

	// Account lockout function — disables a local user when an alert
	// names them in tags.user/username.
	var lockUserFn response.LockUserFn
	if cfg.Lockout.Enabled {
		lockUserFn = func(user string) error {
			r := lockout.Lockout(user)
			if len(r.Errors) > 0 {
				return fmt.Errorf("lockout partial: %v", r.Errors)
			}
			return nil
		}
		log.Info("account lockout enabled")
	}

	// Active response engine — turns alerts into actions.
	var respEngine *response.Engine
	if cfg.Response.Enabled {
		respEngine = response.New(response.Config{
			NetBanner:    bannerOrNil(banner),
			HostBanner:   hostBannerOrNil(banner),
			HostAllowIPs: cfg.HostQuarantine.AllowIPs,
			Remediator:   remediatorOrNil(remediator),
			Snapshotter:  snapshotterOrNil(snapshotter),
			MemPatterns:  memPatterns,
			LockUser:     lockUserFn,
			Quarantine:   quarantine,
			PanicSwitch:  panicSwitch,
			Webhook: func(c context.Context, a model.Alert) error {
				if webhookSink == nil {
					return nil
				}
				return webhookSink.Send(c, a)
			},
			Logger:      log,
			MonitorMode:  cfg.Response.MonitorMode,
			EnforceRules: cfg.Response.EnforceRules,
		})
		_ = respEngine.Start(ctx)
		log.Info("response engine enabled",
			"monitor_mode", cfg.Response.MonitorMode)
	}

	// P-RF.9b daemon wiring: planner pipeline runs in shadow mode
	// alongside the legacy response engine. The planner observes
	// every alert as a takeover.Signal, computes ActionPlans, and
	// (in shadow mode) logs what the Executor would have done. The
	// legacy respEngine remains authoritative for actions. Operator
	// flips to active mode via takeover.active=true once they're
	// satisfied that the plans match policy on their own traffic.
	var plannerWiring *wire.PlannerWiring
	if respEngine != nil {
		plannerWiring = wire.New(wire.Config{
			Log:                    log,
			Active:                 cfg.Takeover.Active,
			TickInterval:           cfg.Takeover.TickInterval,
			MinScoreToPlan:         cfg.Takeover.MinScore,
			BastionAvailable:       cfg.Takeover.BastionAvailable,
			OffHostMirrorAvailable: cfg.Takeover.OffHostMirror,
		}, respEngine)
		go plannerWiring.Tick(ctx)
		cfgAudit.Witness("takeover.active", "PlannerWiring")
		cfgAudit.Witness("takeover.tick_interval", "PlannerWiring")
		cfgAudit.Witness("takeover.min_score", "PlannerWiring")
		cfgAudit.Witness("takeover.bastion_available", "PlannerWiring")
		cfgAudit.Witness("takeover.off_host_mirror", "PlannerWiring")
		log.Info("planner wiring enabled",
			"active", cfg.Takeover.Active,
			"tick", cfg.Takeover.TickInterval)
	}

	// Exec-deny guard — fanotify FAN_OPEN_EXEC_PERM to prevent execve
	// of deny-listed binaries before they ever run. Independent of the
	// alert pipeline; runs continuously.
	//
	// Integrity verifier vars declared at this scope so the LocalAPI
	// handlers registered later in runDaemon can capture them.
	var integrityVerifier *integrity.Verifier
	var integrityBaseline *integrity.Baseline
	var execGuard *execguard.Guard
	if cfg.ExecGuard.Enabled {
		execGuard = execguard.New(func(path string, pid int, d execguard.Decision, reason string) {
			if d == execguard.Deny {
				log.Warn("execguard: DENIED", "path", path, "pid", pid, "reason", reason)
			}
		})
		rules := buildExecGuardRules(cfg.ExecGuard.DenyPaths)
		if len(rules) == 0 {
			rules = execguard.DefaultRules()
		}
		execGuard.SetRules(rules)
		mounts := cfg.ExecGuard.MountPoints
		if len(mounts) == 0 {
			mounts = []string{"/"}
		}
		if err := execGuard.Start(ctx, mounts); err != nil {
			log.Warn("execguard start failed (continuing without exec-deny)", "err", err)
			execGuard = nil
		} else {
			log.Info("execguard enabled", "rules", len(rules), "mounts", mounts)
		}
	}

	// B1+B2+B3 — integrity baseline + verifier. Independent of
	// execguard: the baseline + Verifier exists whenever
	// cfg.Integrity.Enabled, even with execguard off. The execve
	// hook (B3) only activates when execguard is ALSO on.
	if cfg.Integrity.Enabled {
		dbPath := cfg.Integrity.BaselineDB
		if dbPath == "" {
			dbPath = filepath.Join(cfg.Agent.StateDir, "integrity-baseline.db")
		}
		b, err := integrity.Open(dbPath)
		if err != nil {
			log.Warn("integrity baseline open failed (B3 disabled)", "err", err)
		} else {
			integrityBaseline = b
			tester := integrity.NewTester()
			v := integrity.NewVerifier(b, tester, log)
			if !cfg.Integrity.AcceptTOFU {
				v.AcceptTOFU = false
			}
			integrityVerifier = v
			mode := execguard.IntegrityDetect
			switch cfg.Integrity.Mode {
			case "enforce":
				mode = execguard.IntegrityEnforce
			case "off":
				mode = execguard.IntegrityOff
			}
			if execGuard != nil {
				execGuard.SetIntegrity(v, mode)
			}
			cfgAudit.Witness("integrity.enabled", "IntegrityVerifier")
			cfgAudit.Witness("integrity.mode", "IntegrityVerifier")
			cfgAudit.Witness("integrity.baseline_db", "IntegrityVerifier")
			cfgAudit.Witness("integrity.accept_tofu", "IntegrityVerifier")
			log.Info("integrity verifier enabled (B1+B2+B3 substrate)",
				"mode", cfg.Integrity.Mode, "db", dbPath,
				"accept_tofu", v.AcceptTOFU,
				"execguard_hook", execGuard != nil)
			// Background: if baseline is empty, kick a build.
			go func() {
				n, _ := b.Count()
				if n > 0 {
					log.Info("integrity baseline non-empty, skipping initial walk", "rows", n)
					return
				}
				log.Info("integrity baseline empty — walking critical paths in background")
				pr, err := integrity.Build(ctx, b, integrity.WalkOptions{
					Paths: cfg.Integrity.Paths, Log: log,
				})
				if err != nil {
					log.Warn("integrity baseline build returned error", "err", err)
				}
				log.Info("integrity baseline build done",
					"files_hashed", pr.FilesHashed, "skipped", pr.FilesSkipped,
					"bytes_mb", pr.BytesHashed/(1024*1024))
			}()
		}
	}
	_ = integrityVerifier
	_ = integrityBaseline

	// v0.0.9: elite-tier detectors. Each is a standalone goroutine
	// that emits synthetic Alerts back through `emit` when its model
	// trips. We declare the detector handles here so the closure
	// below sees them; we wire emit-back via a small helper after
	// emit is defined.
	var beaconDet *beacon.Detector
	if cfg.Beacon.Enabled {
		bcfg := beacon.Config{
			MinSamples:  cfg.Beacon.MinSamples,
			MaxJitterCV: cfg.Beacon.MaxJitterCV,
		}
		if cfg.Beacon.MinSpanSeconds > 0 {
			bcfg.MinSpan = time.Duration(cfg.Beacon.MinSpanSeconds) * time.Second
		}
		if len(cfg.Beacon.AllowList) > 0 {
			bcfg.AllowList = map[string]bool{}
			for _, ip := range cfg.Beacon.AllowList {
				bcfg.AllowList[ip] = true
			}
		}
		beaconDet = beacon.New(bcfg)
		log.Info("beacon detector enabled")
	}
	var dnsexfilDet *dnsexfil.Detector
	if cfg.DNSExfil.Enabled {
		dcfg := dnsexfil.Config{
			MinQueriesPerWindow: cfg.DNSExfil.MinQueriesPerWindow,
			MaxLabelLen:         cfg.DNSExfil.MaxLabelLen,
			MaxEntropy:          cfg.DNSExfil.MaxEntropy,
			MaxTxtFraction:      cfg.DNSExfil.MaxTxtFraction,
		}
		if cfg.DNSExfil.WindowSeconds > 0 {
			dcfg.Window = time.Duration(cfg.DNSExfil.WindowSeconds) * time.Second
		}
		dnsexfilDet = dnsexfil.New(dcfg)
		log.Info("dns-exfil detector enabled")
	}

	// Per-binary baseline aggregator + JSONL store. Phase 1: just
	// record. Phase 2 will add scoring; phase 3 will ship aggregates
	// to a fleet hub for cross-host learning.
	var baselineAgg *baseline.Aggregator
	var baselineStore *baseline.Store
	var baselineScorer *baseline.Scorer
	var baselineRate *baseline.RateDetector
	var baselineUploader *baseline.Uploader
	// emit is the unified alert publisher. Declared as a var here so
	// goroutines created before its definition (e.g. the baseline
	// scoring loop, which is started during baseline init) capture
	// the variable; the closure assignment happens later in runDaemon
	// once netban / response / threat-intel are wired.
	var emit func(model.Alert)

	// Phase H.3 per-rule fire-rate cap. Wrapped into the emit closure
	// below. DefaultPolicy (30/min) applies to any rule without a
	// custom budget. Suppression count is exposed via
	// `xhelixctl firerate stats`.
	// Built-in baseline policy + operator overrides from cfg.Firerate.
	firerateMap := map[string]firerate.Policy{
		// Long-window threshold rules already self-suppress via their
		// own cooldown; cap further at 6/hour to keep the chain log
		// readable if the cooldown is short.
		"h2.slow_egress_fanout_24h": {MaxFires: 6, Window: time.Hour, Cooldown: 10 * time.Minute},
	}
	for ruleID, pol := range cfg.Firerate {
		firerateMap[ruleID] = firerate.Policy{
			MaxFires: pol.MaxFires,
			Window:   pol.Window,
			Cooldown: pol.Cooldown,
		}
	}
	fireLimiter := firerate.NewLimiter(firerateMap)
	if len(cfg.Firerate) > 0 {
		log.Info("firerate operator overrides loaded", "count", len(cfg.Firerate))
	}
	_ = fireLimiter // stats surface (xhelixctl firerate) lands in H.3.1
	// Declared early so emit's closure (assigned later) can capture
	// them; their actual instances are created further down.
	var dedupe *alertdedupe.Engine
	var liveHub *liveHubT
	var webServer *web.Server
	if cfg.Baseline.Enabled {
		ignore := map[string]bool{}
		for _, b := range cfg.Baseline.IgnoreBinaries {
			ignore[b] = true
		}
		// Always ignore xhelix's own activity to keep baselines clean.
		ignore["/usr/local/bin/xhelix"] = true
		ignore["xhelix"] = true
		// Heartbeat is dense noise and carries no real signal — at
		// 1 Hz × 24h × 30 days that's millions of empty windows. It
		// can be re-enabled by an operator who explicitly wants
		// "agent uptime as a feature".
		ignore["heartbeat"] = true
		baselineAgg = baseline.NewAggregator(baseline.Config{
			KeepHours:        cfg.Baseline.KeepHours,
			MaxKeysPerWindow: cfg.Baseline.MaxKeysPerWindow,
			IgnoreBinaries:   ignore,
		})
		storeDir := cfg.Baseline.StoreDir
		if storeDir == "" {
			storeDir = filepath.Join(cfg.Agent.StateDir, "baseline")
		}
		s, err := baseline.NewStore(storeDir, log)
		if err != nil {
			log.Warn("baseline store init failed (running without persistence)", "err", err)
		} else {
			baselineStore = s
			baselineStore.Start(ctx)
			log.Info("baseline aggregator enabled", "store_dir", storeDir,
				"keep_hours", cfg.Baseline.KeepHours)

			// Phase 2: scoring on top of the baseline. Optional —
			// without it the aggregator still records windows for
			// future training, but no real-time alerts fire.
			if cfg.Baseline.Scoring.Enabled {
				baselineScorer = baseline.NewScorer(baseline.ScorerConfig{
					BaselineDir:       storeDir,
					LookbackDays:      cfg.Baseline.Scoring.LookbackDays,
					WarmupHours:       cfg.Baseline.Scoring.WarmupHours,
					HysteresisN:       cfg.Baseline.Scoring.HysteresisN,
					MinFeatureClasses: cfg.Baseline.Scoring.MinFeatureClasses,
					IgnoreBinaries:    ignore,
				})
				if n, err := baselineScorer.LoadBaseline(time.Now().UTC()); err != nil {
					log.Warn("baseline scorer initial load failed", "err", err)
				} else {
					log.Info("baseline scorer enabled", "binaries_learned", n)
				}
				alpha := float64(cfg.Baseline.Scoring.RateAlphaPercent) / 100.0
				if alpha == 0 {
					alpha = 0.1
				}
				baselineRate = baseline.NewRateDetector(baseline.RateConfig{
					Alpha:             alpha,
					SigmaThreshold:    float64(cfg.Baseline.Scoring.RateSigmaThreshold),
					MinHistory:        cfg.Baseline.Scoring.RateMinHistory,
					MinAbsoluteEvents: uint64(cfg.Baseline.Scoring.RateMinEvents),
				})
			}

			// Phase 3: optional fleet hub uploader.
			if cfg.Baseline.Hub.URL != "" {
				queueDir := cfg.Baseline.Hub.QueueDir
				if queueDir == "" {
					queueDir = filepath.Join(cfg.Agent.StateDir, "hubqueue")
				}
				hostTag := cfg.Baseline.Hub.HostTag
				if hostTag == "" {
					hostTag, _ = os.Hostname()
				}
				upInterval := time.Duration(cfg.Baseline.Hub.UploadIntervalMin) * time.Minute
				if upInterval == 0 {
					upInterval = 5 * time.Minute
				}
				up, err := baseline.NewUploader(baseline.UploaderConfig{
					URL:                   cfg.Baseline.Hub.URL,
					HostTag:               hostTag,
					RoleTag:               cfg.Baseline.Hub.RoleTag,
					XhelixVer:             version.Version,
					AuthToken:             cfg.Baseline.Hub.AuthToken,
					UploadInterval:        upInterval,
					QueueDir:              queueDir,
					TLSInsecureSkipVerify: cfg.Baseline.Hub.TLSInsecureSkipVerify,
					Logger:                log,
				})
				if err != nil {
					log.Warn("baseline uploader init failed", "err", err)
				} else {
					baselineUploader = up
					baselineUploader.Start(ctx)
					log.Info("baseline hub uploader enabled",
						"url", cfg.Baseline.Hub.URL, "host_tag", hostTag,
						"interval", upInterval)
				}
			}

			retention := cfg.Baseline.RetentionDays
			rebuildEvery := time.Duration(cfg.Baseline.Scoring.RebuildHours) * time.Hour
			if rebuildEvery == 0 {
				rebuildEvery = 6 * time.Hour
			}
			go func() {
				flushT := time.NewTicker(10 * time.Minute)
				pruneT := time.NewTicker(time.Hour)
				rebuildT := time.NewTicker(rebuildEvery)
				defer flushT.Stop()
				defer pruneT.Stop()
				defer rebuildT.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-flushT.C:
						ready := baselineAgg.FlushReady(time.Now().UTC())
						// Score every flushed window. Verdicts emit
						// alerts back through the standard pipeline.
						if baselineScorer != nil || baselineRate != nil {
							for _, w := range ready {
								scoreOneWindow(log, baselineScorer, baselineRate, w, emit)
							}
						}
						if len(ready) > 0 {
							baselineStore.Push(ready)
							// Mirror the same windows to the fleet hub
							// if configured. Uploader queues to disk;
							// failure of the hub doesn't slow the local
							// store.
							if baselineUploader != nil {
								_ = baselineUploader.Push(ready)
							}
						}
					case <-rebuildT.C:
						if baselineScorer != nil {
							if n, err := baselineScorer.LoadBaseline(time.Now().UTC()); err != nil {
								log.Warn("baseline rebuild failed", "err", err)
							} else {
								log.Info("baseline rebuilt", "binaries", n)
							}
						}
					case <-pruneT.C:
						if retention > 0 {
							cutoff := time.Now().UTC().AddDate(0, 0, -retention)
							n, _ := baselineStore.PruneOlderThan(cutoff)
							if n > 0 {
								log.Info("baseline pruned old files", "count", n)
							}
						}
					}
				}
			}()
		}
	}

	var threatSet *threatintel.Set
	if cfg.ThreatFeed.Enabled {
		tcfg := threatintel.Config{
			AllowOffline: cfg.ThreatFeed.AllowOffline,
			Logger:       log,
		}
		if cfg.ThreatFeed.RefreshHours > 0 {
			tcfg.RefreshEvery = time.Duration(cfg.ThreatFeed.RefreshHours) * time.Hour
		}
		for _, s := range cfg.ThreatFeed.ExtraSources {
			tcfg.ExtraSources = append(tcfg.ExtraSources,
				threatintel.Source{Name: s.Name, URL: s.URL})
		}
		fetcher := threatintel.New(tcfg)
		if err := fetcher.Start(ctx); err != nil {
			log.Warn("threatintel start failed (running without intel)", "err", err)
		} else {
			threatSet = fetcher.Set()
			log.Info("threat intel feed enabled")
		}
	}

	// Hook the response engine + session tracker into the alert path.
	emit = func(a model.Alert) {
		// Phase H.3 fire-rate cap. Dropped alerts still surface in the
		// per-rule suppressed counter so operators see the noisy rule.
		if !fireLimiter.Allow(a.RuleID, time.Now()) {
			return
		}
		// Evidence bucket aggregation — rolls up repeated alerts
		// per (rule_id, kind, exe_sha, target_class, cgroup,
		// origin_type, 1-min window). Done first so even alerts
		// dropped downstream contribute to the operator's rollup.
		if foundation != nil && foundation.Evidence != nil {
			foundation.Evidence.Observe(&a)
		}

		// Threat-intel enrichment — tag alerts whose src/dst IP is on
		// a public bad-list so the operator immediately sees "this
		// connection went to a known C2 source/destination".
		if threatSet != nil {
			for _, k := range []string{"src_ip", "src", "dst_ip", "dst"} {
				if v := a.Event.Tags[k]; v != "" {
					if ip := net.ParseIP(v); ip != nil {
						if t := threatSet.Lookup(ip); t.Source != "" {
							if a.Event.Tags == nil {
								a.Event.Tags = map[string]string{}
							}
							a.Event.Tags["intel_"+k] = t.Source
						}
					}
				}
			}
		}
		bus.Send(a)
		if webServer != nil {
			webServer.AddAlert(a)
		}
		if sessionTracker != nil {
			sessionTracker.IngestAlert(a)
		}
		if respEngine != nil {
			respEngine.OnAlert(a)
		}
		// P-RF.9b daemon wiring — planner observes every alert as a
		// takeover.Signal. Shadow mode by default: the planner runs
		// but Executor only LOGS what it would do. Operator flips
		// to active via takeover.active=true once they're confident
		// the plans match policy.
		if plannerWiring != nil {
			plannerWiring.OnAlert(a)
		}
		// Feed the dedupe engine so alerts.list returns clusters.
		dst := a.Event.Tags["dst_ip"]
		if dst == "" {
			dst = a.Event.Tags["dst"]
		}
		dport := uint16(0)
		if p := a.Event.Tags["dst_port"]; p != "" {
			var pp int
			_, _ = fmt.Sscanf(p, "%d", &pp)
			dport = uint16(pp)
		}
		if dedupe != nil {
			dedupe.Observe(alertdedupe.Alert{
				At:      time.Now(),
				RuleID:  a.RuleID,
				PID:     a.Event.PID,
				Exe:     a.Event.Image,
				ExeSHA:  a.Event.Tags["exe_sha256"],
				DstIP:   dst,
				DstPort: dport,
				Reason:  a.Reason,
				Tags:    a.Event.Tags,
			})
		}
		// Broadcast to live SSE subscribers.
		if liveHub != nil {
			liveHub.publish(map[string]any{
				"kind":     "alert",
				"ts":       time.Now().Format(time.RFC3339),
				"rule_id":  a.RuleID,
				"reason":   a.Reason,
				"pid":      a.Event.PID,
				"exe":      a.Event.Image,
				"comm":     a.Event.Comm,
				"dst_ip":   dst,
				"dst_port": dport,
				"severity": a.Event.Severity.String(),
			})
		}

		// Incident-graph alert fan-out (Phase D.1). Bridges the alert
		// into the incidentgraph engine where it's correlated with
		// prior events under the same source/lineage. Nil-safe.
		if foundation != nil && foundation.IncidentGraph != nil {
			incidentSink(foundation.IncidentGraph, a)
		}
	}

	// Tamper guard — emits an alert when something attacks the daemon
	// itself. We pass `emit` so its alerts flow through the same
	// pipeline as eBPF/FIM/decoy alerts.
	var tamperG *tamperguard.Guard
	if cfg.TamperGuard.Enabled {
		tcfg := tamperguard.Config{
			PidFile:     cfg.Agent.PIDFile,
			CheckAuditd: cfg.TamperGuard.CheckAuditd,
			Logger:      log,
			OnAnomaly: func(reason string, tags map[string]string) {
				ev := model.NewEvent("tamper", model.SeverityCritical)
				if tags != nil {
					for k, v := range tags {
						ev.Tags[k] = v
					}
				}
				ev.Tags["reason"] = reason
				emit(model.Alert{Event: ev, RuleID: tags["tamper_id"], Reason: reason})
			},
		}
		if cfg.TamperGuard.IntervalSeconds > 0 {
			tcfg.Interval = time.Duration(cfg.TamperGuard.IntervalSeconds) * time.Second
		}
		tamperG = tamperguard.New(tcfg)
		if err := tamperG.Start(ctx); err != nil {
			log.Warn("tamperguard start failed", "err", err)
			tamperG = nil
		} else {
			log.Info("tamperguard enabled")
		}
	}

	// Kernel integrity checker — same emit pattern.
	var kintCheck *kintegrity.Checker
	if cfg.KIntegrity.Enabled {
		kcfg := kintegrity.Config{
			OnAlert: func(reason string, tags map[string]string) {
				ev := model.NewEvent("kintegrity", model.SeverityCritical)
				for k, v := range tags {
					ev.Tags[k] = v
				}
				ev.Tags["reason"] = reason
				emit(model.Alert{Event: ev, RuleID: tags["kintegrity_id"], Reason: reason})
			},
		}
		if cfg.KIntegrity.IntervalSeconds > 0 {
			kcfg.Interval = time.Duration(cfg.KIntegrity.IntervalSeconds) * time.Second
		}
		kintCheck = kintegrity.New(kcfg)
		if err := kintCheck.Start(ctx); err != nil {
			log.Warn("kintegrity start failed", "err", err)
			kintCheck = nil
		} else {
			log.Info("kernel integrity checker enabled")
		}
	}
	// silence unused-vars when none of these features are in play
	_ = beaconDet
	_ = dnsexfilDet

	// Rules engine
	ruleEngine, err := rules.NewEngine(emit)
	if err != nil {
		return fmt.Errorf("init rules engine: %w", err)
	}

	// Load bundled rules. Try the install path first (deb / rpm /
	// tarball), fall back to cwd-relative for `go run` / dev.
	bundledRulesDir := ""
	for _, p := range []string{"/usr/share/xhelix/ruleset/core", "ruleset/core"} {
		if _, err := os.Stat(p); err == nil {
			bundledRulesDir = p
			break
		}
	}
	bundledRules, err := rules.LoadDir(bundledRulesDir)
	if err != nil {
		log.Warn("failed to load bundled rules", "dir", bundledRulesDir, "err", err)
	} else if bundledRulesDir == "" {
		log.Warn("no bundled rules found (looked in /usr/share/xhelix and ./ruleset/core)")
	} else {
		// Apply class_map.yaml so every rule has a detection-class
		// for the per-class FP metric (P-AB.12). Missing file is
		// fine — every rule defaults to class 3 (alert-only).
		cm, cmErr := rules.LoadClassMap(bundledRulesDir)
		if cmErr != nil {
			log.Warn("class_map load failed (all rules default to class 3)", "err", cmErr)
		} else {
			cm.ApplyTo(bundledRules)
			// Re-stamp Class on every persisted soak record that
			// was written before class_map became authoritative.
			// Without this, records loaded from soak.json keep
			// Class=0 (legacy) and skew the per-class FP table.
			soak.Reclassify(cm.Lookup)
		}
		if err := ruleEngine.Load(bundledRules); err != nil {
			log.Warn("failed to compile bundled rules", "err", err)
		} else {
			var c1, c2, c3 int
			for _, r := range bundledRules {
				switch r.NormalizeClass() {
				case 1:
					c1++
				case 2:
					c2++
				default:
					c3++
				}
			}
			log.Info("rules loaded", "count", len(bundledRules),
				"class_1_hard_invariant", c1,
				"class_2_strong_signal", c2,
				"class_3_soft_drift", c3)
		}
	}

	// Load DLCF rule packs (canary, future budget/passport rules).
	// Lives alongside bundled rules but in a sibling directory; same
	// install-path-then-cwd fallback used by core rules.
	dlcfRulesDir := ""
	for _, p := range []string{"/usr/share/xhelix/ruleset/dlcf", "ruleset/dlcf"} {
		if _, err := os.Stat(p); err == nil {
			dlcfRulesDir = p
			break
		}
	}
	if dlcfRulesDir != "" {
		dlcfRules, err := rules.LoadDir(dlcfRulesDir)
		if err != nil {
			log.Warn("failed to load DLCF rules", "dir", dlcfRulesDir, "err", err)
		} else if len(dlcfRules) > 0 {
			combined := append(bundledRules, dlcfRules...)
			if err := ruleEngine.Load(combined); err != nil {
				log.Warn("failed to compile DLCF rules", "err", err)
			} else {
				bundledRules = combined
				log.Info("dlcf rules loaded", "count", len(dlcfRules), "dir", dlcfRulesDir)
			}
		}
	}

	// Load custom rules
	if cfg.Ruleset.CustomDir != "" {
		customRules, err := rules.LoadDir(cfg.Ruleset.CustomDir)
		if err == nil && len(customRules) > 0 {
			_ = ruleEngine.Load(append(bundledRules, customRules...))
			log.Info("custom rules loaded", "count", len(customRules))
		}
	}

	// Correlator — uses the same emit so correlation incidents go
	// through the response chain too.
	corrEngine, err := correlator.New(emit)
	if err != nil {
		return fmt.Errorf("init correlator: %w", err)
	}
	// Load correlator chain rules from disk (Phase J.2). Each *.yaml
	// under /usr/share/xhelix/correlator.d/ contains one or more rule
	// documents. Missing dir is fine — the correlator just runs empty.
	{
		corrDir := "/usr/share/xhelix/correlator.d"
		corrRules, loadErr := correlator.LoadFromDir(corrDir)
		if loadErr != nil {
			log.Warn("correlator: some rules failed to load", "dir", corrDir, "err", loadErr)
		}
		if len(corrRules) > 0 {
			if err := corrEngine.Load(corrRules); err != nil {
				log.Warn("correlator: Load failed; running with no rules", "err", err)
			} else {
				ids := make([]string, 0, len(corrRules))
				for _, r := range corrRules {
					ids = append(ids, r.ID)
				}
				log.Info("correlator: rules loaded", "count", len(corrRules), "ids", ids)
			}
		} else {
			log.Info("correlator: no rules loaded", "dir", corrDir)
		}
	}

	// ProcTree
	procTree := proctree.New(0)
	ruleEngine.SetTreeFn(procTree.Ancestors)

	// Per-process connection visibility (NETVISIBILITY F1–F4 wiring).
	// cgroupClassifier resolves /proc/<pid>/cgroup → user/system/
	// container/kernel class once per pid (cached). connTable is the
	// live flow table fed from ebpf.net events in the dispatch loop.
	// A periodic sweeper drops terminated flows. See pkg/connstate
	// and pkg/cgroupclass.
	cgroupClassifier := cgroupclass.New(0)
	connTable := connstate.New(0)

	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				connTable.Sweep(now, 2*time.Minute, 30*time.Minute)
			}
		}
	}()

	// DNS observation collector — NETVISIBILITY F5/F6. Today's
	// upstream source is the existing netids (Suricata) DNS event
	// stream; a built-in DoH/DoT shim lands in a follow-up (T0.7b).
	// The Sink feeds connstate.RecordDNS so the next outbound
	// connect by the same pid to a resolved IP picks up the qname.
	dnsCollector := dnsresolver.NewCollector(
		nil, // PIDResolver — netids events already carry pid; resolver runs only when needed
		func(obs dnsresolver.Observation) {
			if obs.PID != 0 && obs.QName != "" && len(obs.IPs) > 0 {
				connTable.RecordDNS(obs.PID, obs.QName, obs.IPs)
			}
		},
	)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				dnsCollector.Sweep(now)
			}
		}
	}()

	// History store — narrative journal persistence target.
	histPath := filepath.Join(cfg.Agent.StateDir, "history.db")
	histStore, err := storehistory.Open(histPath)
	if err != nil {
		log.Warn("history store open failed; journal disabled", "err", err)
	} else {
		log.Info("history store ready", "path", histPath)
	}

	// Activity clusterer — turns raw flows into narrative
	// activities. Periodic flush goroutine persists to history.
	activityClusterer := activity.New(30 * time.Second)
	if histStore != nil {
		go runActivityPersister(ctx, log, activityClusterer, connTable, histStore)
		go runHistoryPruner(ctx, log, histStore)
	}

	// Hot store pruner (fix for the 14GB hot.db bug — see ERRORS.md).
	// retention_hours + max_size_mb in xhelix.yaml were declared but
	// not enforced. This goroutine consumes them properly.
	if hot != nil {
		retention := time.Duration(cfg.Storage.Hot.RetentionHours) * time.Hour
		if retention <= 0 {
			retention = 24 * time.Hour
		}
		maxBytes := int64(cfg.Storage.Hot.MaxSizeMB) * 1024 * 1024
		go runHotStorePruner(ctx, log, hot, retention, maxBytes)
		cfgAudit.Witness("storage.hot.retention_hours", "runHotStorePruner")
		cfgAudit.Witness("storage.hot.max_size_mb", "runHotStorePruner")
	}

	// Heartbeat writer — pairs with the Rust watchdog. Writes
	// /run/xhelix.heartbeat every 15s.
	go runHeartbeatWriter(ctx, log, "/run")

	// Operator suppression registry — analyst-feedback loop.
	suppressor := suppression.NewStore()

	// Alert dedupe + scoring — composes individual rule fires
	// into clusters before promotion.
	dedupe = alertdedupe.NewEngine()

	// Live event hub — emit() and the dispatch loop publish here;
	// stream.events subscribers receive their own bounded channel.
	liveHub = newLiveHub()

	// Verdict engine (Phase F2). Decides every observed connection
	// against policy → telemetry-corpus → known-good → (future
	// layers). Observe-only — verdicts are recorded, never enforced
	// here.
	vctx := newVerdictCtx()
	log.Info("verdict engine ready",
		"kg_hosts", func() int { h, _ := vctx.kg.Size(); return h }(),
		"kg_asns", func() int { _, a := vctx.kg.Size(); return a }(),
		"telemetry_entries", vctx.tlm.Size())

	// Hot-reloadable on-disk policy. Default location matches the
	// debian package layout; operator can override via XDG-ish
	// env vars in a future iteration.
	policyPath := "/etc/xhelix/policy.yaml"
	// Enforcement plane (Phase F6) — wired but disarmed by default.
	// Operator must explicitly arm via the UI. Disarmed = pure
	// observe-mode; verdicts are tagged but no packets are dropped.
	enfCtx := newEnforceCtx(log, vctx, connTable)
	defer enfCtx.Disarm()

	// Per-process bytes history sampler (5s tick, 10min retention).
	procHist := newProcHistory()
	go procHist.Run(ctx, connTable)

	if err := vctx.loadPolicyFile(policyPath, func() {
		log.Info("policy reloaded", "path", policyPath,
			"block_telemetry", vctx.blockTelemetry.Load())
	}); err != nil {
		log.Warn("policy file load failed (running with empty policy)", "err", err)
	} else {
		log.Info("policy loaded", "path", policyPath,
			"block_telemetry", vctx.blockTelemetry.Load())
	}

	// User-activity hint — feeds the "user idle + active egress"
	// composite alert.
	idleDet := idlehint.New(nil, 60*time.Second)
	go runIdlePoller(ctx, log, idleDet)

	// Brand-local phishing detector (typosquat/IDN/combosquat/bitsquat)
	brandDet := brandcheck.NewDetector(brandcheck.Config{}, nil)

	// tmpfs exec watcher — bootstrap with current mount snapshot.
	shmDet := shmguard.NewDetector(loadTmpfsMounts(log))
	go runShmRefresher(ctx, log, shmDet)

	// LocalAPI — Unix socket for my-net-gate.
	// Socket lives inside /run/xhelix/ — the systemd unit grants
	// ReadWritePaths for that directory but not for /run itself.
	apiSock := "/run/xhelix/xhelix.sock"
	apiSrv := localapi.NewServer(apiSock,
		localapi.OptionAllowUIDs(0), // root only by default
	)
	registerLocalAPIHandlers(apiSrv, histStore, suppressor, dedupe, connTable, liveHub, vctx, procHist, log)

	// P-RF.9c: register P-PS.13 operator-UX handlers.
	// P-RF.9d: load protected_services from config (Registry was
	// empty in P-RF.9c). The forensic store is still empty until
	// the JSON-lines ingest path lands in P-RF.9e.
	protectedRegistry := protectedsvc.NewRegistry()
	if cfg.ProtectedServices.Enabled && len(cfg.ProtectedServices.Services) > 0 {
		if err := protectedRegistry.Load(cfg.ProtectedServices.Services); err != nil {
			log.Error("protected_services config refused", "err", err)
		} else {
			cfgAudit.Witness("protected_services.enabled", "protectedRegistry")
			cfgAudit.Witness("protected_services.services", "protectedRegistry")
			log.Info("protected services loaded",
				"count", protectedRegistry.Count())
		}
	}
	(&protectsvcapi.API{Reg: protectedRegistry}).Register(apiSrv)
	forensicStore := forensic.NewStore()
	(&forensicapi.API{Store: forensicStore}).Register(apiSrv)
	log.Info("operator-UX APIs registered",
		"protected_services", protectedRegistry.Count(),
		"iocs", forensicStore.Len())

	// Phase H.1 / H.3 operator surfaces.
	apiSrv.RegisterHandler("firerate.stats", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return fireLimiter.SuppressedStats(), nil
	})
	apiSrv.RegisterHandler("endpointscore.current", func(ctx context.Context, _ json.RawMessage) (any, error) {
		if foundation == nil || foundation.IncidentGraph == nil {
			return endpointscore.EndpointScore{At: time.Now()}, nil
		}
		tr := foundation.IncidentGraph.SourceScoreTracker()
		e := endpointscore.NewEngine(tr, nil)
		return e.Evaluate(time.Now()), nil
	})
	apiSrv.RegisterHandler("flowstats.top", func(ctx context.Context, req json.RawMessage) (any, error) {
		n := 20
		if len(req) > 0 {
			var p struct{ N int }
			if err := json.Unmarshal(req, &p); err == nil && p.N > 0 {
				n = p.N
			}
		}
		if foundation == nil || foundation.FlowStats == nil {
			return []flowstats.ImageBytes{}, nil
		}
		return foundation.FlowStats.TopOut(n, time.Now()), nil
	})

	// P-RF.9e: spawn the forensic JSON-lines ingestor when the
	// operator opts in. The deception binaries (honey-sh /
	// sinkhole / dnspoison) write *.jsonl files into the
	// configured dir; this goroutine tails them and populates
	// forensicStore + fires co-occurrence rules.
	if cfg.ForensicIngest.Enabled && cfg.ForensicIngest.Dir != "" {
		co := forensic.NewCoEngine(forensic.DefaultCoRules())
		ingestor := forensicingest.New(forensicingest.Config{
			Dir:          cfg.ForensicIngest.Dir,
			ScanInterval: cfg.ForensicIngest.ScanInterval,
			PollInterval: cfg.ForensicIngest.PollInterval,
			Log:          log,
		}, forensicStore, co, func(h forensic.Hit) {
			log.Warn("forensic co-occurrence fired",
				"rule", h.RuleID, "source", h.Source,
				"severity", h.Severity, "contributors", h.Contributors)
		})
		go ingestor.Run(ctx)
		cfgAudit.Witness("forensic_ingest.enabled", "forensicIngestor")
		cfgAudit.Witness("forensic_ingest.dir", "forensicIngestor")
		cfgAudit.Witness("forensic_ingest.scan_interval", "forensicIngestor")
		cfgAudit.Witness("forensic_ingest.poll_interval", "forensicIngestor")
		log.Info("forensic ingestor enabled", "dir", cfg.ForensicIngest.Dir)
	}
	// Enforcement handlers (F6 v2) — wired after the main registration
	// since they need their own context closure for Arm.
	apiSrv.RegisterHandler("enforce.status", func(_ context.Context, _ json.RawMessage) (any, error) {
		return enforceStatus(enfCtx)
	})
	apiSrv.RegisterHandler("enforce.arm", func(c context.Context, raw json.RawMessage) (any, error) {
		return enforceArm(ctx, enfCtx, raw)
	})
	apiSrv.RegisterHandler("enforce.disarm", func(_ context.Context, _ json.RawMessage) (any, error) {
		return enforceDisarm(enfCtx)
	})
	// alerts.test_fire (P-AB.5): publish a synthetic Alert through the
	// real bus so file/stdout/webhook sinks AND the response engine
	// process it end-to-end. Operator's smoke-test for "is my Slack
	// webhook actually wired up?" without needing a real attack.
	apiSrv.RegisterHandler("alerts.test_fire", func(_ context.Context, raw json.RawMessage) (any, error) {
		return testFireAlert(bus, hostnameOrEmpty(), raw)
	})
	// rules.soak (P-AB.10): snapshot the per-rule clean-day counter
	// so xhelixctl can show "rule X has been clean for N days".
	apiSrv.RegisterHandler("rules.soak", func(_ context.Context, _ json.RawMessage) (any, error) {
		recs := soak.Snapshot()
		out := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			out = append(out, map[string]any{
				"rule_id":                r.RuleID,
				"class":                  r.Class,
				"entered_detect_at":      r.EnteredDetectAt,
				"fire_count":             r.FireCount,
				"fp_count":               r.FPCount,
				"last_fp":                r.LastFP,
				"zero_fp_since":          r.ZeroFPSince,
				"consecutive_clean_days": r.ConsecutiveCleanDays,
			})
		}
		return map[string]any{
			"min_clean_days": soakDays,
			"records":        out,
		}, nil
	})
	// rules.fp_class (P-AB.12): the per-class FP-rate breakout
	// required by LOW_FALSE_POSITIVE_ARCHITECTURE_2026-05-21.md §12.
	// Used by `xhelixctl rules fp` to confirm Class 1+2 are within
	// architectural targets before any rule is promoted to a
	// destructive action mask.
	apiSrv.RegisterHandler("rules.fp_class", func(_ context.Context, _ json.RawMessage) (any, error) {
		stats := soak.ClassBreakdown()
		out := make([]map[string]any, 0, len(stats))
		for _, c := range stats {
			out = append(out, map[string]any{
				"class":         c.Class,
				"rules":         c.Rules,
				"total_fires":   c.TotalFires,
				"total_fps":     c.TotalFPs,
				"fp_rate":       c.FPRate,
				"target":        c.Target,
				"within_target": c.WithinTarget,
			})
		}
		return map[string]any{"classes": out}, nil
	})
	// credbroker (P-USG.1b). Daemon-resident broker handles
	// audit-log queries and (USG.2+) policy-gated unseals over
	// LocalAPI. The seal/unseal/migration path stays on
	// xhelixctl-side for operator workflows.
	// P-EGRESS.M1 — egress observer (Mode 1, default-off opt-in).
	// Construct early so the LocalAPI handler closure below can
	// capture it. Pipeline picks it up later via Pipeline.EgressObserver.
	// Pure data layer: classifies every outbound connect; no enforcement.
	var egressObs *egressmon.Observer
	var ipTS *egressmon.IPTimeSeries
	if cfg.Egress.Observe {
		sampleTTL := cfg.Egress.SampleTTL
		if sampleTTL == 0 {
			sampleTTL = 10 * time.Minute
		}
		minFleet := cfg.Egress.MinFleetSeen
		if minFleet == 0 {
			minFleet = 3
		}
		_ = minFleet // fleet baseline provider lands in P-EGRESS.M1.b
		// intel provider is attached later, after intelMgr is built,
		// via egressObs.WithIntel-equivalent — but the observer's
		// classifier is fixed at construction. For now build without
		// intel; P-EGRESS.M1.b will reorder construction.
		classifier := destclass.New()
		egressObs = egressmon.New(classifier, sampleTTL)
		cfgAudit.Witness("egress.observe", "EgressObserver")
		cfgAudit.Witness("egress.sample_ttl", "EgressObserver")
		cfgAudit.Witness("egress.min_fleet_seen", "EgressObserver")
		log.Info("egress observer enabled (Mode 1 — observe + classify, no enforcement)",
			"sample_ttl", sampleTTL, "min_fleet_seen", minFleet)
		if cfg.Egress.CIDRFeedSync {
			cfgAudit.Witness("egress.cidr_feed_sync", "DestclassFeedSync")
			go destclass.SyncLoop(ctx, classifier, destclass.DefaultFeeds(), nil, 24*time.Hour, func(err error) {
				log.Warn("destclass feed sync error", "err", err)
			})
			log.Info("destclass CIDR feed sync enabled (24h cadence, AWS + Cloudflare)")
		}
		// Per-IP time-series store (graphs + retention). Independent
		// of the per-lineage observer; persists every IP we see bytes
		// for, bucketed by 5 minutes, retained 30 days.
		tsDB := filepath.Join(cfg.Agent.StateDir, "ip-timeseries.db")
		if ts, err := egressmon.NewIPTimeSeries(egressmon.IPTimeSeriesConfig{
			DBPath: tsDB, BucketSize: 5 * time.Minute, RetentionDays: 30,
		}); err == nil {
			ipTS = ts
			ts.StartFlushLoop(ctx)
			log.Info("egress ip-timeseries enabled",
				"db", tsDB, "bucket", "5m", "retention_days", 30)
		} else {
			log.Warn("egress ip-timeseries init failed (continuing without graphs)", "err", err)
		}

		// Daily rollup writer — periodic snapshot to
		// /var/lib/xhelix/egress-analytics/YYYY-MM-DD.jsonl.
		rollupHost, _ := os.Hostname()
		rollupDir := filepath.Join(cfg.Agent.StateDir, "egress-analytics")
		rollup := egressmon.NewRollup(egressObs, rollupDir, 60*time.Second, rollupHost)
		if err := rollup.Start(ctx); err != nil {
			log.Warn("egress rollup start failed (continuing without daily file)", "err", err)
		} else {
			log.Info("egress rollup writer started", "dir", rollupDir, "period", "60s")
		}
	}

	// App identification — load operator declarations from
	// /etc/xhelix/apps.d/*.yaml + heuristics. Always constructed
	// (cheap, nil-safe, no enforcement). Pipeline uses it to tag
	// every event with app_id for analytics + grouping.
	// Two-tier load: vendor decls ship under /usr/share/xhelix/apps.d/
	// (WordPress, Drupal, Laravel, Rails recognizers); operator overlays
	// live under /etc/xhelix/apps.d/. Later entries win (operator overrides
	// vendor) — appident.New takes the merged slice in declaration order.
	vendorDecls, vendorErrs := appident.LoadDecls("/usr/share/xhelix/apps.d")
	for _, e := range vendorErrs {
		log.Warn("appident vendor decl error", "err", e)
	}
	opDecls, opDeclErrs := appident.LoadDecls("/etc/xhelix/apps.d")
	for _, e := range opDeclErrs {
		log.Warn("appident operator decl error", "err", e)
	}
	appDecls := append(vendorDecls, opDecls...)
	appIdentifier := appident.New(appDecls)
	log.Info("appident declarations loaded",
		"vendor", len(vendorDecls), "operator", len(opDecls), "total", len(appDecls))

	// Vhost correlator — per-worker-pid pending vhost slot, TTL 2s.
	// Always constructed; cheap, nil-safe. Pipeline notes inbound
	// HTTP Host header → outbound connects within TTL get tagged
	// with inbound_vhost.
	vhostCorrelator := vhostcorr.New(2 * time.Second)
	// Periodic sweep (cheap; lookups also lazy-prune).
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				vhostCorrelator.Sweep()
			}
		}
	}()

	// Disk warden — bounded retention. Default 4 GiB cap, 30d retention.
	// Always-on; cheap. Addresses the JSONL rollup unbounded-growth
	// risk from the perf review.
	dw := diskwarden.New(diskwarden.Config{
		StateDir: cfg.Agent.StateDir, LogDir: cfg.Agent.LogDir, Log: log,
	})
	dw.Start(ctx)
	log.Info("diskwarden enabled", "cap_bytes", 4<<30, "retention_days", 30)

	// GeoIP — best-effort country lookup. Loads operator CSV at
	// /var/lib/xhelix/geoip/country.csv plus the built-in seed
	// (RFC-1918, cloud-metadata, well-known anycast). Missing CSV =
	// only seed entries, Lookup returns ZZ/false for unmapped IPs.
	geoDB := geoip.NewInMemory()
	geoCSV := filepath.Join(cfg.Agent.StateDir, "geoip", "country.csv")
	entries := geoip.SeedEntries()
	if csvEntries, err := geoip.LoadCSVFile(geoCSV); err != nil {
		log.Warn("geoip CSV load failed", "path", geoCSV, "err", err)
	} else {
		entries = append(entries, csvEntries...)
		if len(csvEntries) > 0 {
			log.Info("geoip loaded", "csv_path", geoCSV, "csv_entries", len(csvEntries))
		}
	}
	geoDB.Load(entries)

	credBroker := loadCredBroker(log)
	// Bridge the daemon's emit closure into the fangate so cred-broker
	// denies / honey-touches land in the alert bus AND the takeover
	// planner (via plannerWiring.OnAlert which is wrapped inside emit).
	startFanGate(ctx, log, credBroker, cfg.Credbroker.Plaintext, func(a interface{}) {
		if ma, ok := a.(model.Alert); ok && emit != nil {
			emit(ma)
		}
	})
	apiSrv.RegisterHandler("credbroker.history", func(_ context.Context, _ json.RawMessage) (any, error) {
		hist := credBroker.History()
		out := make([]map[string]any, 0, len(hist))
		for _, r := range hist {
			out = append(out, map[string]any{
				"time":        r.Time,
				"sealed_path": r.SealedPath,
				"class":       r.Class,
				"outcome":     r.Outcome,
				"pid":         r.PID,
				"comm":        r.Comm,
				"image":       r.Image,
				"uid":         r.UID,
				"reason":      r.Reason,
			})
		}
		return map[string]any{"records": out}, nil
	})
	apiSrv.RegisterHandler("integrity.status", func(_ context.Context, _ json.RawMessage) (any, error) {
		if integrityVerifier == nil {
			return map[string]any{"enabled": false}, nil
		}
		total, _ := integrityBaseline.Count()
		per, _ := integrityBaseline.PerSource()
		perOut := map[string]int{}
		for k, v := range per {
			perOut[string(k)] = v
		}
		s := integrityVerifier.Stats()
		dbPath := cfg.Integrity.BaselineDB
		if dbPath == "" {
			dbPath = filepath.Join(cfg.Agent.StateDir, "integrity-baseline.db")
		}
		return map[string]any{
			"enabled":     true,
			"mode":        cfg.Integrity.Mode,
			"baseline_db": dbPath,
			"total_rows":  total,
			"per_source":  perOut,
			"verifier": map[string]uint64{
				"baseline_matched": s.BaselineMatched,
				"hash_mismatched":  s.HashMismatched,
				"tofu_accepted":    s.TOFUAccepted,
				"upgrade_recovers": s.UpgradeRecovers,
				"errors":           s.Errors,
			},
		}, nil
	})
	apiSrv.RegisterHandler("integrity.verify", func(_ context.Context, raw json.RawMessage) (any, error) {
		if integrityBaseline == nil {
			return nil, fmt.Errorf("integrity verifier not enabled")
		}
		var req struct {
			Path string `json:"path"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		row, found, err := integrityBaseline.Lookup(req.Path)
		if err != nil {
			return nil, err
		}
		hash, _, _, hErr := integrity.HashFile(req.Path, integrity.DefaultMaxFileSize)
		if hErr != nil {
			return nil, hErr
		}
		out := map[string]any{
			"match":           found && row.SHA256 == hash,
			"baseline_sha256": row.SHA256,
			"current_sha256":  hash,
			"source":          string(row.Source),
			"package":         row.Package,
		}
		if !found {
			out["match"] = false
			out["reason"] = "not in baseline"
		} else if row.SHA256 != hash {
			out["reason"] = "SHA-256 mismatch"
		}
		return out, nil
	})
	apiSrv.RegisterHandler("integrity.refresh_recent", func(_ context.Context, _ json.RawMessage) (any, error) {
		if integrityVerifier == nil {
			return map[string]any{"refreshed": 0}, nil
		}
		integrityVerifier.InvalidateCache()
		// Touch the critical paths — the Verify path will re-hash anything
		// modified. We don't bulk-rehash; lazy refresh is correct.
		return map[string]any{"refreshed": 0, "note": "cache invalidated; next execve re-hashes per path"}, nil
	})
	apiSrv.RegisterHandler("integrity.rebuild", func(_ context.Context, _ json.RawMessage) (any, error) {
		if integrityBaseline == nil {
			return nil, fmt.Errorf("integrity verifier not enabled")
		}
		pr, err := integrity.Build(ctx, integrityBaseline, integrity.WalkOptions{
			Paths: cfg.Integrity.Paths, Log: log,
		})
		if err != nil {
			return nil, err
		}
		if integrityVerifier != nil {
			integrityVerifier.InvalidateCache()
		}
		return map[string]any{
			"files_hashed": pr.FilesHashed,
			"bytes_hashed": pr.BytesHashed,
		}, nil
	})
	apiSrv.RegisterHandler("tui.alerts_recent", func(_ context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			Limit       int    `json:"limit"`
			MinSeverity string `json:"min_severity"`
			RuleFilter  string `json:"rule_filter"`
		}
		_ = json.Unmarshal(raw, &req)
		if req.Limit <= 0 {
			req.Limit = 100
		}
		snap := alertRing.Snapshot()
		// Newest first.
		out := make([]map[string]any, 0, len(snap))
		for i := len(snap) - 1; i >= 0 && len(out) < req.Limit; i-- {
			a := snap[i]
			if req.RuleFilter != "" && !strings.Contains(a.RuleID, req.RuleFilter) {
				continue
			}
			out = append(out, map[string]any{
				"time":     a.Event.Time.Unix(),
				"severity": a.Event.Severity.String(),
				"rule_id":  a.RuleID,
				"reason":   a.Reason,
				"sensor":   a.Event.Sensor,
				"pid":      a.Event.PID,
				"comm":     a.Event.Comm,
				"image":    a.Event.Image,
				"tags":     compactTags(a.Event.Tags),
				"class":    a.Class,
				"action":   a.Action,
			})
		}
		return map[string]any{"alerts": out, "total": len(snap)}, nil
	})
	apiSrv.RegisterHandler("tui.alert_detail", func(_ context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			Index int `json:"index"` // index from snapshot (newest=0)
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		snap := alertRing.Snapshot()
		if len(snap) == 0 {
			return nil, fmt.Errorf("ring empty")
		}
		idx := len(snap) - 1 - req.Index
		if idx < 0 || idx >= len(snap) {
			return nil, fmt.Errorf("index out of range")
		}
		a := snap[idx]
		// Causal chain from ProcTree.
		chain := make([]map[string]any, 0, len(a.Event.ProcTree))
		for _, n := range a.Event.ProcTree {
			chain = append(chain, map[string]any{
				"pid":   n.PID,
				"uid":   n.UID,
				"comm":  n.Comm,
				"image": n.Image,
				"argv":  n.Argv,
			})
		}
		return map[string]any{
			"time":     a.Event.Time.Unix(),
			"severity": a.Event.Severity.String(),
			"rule_id":  a.RuleID,
			"reason":   a.Reason,
			"sensor":   a.Event.Sensor,
			"pid":      a.Event.PID,
			"comm":     a.Event.Comm,
			"image":    a.Event.Image,
			"all_tags": a.Event.Tags,
			"chain":    chain,
			"action":   a.Action,
			"class":    a.Class,
		}, nil
	})
	apiSrv.RegisterHandler("tui.lineage_detail", func(_ context.Context, raw json.RawMessage) (any, error) {
		if egressObs == nil {
			return map[string]any{"enabled": false}, nil
		}
		var req struct {
			Lineage uint64 `json:"lineage"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		snaps := egressObs.Snapshot(egressmon.LineageID(req.Lineage))
		if len(snaps) == 0 {
			return map[string]any{"enabled": true, "found": false}, nil
		}
		s := snaps[0]
		byClass := map[string]int{}
		for k, v := range s.ByClass {
			byClass[string(k)] = v
		}
		bytesByClass := map[string]uint64{}
		for k, v := range s.BytesOutByClass {
			bytesByClass[string(k)] = v
		}
		// Top destinations by bytes_out for this lineage.
		type kv struct {
			Key   string `json:"dest"`
			Bytes uint64 `json:"bytes_out"`
		}
		dests := make([]kv, 0, len(s.BytesOutByDest))
		for k, v := range s.BytesOutByDest {
			dests = append(dests, kv{Key: k, Bytes: v})
		}
		// Sort top-15.
		for i := 0; i < len(dests); i++ {
			for j := i + 1; j < len(dests); j++ {
				if dests[j].Bytes > dests[i].Bytes {
					dests[i], dests[j] = dests[j], dests[i]
				}
			}
		}
		if len(dests) > 15 {
			dests = dests[:15]
		}
		sample := make([]map[string]any, 0, len(s.RecentSample))
		for _, o := range s.RecentSample {
			sample = append(sample, map[string]any{
				"at":    o.At.Unix(),
				"ip":    o.IP.String(),
				"sni":   o.SNI,
				"port":  o.Port,
				"class": string(o.Class),
			})
		}
		return map[string]any{
			"enabled":          true,
			"found":            true,
			"lineage":          req.Lineage,
			"app_id":           s.AppID,
			"app_kind":         s.AppKind,
			"total_connects":   s.TotalConnects,
			"total_bytes_out":  s.TotalBytesOut,
			"by_class":         byClass,
			"bytes_out_by_class": bytesByClass,
			"top_dests":        dests,
			"unique_dests":     s.UniqueDests,
			"unique_unknown":   s.UniqueUnknown,
			"first_unknown_at": s.FirstUnknownAt.Unix(),
			"first_intel_bad":  s.FirstIntelBadAt.Unix(),
			"last_connect":     s.LastConnect.Unix(),
			"recent_sample":    sample,
		}, nil
	})
	apiSrv.RegisterHandler("tui.dest_detail", func(_ context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			IP    string `json:"ip"`
			Hours int    `json:"hours"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.Hours <= 0 {
			req.Hours = 24
		}
		ip := net.ParseIP(req.IP)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip")
		}
		out := map[string]any{"ip": req.IP}
		// Timeseries (in/out) — from ipTS.
		if ipTS != nil {
			until := time.Now()
			since := until.Add(-time.Duration(req.Hours) * time.Hour)
			points, _ := ipTS.Series(ip, since, until)
			pts := make([]map[string]any, 0, len(points))
			for _, p := range points {
				pts = append(pts, map[string]any{
					"bucket_ts": p.BucketTs.Unix(),
					"bytes_out": p.BytesOut,
					"bytes_in":  p.BytesIn,
				})
			}
			out["points"] = pts
		}
		// Talkers — which lineages have this IP in their stats.
		var talkers []map[string]any
		if egressObs != nil {
			for _, s := range egressObs.Snapshot(0) {
				if b, ok := s.BytesOutByDest[req.IP]; ok {
					talkers = append(talkers, map[string]any{
						"lineage":   uint64(s.LineageID),
						"app_id":    s.AppID,
						"bytes_out": b,
					})
				}
			}
		}
		out["talkers"] = talkers
		// Intel verdict pending — intel manager lives inside dispatch.
		// Re-wired in next iteration; for now omit.
		out["intel_bad"] = false
		// GeoIP country lookup (best-effort, "" if no entry).
		if res, ok := geoDB.Lookup(req.IP); ok {
			out["country"] = res.Country
			if res.ASNOrg != "" {
				out["asn_org"] = res.ASNOrg
			}
		}
		return out, nil
	})
	apiSrv.RegisterHandler("tui.api_recent", func(_ context.Context, raw json.RawMessage) (any, error) {
		// Per-API breakdown: scans HotStore SSL_read events that have
		// http_request_line + http_host tags, aggregates by
		// (host, method, path). Returns top-N rows by count.
		var req struct {
			Limit int    `json:"limit"`
			Host  string `json:"host"` // optional filter
		}
		_ = json.Unmarshal(raw, &req)
		if req.Limit <= 0 {
			req.Limit = 200
		}
		// We scan recent events from any of the eBPF SSL sensors.
		evs, err := hot.RecentBySensor(context.Background(), "ebpf", 5000)
		if err != nil {
			return nil, err
		}
		type key struct {
			Host, Method, Path string
		}
		type val struct {
			Count   int
			LastTs  int64
			PIDs    map[uint32]struct{}
		}
		agg := map[key]*val{}
		for _, e := range evs {
			line := e.Tags["http_request_line"]
			host := e.Tags["http_host"]
			if line == "" {
				continue
			}
			// Parse "METHOD path HTTP/1.x"
			fs := strings.Fields(line)
			if len(fs) < 2 {
				continue
			}
			method := fs[0]
			path := fs[1]
			// Truncate paths so query strings don't explode the cardinality.
			if i := strings.IndexByte(path, '?'); i >= 0 {
				path = path[:i] + "?…"
			}
			if len(path) > 80 {
				path = path[:80] + "…"
			}
			if req.Host != "" && host != req.Host {
				continue
			}
			k := key{Host: host, Method: method, Path: path}
			v := agg[k]
			if v == nil {
				v = &val{PIDs: map[uint32]struct{}{}}
				agg[k] = v
			}
			v.Count++
			if t := e.Time.Unix(); t > v.LastTs {
				v.LastTs = t
			}
			v.PIDs[e.PID] = struct{}{}
		}
		// Materialise + sort by count desc.
		type row struct {
			Host    string `json:"host"`
			Method  string `json:"method"`
			Path    string `json:"path"`
			Count   int    `json:"count"`
			Pids    int    `json:"pids"`
			LastTs  int64  `json:"last_ts"`
		}
		rows := make([]row, 0, len(agg))
		for k, v := range agg {
			rows = append(rows, row{
				Host: k.Host, Method: k.Method, Path: k.Path,
				Count: v.Count, Pids: len(v.PIDs), LastTs: v.LastTs,
			})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })
		if len(rows) > req.Limit {
			rows = rows[:req.Limit]
		}
		return map[string]any{"rows": rows, "total_keys": len(agg)}, nil
	})
	apiSrv.RegisterHandler("tui.dns_recent", func(_ context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			Limit int `json:"limit"`
		}
		_ = json.Unmarshal(raw, &req)
		if req.Limit <= 0 {
			req.Limit = 100
		}
		evs, err := hot.RecentBySensor(context.Background(), "dnsresolver", req.Limit)
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, 0, len(evs))
		for _, e := range evs {
			out = append(out, map[string]any{
				"time":    e.Time.Unix(),
				"pid":     e.PID,
				"comm":    e.Comm,
				"qname":   e.Tags["qname"],
				"qtype":   e.Tags["qtype"],
				"answers": e.Tags["dns_answers"],
			})
		}
		return map[string]any{"queries": out}, nil
	})
	apiSrv.RegisterHandler("tui.history_by_pid", func(_ context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			PID   uint32 `json:"pid"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.Limit <= 0 {
			req.Limit = 200
		}
		evs, err := hot.RecentByPID(context.Background(), req.PID, req.Limit)
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, 0, len(evs))
		for _, e := range evs {
			tagsCompact := map[string]string{}
			for _, k := range []string{"dst_ip", "dst_port", "sni", "http_host", "argv", "kind", "outbound", "dir", "bytes", "qname", "dns_answers", "dest_class"} {
				if v := e.Tags[k]; v != "" {
					tagsCompact[k] = v
				}
			}
			out = append(out, map[string]any{
				"time":   e.Time.Unix(),
				"sensor": e.Sensor,
				"rule":   e.Rule,
				"comm":   e.Comm,
				"image":  e.Image,
				"tags":   tagsCompact,
			})
		}
		return map[string]any{"events": out}, nil
	})
	apiSrv.RegisterHandler("egress.ip_timeseries", func(_ context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			IP    string `json:"ip"`
			Hours int    `json:"hours"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if ipTS == nil {
			return map[string]any{"enabled": false}, nil
		}
		if req.Hours <= 0 {
			req.Hours = 24
		}
		ip := net.ParseIP(req.IP)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip %q", req.IP)
		}
		until := time.Now()
		since := until.Add(-time.Duration(req.Hours) * time.Hour)
		points, err := ipTS.Series(ip, since, until)
		if err != nil {
			return nil, err
		}
		out := make([]map[string]any, 0, len(points))
		for _, p := range points {
			out = append(out, map[string]any{
				"bucket_ts": p.BucketTs.Unix(),
				"bytes_out": p.BytesOut,
				"bytes_in":  p.BytesIn,
			})
		}
		return map[string]any{"enabled": true, "ip": req.IP, "points": out}, nil
	})
	apiSrv.RegisterHandler("egress.top_ips", func(_ context.Context, raw json.RawMessage) (any, error) {
		if ipTS == nil {
			return map[string]any{"enabled": false}, nil
		}
		var req struct {
			Hours int `json:"hours"`
			Top   int `json:"top"`
		}
		_ = json.Unmarshal(raw, &req)
		if req.Hours <= 0 {
			req.Hours = 24
		}
		until := time.Now()
		since := until.Add(-time.Duration(req.Hours) * time.Hour)
		top, err := ipTS.TopIPs(since, until, req.Top)
		if err != nil {
			return nil, err
		}
		rows := make([]map[string]any, 0, len(top))
		for _, s := range top {
			rows = append(rows, map[string]any{
				"ip": s.IP, "bytes_out": s.BytesOut, "bytes_in": s.BytesIn,
			})
		}
		return map[string]any{"enabled": true, "top": rows}, nil
	})
	apiSrv.RegisterHandler("egress.block", func(_ context.Context, raw json.RawMessage) (any, error) {
		if banner == nil {
			return map[string]any{"ok": false, "error": "netban disabled — set netban.enabled=true"}, nil
		}
		var req struct {
			Dest   string `json:"dest"`
			Reason string `json:"reason"`
			CIDR   bool   `json:"cidr"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.CIDR {
			return nil, fmt.Errorf("CIDR blocking via Banner not supported yet; v1 only single-IP")
		}
		ip := net.ParseIP(req.Dest)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %q", req.Dest)
		}
		if err := banner.Ban(ip, req.Reason, 0); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "banned": ip.String(), "reason": req.Reason}, nil
	})
	apiSrv.RegisterHandler("egress.deep_observe", func(_ context.Context, raw json.RawMessage) (any, error) {
		// v1: deep-observe is a marker the operator sets; sensor-side
		// elevation lands in P-EGRESS.M2. We record it in the daemon
		// state for visibility but don't change observer behaviour.
		var req struct {
			Dest   string `json:"dest"`
			Port   uint16 `json:"port"`
			Reason string `json:"reason"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		log.Info("egress.deep_observe marker recorded (sensor elevation in M2)",
			"dest", req.Dest, "port", req.Port, "reason", req.Reason)
		return map[string]any{"ok": true, "dest": req.Dest, "port": req.Port,
			"note": "marker recorded; sensor-side elevation lands in P-EGRESS.M2"}, nil
	})
	apiSrv.RegisterHandler("egress.observe", func(_ context.Context, raw json.RawMessage) (any, error) {
		if egressObs == nil {
			return map[string]any{"enabled": false}, nil
		}
		var req struct {
			Lineage uint64 `json:"lineage"`
		}
		_ = json.Unmarshal(raw, &req)
		snaps := egressObs.Snapshot(egressmon.LineageID(req.Lineage))
		out := make([]map[string]any, 0, len(snaps))
		for _, s := range snaps {
			byClass := map[string]int{}
			for k, v := range s.ByClass {
				byClass[string(k)] = v
			}
			sample := make([]map[string]any, 0, len(s.RecentSample))
			for _, o := range s.RecentSample {
				sample = append(sample, map[string]any{
					"at":    o.At,
					"ip":    o.IP.String(),
					"sni":   o.SNI,
					"port":  o.Port,
					"class": string(o.Class),
				})
			}
			out = append(out, map[string]any{
				"lineage":           uint64(s.LineageID),
				"app_id":            s.AppID,
				"app_kind":          s.AppKind,
				"total_connects":    s.TotalConnects,
				"total_bytes_out":   s.TotalBytesOut,
				"by_class":          byClass,
				"unique_dests":      s.UniqueDests,
				"unique_unknown":    s.UniqueUnknown,
				"last_connect":      s.LastConnect,
				"first_unknown_at":  s.FirstUnknownAt,
				"first_intel_bad":   s.FirstIntelBadAt,
				"recent_sample":     sample,
			})
		}
		return map[string]any{"enabled": true, "lineages": out}, nil
	})
	apiSrv.RegisterHandler("credbroker.contracts", func(_ context.Context, _ json.RawMessage) (any, error) {
		set := credBroker.AppContracts()
		if set == nil {
			return map[string]any{"contracts": []any{}}, nil
		}
		out := make([]map[string]any, 0)
		for _, c := range set.Contracts() {
			out = append(out, map[string]any{
				"name":                c.Name,
				"binary":              c.Binary,
				"sha256_pin":          c.SHA256Pin,
				"parent_shape":        c.ParentShape,
				"allowed_credentials": c.AllowedCredentials,
				"purpose":             c.Purpose,
				"max_opens_per_min":   c.MaxOpensPerMin,
			})
		}
		return map[string]any{"contracts": out}, nil
	})
	apiSrv.RegisterHandler("credbroker.decide", func(_ context.Context, raw json.RawMessage) (any, error) {
		// LocalAPI entry-point used by USG.2 kernel hook OR by
		// xhelixctl when an operator-attested unseal is needed.
		// USG.1b: accepts (sealed_path, requesting PID, optional
		// lineage), returns Outcome + reason. Plaintext is NOT
		// returned over LocalAPI by design — callers wanting
		// plaintext use xhelixctl credbroker unseal --force on
		// the host where the master key lives. USG.2 changes
		// this: kernel hook will receive plaintext via a separate
		// trusted FD channel, not via LocalAPI JSON.
		var req struct {
			SealedPath string                       `json:"sealed_path"`
			PID        uint32                       `json:"pid"`
			Lineage    []credbroker.LineageNode     `json:"lineage"`
			Reason     string                       `json:"reason"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		sf, err := credbroker.ReadSealed(req.SealedPath)
		if err != nil {
			return nil, err
		}
		res := credBroker.Decide(sf, credbroker.Request{
			SealedPath: req.SealedPath,
			PID:        req.PID,
			Lineage:    req.Lineage,
			Reason:     req.Reason,
		})
		// Return outcome + reason but never plaintext over the API.
		return map[string]any{
			"outcome": res.Outcome,
			"reason":  res.Reason,
			"audit":   res.Audit,
		}, nil
	})
	log.Info("credbroker LocalAPI handlers registered")
	registerFoundationHandlers(apiSrv, foundation)
	if err := apiSrv.Start(ctx); err != nil {
		log.Warn("LocalAPI failed to start", "err", err)
	} else {
		log.Info("LocalAPI listening", "socket", apiSock)
	}

	// Threat intel
	var intelMgr *intel.Manager
	if cfg.Intel.Enabled {
		intelMgr = intel.NewManager(intel.DefaultFeeds, filepath.Join(cfg.Agent.StateDir, "intel"), log)
		// Seed with baked-in static IOCs (Megalodon C2, TeamTNT
		// cryptominer infra, Outlaw, etc.) so outbound_to_known_bad
		// fires on day-1 without waiting for the Spamhaus feed to
		// refresh. Operator-overridable via /etc/xhelix/iocs.yaml.
		for _, p := range []string{
			"/etc/xhelix/iocs.yaml",
			"/usr/share/xhelix/ruleset/iocs/static.yaml",
			"ruleset/iocs/static.yaml",
		} {
			if ips, err := intel.LoadStaticFile(p); err != nil {
				log.Warn("ioc load failed", "path", p, "err", err)
			} else if len(ips) > 0 {
				added := intelMgr.AddStatic(ips)
				log.Info("static iocs seeded", "path", p, "added", added)
			}
		}
		intelMgr.Start(ctx)
		log.Info("threat intel started")
	}

	// YARA scanner
	var yaraScanner *yara.Scanner
	if cfg.YARA.Enabled {
		yaraScanner = yara.NewScanner(cfg.YARA.RulesDir, log)
		log.Info("yara scanner configured", "enabled", yaraScanner.Enabled())
	}

	// SBOM baseline
	var sbomBaseline *sbom.Baseline
	if cfg.SBOM.Enabled {
		path := cfg.SBOM.BaselinePath
		if path == "" {
			path = filepath.Join(cfg.Agent.StateDir, "sbom.json")
		}
		var err error
		sbomBaseline, err = sbom.NewBaseline(path)
		if err != nil {
			log.Warn("sbom baseline load failed", "err", err)
		} else {
			if err := sbomBaseline.Scan(); err != nil {
				log.Warn("sbom initial scan failed", "err", err)
			} else {
				log.Info("sbom baseline scanned")
			}
		}
	}

	// ML anomaly detector
	var mlDetector *ml.AnomalyDetector
	if cfg.ML.Enabled {
		mlDetector = ml.NewDetector(cfg.ML.Window, cfg.ML.Threshold)
		log.Info("ml anomaly detector configured")
	}

	// Image cache
	var imgCache *imagecache.Cache
	if cfg.Sensors.EBPF.Enabled {
		imgCache, _ = imagecache.Open(filepath.Join(cfg.Agent.StateDir, "images.db"))
		if imgCache != nil {
			defer imgCache.Close()
		}
	}

	// Forensics chain
	var forensicsChain *chain.Chain
	if cfg.Chain.Enabled {
		chainDir := cfg.Chain.Dir
		if chainDir == "" {
			chainDir = filepath.Join(cfg.Agent.StateDir, "chain")
		}
		keyPath := cfg.Chain.KeyPath
		if keyPath == "" {
			keyPath = filepath.Join(cfg.Agent.StateDir, "chain.key")
		}
		privKey, err := loadOrGenerateEd25519Key(keyPath)
		if err != nil {
			log.Warn("chain key load failed", "err", err)
		} else {
			forensicsChain, err = chain.New(chainDir, privKey)
			if err != nil {
				log.Warn("chain init failed", "err", err)
			} else {
				// Cap chain growth. Operator can override via
				// cfg.Chain.MaxBatches; default 2000 covers ~6-12h
				// at typical event rate, prevents unbounded disk hog
				// (root cause of /var/lib/xhelix/chain 20GB on
				// 2026-05-24 incident).
				maxBatches := cfg.Chain.MaxBatches
				if maxBatches <= 0 {
					maxBatches = 2000
				}
				forensicsChain.MaxBatches = maxBatches
				log.Info("forensics chain ready",
					"dir", chainDir, "max_batches", maxBatches)
			}
		}
	}

	// Event channel
	events := make(chan model.Event, 4096)

	hostname, _ := os.Hostname()

	// SNI-required-for-TLS detector (P-SNI). Watches outbound
	// connects to TLS ports; flags any whose ClientHello carried no
	// SNI extension after EvalDelay. snicheck.Note() is called from
	// the pipeline on every net_connect event; evaluation runs in
	// a background ticker goroutine.
	var sniCheck *snicheck.Detector
	if cfg.SNICheck.Enabled {
		sniCheck = snicheck.New(connTable, events, snicheck.Config{
			Host:             hostname,
			EvalDelay:        cfg.SNICheck.EvalDelay,
			TLSPorts:         cfg.SNICheck.TLSPorts,
			AllowCIDRs:       cfg.SNICheck.AllowCIDRs,
			AllowReaderComms: cfg.SNICheck.AllowReaderComms,
		})
		sniCheck.Start(ctx)
		log.Info("snicheck detector configured", "eval_delay", "800ms")
	}

	// Build sensor list
	var activeSensors []sensors.Sensor

	// Heartbeat sensor
	if cfg.Sensors.Heartbeat.Enabled {
		hb := heartbeat.New(cfg.Sensors.Heartbeat.Interval, hostname)
		activeSensors = append(activeSensors, hb)
		log.Info("heartbeat sensor configured")
	}

	// DPI sniffer (Phase F3) — out-of-band AF_PACKET listener that
	// parses TLS ClientHello and attaches the SNI directly to
	// connstate. Doesn't go through the event bus; lifecycle is
	// managed separately.
	dpiSensor := dpisensor.New(dpisensor.Config{Logger: log}, connTable)
	if err := dpiSensor.Start(ctx); err != nil {
		log.Warn("dpi sensor disabled", "err", err)
	} else {
		log.Info("dpi sniffer started (TLS ClientHello → SNI)")
		defer func() { _ = dpiSensor.Stop() }()
	}

	// eBPF sensor
	if cfg.Sensors.EBPF.Enabled {
		badIPs := []string{}
		if intelMgr != nil {
			for _, ip := range intelMgr.BadIPs() {
				badIPs = append(badIPs, ip.String())
			}
		}
		ebpfCfg := ebpfsensor.Config{
			RingbufSizeMB: cfg.Sensors.EBPF.RingbufSizeMB,
			WatchPaths:    cfg.Sensors.FIM.WatchPaths,
			BadIPs:        badIPs,
			SelfPID:       uint32(os.Getpid()),
		}
		ebpf := ebpfsensor.New(ebpfCfg)
		activeSensors = append(activeSensors, ebpf)
		log.Info("ebpf sensor configured")
	}

	// Identity sensor
	if cfg.Sensors.Identity.Enabled {
		ssh := identity.NewSSHTailer("", hostname)
		activeSensors = append(activeSensors, ssh)
		pam := identity.NewPAMBridge("", hostname)
		activeSensors = append(activeSensors, pam)
		log.Info("identity sensor configured")
	}

	// Memory sensor
	if cfg.Sensors.Memory.Enabled {
		dmesg := memory.NewDmesgWatcher("", hostname)
		activeSensors = append(activeSensors, dmesg)
		log.Info("memory sensor configured")

		// procmem (P-AB.11) — periodic /proc walk for:
		//   - deleted-binary-still-running (curl|sh + rm self
		//     droppers, memfd replay patterns)
		//   - thread-outside-module (anonymous-exec shellcode,
		//     reflective loaders, Cobalt Strike / Sliver beacons)
		// JIT runtimes exempted via the same runtimeallow.Set
		// that the pipeline uses for jit_allowlisted tagging.
		procmemRA, _ := runtimeallow.LoadFile("/etc/xhelix/runtime-allowlist.yaml")
		pms := procmemsensor.NewSensor(hostname, 60*time.Second, procmemRA)
		activeSensors = append(activeSensors, pms)
		log.Info("procmem sensor configured", "interval", "60s")

		// memdiff (P-MEMDIFF) — per-PID /proc/*/maps diff for new
		// anonymous executable mappings. Catches RemotePE-class
		// reflective loaders that don't trip procmem's thread-RIP
		// check but DO appear as new RWX regions. Same JIT
		// allowlist as procmem. 60s tick = ~10-50ms wall time on a
		// 200-pid host, well below the noise floor.
		mds := memdiffsensor.NewSensor(hostname, 60*time.Second, procmemRA)
		activeSensors = append(activeSensors, mds)
		log.Info("memdiff sensor configured", "interval", "60s")
	}

	// Procscrape (P-PROCFS-A1) — userspace enrichment for the
	// XH_EV_PROC_SCRAPE events the eBPF backend emits on
	// /proc/<pid>/{environ,maps,mem,auxv} opens. The sensor is a
	// thin wrapper over an allowlist; the actual decision happens
	// in pkg/pipeline when ev.Tags["kind"] == "proc_scrape".
	var procScrapeSensor *procscrapesensor.Sensor
	if cfg.Sensors.ProcScrape.Enabled {
		allow := procscrapesensor.Default()
		if path := cfg.Sensors.ProcScrape.AllowlistFile; path != "" {
			if err := allow.LoadFile(path); err != nil {
				log.Warn("procscrape allowlist load",
					"path", path, "err", err,
					"fallback", "default allowlist only")
			}
		}
		procScrapeSensor = procscrapesensor.NewSensor(allow)
		activeSensors = append(activeSensors, procScrapeSensor)
		log.Info("procscrape sensor configured",
			"allowlist_size", allow.Size())
	}

	// Decoy sensors
	if cfg.Sensors.Decoys.Enabled {
		var honeyFiles []decoy.HoneyFile
		for _, f := range cfg.Sensors.Decoys.HoneyFiles {
			honeyFiles = append(honeyFiles, decoy.HoneyFile{
				Path:          f.Path,
				Persona:       f.Persona,
				AllowlistComm: f.AllowlistComm,
			})
		}
		if len(honeyFiles) > 0 {
			activeSensors = append(activeSensors, decoy.NewFilesSensor(honeyFiles, hostname))
			log.Info("decoy files sensor configured", "files", len(honeyFiles))
		}

		var honeySvcs []decoy.HoneyService
		for _, s := range cfg.Sensors.Decoys.HoneyServices {
			bind := s.Bind
			if bind == "" && s.Port != 0 {
				bind = fmt.Sprintf("127.0.0.1:%d", s.Port)
			}
			honeySvcs = append(honeySvcs, decoy.HoneyService{
				Persona: s.Persona,
				Bind:    bind,
			})
		}
		if len(honeySvcs) > 0 {
			activeSensors = append(activeSensors, decoy.NewServicesSensor(honeySvcs, hostname))
			log.Info("decoy services sensor configured", "services", len(honeySvcs))
		}

		if cfg.Sensors.Decoys.CanaryTokenURL != "" {
			activeSensors = append(activeSensors, decoy.NewCanaryReceiver(cfg.Sensors.Decoys.CanaryTokenURL, hostname, nil))
			log.Info("decoy canary receiver configured")
		}
	}

	// FIM sensor
	if cfg.Sensors.FIM.Enabled {
		fimDb := filepath.Join(cfg.Agent.StateDir, "fim.db")
		if cfg.Storage.Hot.Path != "" && cfg.Storage.Hot.Path != ":memory:" {
			fimDb = filepath.Join(filepath.Dir(cfg.Storage.Hot.Path), "fim.db")
		}
		watchPaths := cfg.Sensors.FIM.WatchPaths

		// P-AB.8: ask the running web servers what their document
		// roots and reverse-proxy upstreams are, then fold the
		// sentinel files (wp-config.php, .htaccess, .env, etc.)
		// from each discovered root into the FIM watch list. This
		// catches custom layouts (cPanel, DirectAdmin, raw nginx
		// pointing at /srv/whatever, FastCGI apps whose code lives
		// at the upstream's cwd) without operator-supplied paths.
		vhostResult := vhostdiscovery.DiscoverAll()
		vhostPaths := vhostdiscovery.FIMWatchPatterns(vhostResult)
		if len(vhostPaths) > 0 {
			watchPaths = append(watchPaths, vhostPaths...)
			var srcs []string
			for _, v := range vhostResult.Vhosts {
				srcs = append(srcs, v.Source+":"+v.Root)
			}
			log.Info("vhost discovery enriched fim",
				"vhosts", len(vhostResult.Vhosts),
				"sentinels", len(vhostPaths),
				"sources", srcs)
		}
		for _, e := range vhostResult.Errors {
			log.Warn("vhost discovery soft error", "err", e)
		}

		fimSensor := fimsensor.NewSensor(fimDb, watchPaths, hostname, 5*time.Minute)
		activeSensors = append(activeSensors, fimSensor)
		log.Info("fim sensor configured", "db", fimDb, "paths", len(watchPaths))
	}

	// NetIDS sensor
	if cfg.Sensors.NetIDS.Enabled {
		iface := ""
		if len(cfg.Sensors.NetIDS.Interfaces) > 0 {
			iface = cfg.Sensors.NetIDS.Interfaces[0]
		}
		netSensor := netidssensor.NewSensor("/var/log/suricata/eve.json", "suricata", iface, hostname)
		activeSensors = append(activeSensors, netSensor)
		log.Info("netids sensor configured", "iface", iface)
	}

	// LSM audit sensor
	if cfg.Sensors.LSMAudit.Enabled {
		lsm := lsmaudit.NewTailer("", hostname)
		activeSensors = append(activeSensors, lsm)
		log.Info("lsm audit sensor configured")
	}

	// Start all sensors
	for _, s := range activeSensors {
		if err := s.Start(ctx, events); err != nil {
			log.Warn("sensor start failed", "sensor", s.Name(), "err", err)
		} else {
			log.Info("sensor started", "sensor", s.Name())
		}
	}

	// Web dashboard — protected enterprise UI when cfg.UI.Enabled.
	// Falls back to legacy unprotected mode if not enabled, to keep
	// upgrades from older configs working.
	webServer = web.NewServer(web.Config{
		Addr:        webBindAddr(cfg),
		Log:         log,
		Store:       hot,
		Bus:         bus,
		Sensors:     activeSensors,
		Rules:       ruleEngine,
		Quarantine:  quarantine,
		Soak:        soak,
		PanicSwitch: panicSwitch,
		IncidentStore: foundation.IncidentStore,
		SourceStore:   foundation.SourceStore,
	})
	// T11 + T12 — 9-step containment ladder. Default observe-only;
	// raises to enforce-tier only when the operator sets a higher
	// `containment.max_step` in /etc/xhelix/xhelix.yaml. Evaluator
	// runs every eval_interval (default 30s) pulling endpointscore
	// and routing through Ladder.Handle.
	if cfg.Containment.Enabled {
		policy := buildContainmentPolicy(cfg.Containment)
		acts := containment.Actions{
			Alert: func(v containment.Verdict) error {
				bus.Send(model.Alert{
					RuleID: "containment.endpoint_breach",
					Reason: fmt.Sprintf("endpoint score %d (chain=%s) breached alert threshold", v.Score, v.Chain),
					Mode:   model.ModeDetect,
					Event: model.Event{
						Time:     v.At,
						Sensor:   "containment",
						Severity: model.SeverityHigh,
						Image:    v.Image,
						PID:      v.PID,
						Tags: map[string]string{
							"kind":   "endpoint_score_breach",
							"chain":  v.Chain,
							"score":  strconv.Itoa(v.Score),
							"source": v.SourceID,
						},
					},
				})
				return nil
			},
			KillProc: func(v containment.Verdict) error {
				if v.PID == 0 {
					return fmt.Errorf("kill_proc with PID=0")
				}
				return quarantine.Kill(v.PID)
			},
			QuarantineFile: func(v containment.Verdict) error {
				if v.PID == 0 {
					return fmt.Errorf("quarantine_file with PID=0")
				}
				_, err := quarantine.Stop(v.PID, "", v.Image, "containment.endpoint_breach")
				return err
			},
			BlockNet: func(v containment.Verdict) error {
				if banner == nil {
					return fmt.Errorf("netban not wired")
				}
				for _, ip := range v.DstIPs {
					parsed := net.ParseIP(ip)
					if parsed == nil {
						continue
					}
					if err := banner.Ban(parsed, "containment.endpoint_breach", 15*time.Minute); err != nil {
						log.Warn("containment.block_net: ban failed", "ip", ip, "err", err)
					}
				}
				return nil
			},
			PanicSwitch: func(v containment.Verdict) error {
				return panicSwitch.Arm()
			},
		}
		ladder := containment.New(policy, acts, log)
		evalInterval := cfg.Containment.EvalInterval
		if evalInterval <= 0 {
			evalInterval = 30 * time.Second
		}
		log.Info("containment ladder ready",
			"enabled", true,
			"max_step", policy.MaxStep.String(),
			"eval_interval", evalInterval.String())
		go runContainmentEvaluator(ctx, ladder, foundation, evalInterval, log)
	} else {
		log.Info("containment ladder disabled (default); set containment.enabled=true to activate observe mode")
	}

	enterpriseSrv := startWebServer(ctx, log, cfg, webServer, sessionTracker, banner, ruleEngine, soak, &uiStats{
		hot: hot, bus: bus, sessionTracker: sessionTracker, banner: banner,
	}, foundation.IncidentGraph)

	// SBOM periodic diff
	if cfg.SBOM.Enabled && sbomBaseline != nil {
		go runSBOMDiff(ctx, sbomBaseline, hostname, events, 1*time.Hour, log)
	}

	// Posture scans
	if cfg.Posture.Enabled {
		postureRunner := posture.NewRunner(cfg.Posture.Interval, hostname, cfg.Agent.StateDir, log)
		go postureRunner.Start(ctx, events)
		log.Info("posture runner started")
	}

	// Chain periodic tick
	if forensicsChain != nil {
		go func() {
			ticker := time.NewTicker(forensicsChain.Interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					_ = forensicsChain.Close()
					return
				case <-ticker.C:
					_ = forensicsChain.Tick()
				}
			}
		}()
	}

	// Self-protect integrity periodic verify
	if cfg.SelfProtect.Enabled && cfg.SelfProtect.Integrity && protector != nil {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					findings := protector.Verify()
					for _, f := range findings {
						log.Error("selfprotect integrity violation", "what", f.What, "reason", f.Reason)
						ev := model.NewEvent("selfprotect.integrity", model.SeverityCritical)
						ev.Host = hostname
						ev.Tags["what"] = f.What
						ev.Tags["path"] = f.Path
						ev.Tags["reason"] = f.Reason
						select {
						case events <- ev:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	// Dispatch loop
	go dispatch(ctx, log, events, hot, ruleEngine, corrEngine,
		yaraScanner, intelMgr, mlDetector,
		procTree, forensicsChain, imgCache, sessionTracker,
		beaconDet, dnsexfilDet, baselineAgg,
		cgroupClassifier, connTable, dnsCollector,
		shmDet, brandDet,
		emit,
		foundation.ColdStore,
		foundation.Catalog,
		egressObs,
		appIdentifier,
		vhostCorrelator,
		ipTS,
		procScrapeSensor,
		sniCheck,
		foundation.SourceMinter,
		foundation.FileTaint,
		foundation.SourceStore,
		foundation.BRPMatcher,
		foundation.BRPRuntime,
		foundation.BRPPhases,
		foundation.BRPWriterCache,
		foundation.IntegrityTester,
		foundation.VerifyEngine,
		foundation.BRPEdges,
		foundation.AssetResolver,
		foundation.SecretTaint,
		foundation.EgressGuard,
		foundation.IncidentGraph,
		foundation.SSHBrute,
		foundation.PkgMgr,
		foundation.LongWindow,
		foundation.CDNDNS,
		foundation.FlowStats)

	// Run the config audit at startup completion. Logs warnings for
	// any non-default config knob that nothing has registered to
	// consume. This is the architectural lock against the
	// "FileSink rotation / hot.db retention" bug class — three
	// instances logged in ERRORS.md before this lock landed.
	if findings := cfgAudit.Audit(&cfg); len(findings) > 0 {
		for _, f := range findings {
			log.Warn("config knob declared but no consumer registered",
				"key", f.Key, "value", f.Value, "issue", f.Issue,
				"action", "either wire a Witness in code OR remove the field from xhelix.yaml")
		}
	} else {
		log.Info("config audit clean — every non-default knob has a registered consumer",
			"stats", cfgAudit.Stats())
	}

	notifyReady()

	<-ctx.Done()
	log.Info("xhelix stopping")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()

	for _, s := range activeSensors {
		if err := s.Stop(stopCtx); err != nil {
			log.Warn("sensor stop error", "sensor", s.Name(), "err", err)
		}
	}

	if execGuard != nil {
		_ = execGuard.Stop()
	}
	if tamperG != nil {
		tamperG.Stop()
	}
	if kintCheck != nil {
		kintCheck.Stop()
	}
	if baselineStore != nil && baselineAgg != nil {
		// Drain in-memory windows so the last hour isn't lost on
		// shutdown. WriteSync (not Push) because by this point the
		// store's writer goroutine has likely already returned via
		// ctx.Done() — the channel has no consumer.
		final := baselineAgg.FlushAll()
		baselineStore.WriteSync(final)
		baselineStore.Stop()
		// Also enqueue for fleet upload if configured. Push() writes
		// to the on-disk queue synchronously; safe to call after the
		// uploader's retry goroutine has exited via ctx.Done — the
		// queued files persist across restart and the next daemon
		// instance will ship them on its first flush cycle.
		if baselineUploader != nil && len(final) > 0 {
			_ = baselineUploader.Push(final)
		}
	}
	if respEngine != nil {
		_ = respEngine.Stop(stopCtx)
	}

	_ = webServer.Stop(stopCtx)
	if enterpriseSrv != nil {
		// Drain the enterprise listener cleanly so connections in
		// flight finish and the bound port is released for reuse.
		// The legacy listener is owned by webServer.Stop above.
		_ = enterpriseSrv.Shutdown(stopCtx)
	}
	if forensicsChain != nil {
		_ = forensicsChain.Close()
	}
	bus.Close()
	log.Info("xhelix stopped")
	return nil
}


// dispatch is the thin event-loop wrapper. The per-event handler
// logic lives in pkg/pipeline.Pipeline.Handle — this function only
// owns the select on ctx.Done() and the events channel. Extracted
// in P-RF.7b; behaviour unchanged.
func dispatch(
	ctx context.Context,
	log *slog.Logger,
	events <-chan model.Event,
	hot *store.HotStore,
	eng *rules.Engine,
	corr *correlator.Engine,
	yaraScanner *yara.Scanner,
	intelMgr *intel.Manager,
	mlDetector *ml.AnomalyDetector,
	procTree *proctree.Graph,
	forensicsChain *chain.Chain,
	imgCache *imagecache.Cache,
	sessionTracker *session.Tracker,
	beaconDet *beacon.Detector,
	dnsexfilDet *dnsexfil.Detector,
	baselineAgg *baseline.Aggregator,
	cgroupClassifier *cgroupclass.Classifier,
	connTable *connstate.Table,
	dnsCollector *dnsresolver.Collector,
	shmDet *shmguard.Detector,
	brandDet *brandcheck.Detector,
	emit func(model.Alert),
	coldStore *coldstore.Store,
	cat *catalog.Catalog,
	egressObs *egressmon.Observer,
	appIdentifier *appident.Identifier,
	vhostCorrelator *vhostcorr.Correlator,
	ipTS *egressmon.IPTimeSeries,
	procScrapeSensor *procscrapesensor.Sensor,
	sniCheck *snicheck.Detector,
	srcMinter *source.Minter,
	fileTaint *source.FileTaint,
	srcStore *source.Store,
	brpMatcher *brp.Matcher,
	brpRuntime *brp.Runtime,
	brpPhases *brpphase.Tracker,
	brpWriterCache *writerattr.Cache,
	integrityTester *integrity.Tester,
	verifyEngine *verify.Engine,
	brpEdges *brp.EdgeSet,
	assetResolver assetclass.Resolver,
	secretTaint secrettaint.Store,
	egressGuard egressguard.Guard,
	incidentGraph incidentgraph.Engine,
	sshBrute *sshbrute.Detector,
	pkgMgrStore *pkgmgr.Store,
	longWindow *longwindow.Store,
	cdnDNS *cdndetect.DNSCache,
	flowStats *flowstats.Counters,
) {
	// Runtime allowlist — overlays /etc/xhelix/runtime-allowlist.yaml
	// on a baked-in default set covering Node/V8, JVM, .NET, Python,
	// dpkg/apt/snap, runc/docker, sudo/systemd. Missing file is not
	// an error; the daemon falls back to defaults. P-PS.25.
	ra, raErr := runtimeallow.LoadFile("/etc/xhelix/runtime-allowlist.yaml")
	if raErr != nil {
		log.Warn("runtime-allowlist load",
			"path", "/etc/xhelix/runtime-allowlist.yaml",
			"err", raErr,
			"fallback", "default set in use")
	} else {
		log.Info("runtime-allowlist loaded",
			"path", "/etc/xhelix/runtime-allowlist.yaml")
	}

	// Vendor catalog (P-AB.1): auto-detect hosting/control-panel
	// stacks installed on the host. Each detected vendor contributes
	// its known binary globs to the runtime allowlist seed so
	// xhelix doesn't treat Plesk/cPanel/etc. as anomalous in the
	// observation window. Missing /usr/share/xhelix/vendors is fine
	// — Default() ships the baked-in catalog.
	vc, _ := vendorcatalog.LoadDir("/usr/share/xhelix/vendors")
	vendorBinaries := vendorcatalog.AllBinaries(vc.AutoDetect())
	if len(vendorBinaries) > 0 {
		ra.Extend(vendorBinaries)
		var names []string
		for _, d := range vc.AutoDetect() {
			names = append(names, d.Vendor)
		}
		log.Info("vendor catalog auto-detected", "vendors", names,
			"binaries_added", len(vendorBinaries))
	}

	// Autobaseline (P-AB.1): per-host silent observation → sealed
	// detection. Database lives under the agent state dir; on a
	// fresh install the manager starts in OBSERVE mode and seals
	// after 24h. Pipeline.Handle queries IsKnown for suppression.
	abPath := "/var/lib/xhelix/autobaseline.db"
	abMgr, abErr := autobaseline.New(autobaseline.Options{
		DBPath:      abPath,
		Observation: 24 * time.Hour,
	})
	if abErr != nil {
		log.Warn("autobaseline init failed (continuing without)",
			"path", abPath, "err", abErr)
		abMgr = nil
	} else {
		log.Info("autobaseline ready",
			"mode", string(abMgr.Mode()),
			"db", abPath)
		// Periodic flush + auto-seal probe.
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := abMgr.Tick(ctx); err != nil {
						log.Warn("autobaseline tick", "err", err)
					}
				}
			}
		}()
	}

	// Burst detectors (P-AB.13). Wired with default thresholds:
	// 80 file-opens in 10s = "credential scan"; 20 spawns in 10s
	// = "process-recon loop". Both have 60s cooldown per PID so a
	// sustained burst from one attacker doesn't flood Slack.
	fileBurstT, spawnBurstT := burstdet.Defaults()
	fileBurst := burstdet.NewCounter(fileBurstT)
	spawnBurst := burstdet.NewCounter(spawnBurstT)
	// Sweep dead PIDs every 5 min so dropped exit events don't
	// leak memory.
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fileBurst.Sweep(time.Now(), 10*time.Minute)
				spawnBurst.Sweep(time.Now(), 10*time.Minute)
			}
		}
	}()
	log.Info("burst detectors configured",
		"file_window", fileBurstT.Window, "file_count", fileBurstT.Count,
		"spawn_window", spawnBurstT.Window, "spawn_count", spawnBurstT.Count)

	p := &pipeline.Pipeline{
		Log:              log,
		HotStore:         hot,
		Rules:            eng,
		Correlator:       corr,
		YaraScanner:      yaraScanner,
		IntelMgr:         intelMgr,
		MLDetector:       mlDetector,
		ProcTree:         procTree,
		ForensicsChain:   forensicsChain,
		ImageCache:       imgCache,
		SessionTracker:   sessionTracker,
		BeaconDet:        beaconDet,
		DNSExfilDet:      dnsexfilDet,
		BaselineAgg:      baselineAgg,
		CGroupClassifier: cgroupClassifier,
		ConnTable:        connTable,
		DNSCollector:     dnsCollector,
		ShmDet:           shmDet,
		BrandDet:         brandDet,
		Catalog:          cat,
		ColdStore:        coldStore,
		RuntimeAllow:     ra,
		AutoBaseline:     abMgr,
		FileReadBurst:    fileBurst,
		SpawnBurst:       spawnBurst,
		Emit:             emit,
		EgressObserver:   egressObs,
		AppIdent:         appIdentifier,
		VhostCorr:        vhostCorrelator,
		IPTimeSeries:     ipTS,
		ProcScrape:       procScrapeSensor,
		SNICheck:         sniCheck,
		SourceMinter:     srcMinter,
		FileTaint:        fileTaint,
		SourceStore:      srcStore,
		BRPMatcher:       brpMatcher,
		BRPRuntime:       brpRuntime,
		BRPPhases:        brpPhases,
		BRPWriterCache:   brpWriterCache,
		IntegrityTester:  integrityTester,
		VerifyEngine:     verifyEngine,
		BRPEdges:         brpEdges,
		AssetResolver:    assetResolver,
		SecretTaint:      secretTaint,
		EgressGuard:      egressGuard,
		IncidentGraph:    incidentGraph,
		SSHBrute:         sshBrute,
		PkgMgr:           pkgMgrStore,
		LongWindow:       longWindow,
		CDNDNS:           cdnDNS,
		FlowStats:        flowStats,
	}
	p.Run(ctx, events)
}
