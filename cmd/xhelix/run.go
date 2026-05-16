package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/alert"
	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/beacon"
	"github.com/xhelix/xhelix/pkg/cgroupclass"
	"github.com/xhelix/xhelix/pkg/chain"
	"github.com/xhelix/xhelix/pkg/config"
	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/dnsexfil"
	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/execguard"
	"github.com/xhelix/xhelix/pkg/forensic"
	"github.com/xhelix/xhelix/pkg/imagecache"
	"github.com/xhelix/xhelix/pkg/intel"
	"github.com/xhelix/xhelix/pkg/kintegrity"
	"github.com/xhelix/xhelix/pkg/lockout"
	"github.com/xhelix/xhelix/pkg/memscan"
	"github.com/xhelix/xhelix/pkg/ml"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/netban"
	"github.com/xhelix/xhelix/pkg/posture"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/remediate"
	"github.com/xhelix/xhelix/pkg/response"
	"github.com/xhelix/xhelix/pkg/rules"
	"github.com/xhelix/xhelix/pkg/sbom"
	"github.com/xhelix/xhelix/pkg/selfprotect"
	"github.com/xhelix/xhelix/pkg/session"
	"github.com/xhelix/xhelix/pkg/store"
	"github.com/xhelix/xhelix/pkg/activity"
	"github.com/xhelix/xhelix/pkg/alertdedupe"
	"github.com/xhelix/xhelix/pkg/brandcheck"
	"github.com/xhelix/xhelix/pkg/capwatch"
	"github.com/xhelix/xhelix/pkg/cloudmeta"
	"github.com/xhelix/xhelix/pkg/contescape"
	"github.com/xhelix/xhelix/pkg/idlehint"
	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/lolbin"
	"github.com/xhelix/xhelix/pkg/ptraceguard"
	"github.com/xhelix/xhelix/pkg/revshell"
	"github.com/xhelix/xhelix/pkg/shmguard"
	storehistory "github.com/xhelix/xhelix/pkg/store/history"
	"github.com/xhelix/xhelix/pkg/suppression"
	"github.com/xhelix/xhelix/pkg/tamperguard"
	"github.com/xhelix/xhelix/pkg/webshellguard"
	"github.com/xhelix/xhelix/sensors/dnsresolver"
	"github.com/xhelix/xhelix/pkg/threatintel"
	"github.com/xhelix/xhelix/pkg/version"
	"github.com/xhelix/xhelix/pkg/yara"
	"github.com/xhelix/xhelix/sensors"
	"github.com/xhelix/xhelix/sensors/decoy"
	ebpfsensor "github.com/xhelix/xhelix/sensors/ebpf"
	fimsensor "github.com/xhelix/xhelix/sensors/fim"
	dpisensor "github.com/xhelix/xhelix/sensors/dpi"
	"github.com/xhelix/xhelix/sensors/heartbeat"
	"github.com/xhelix/xhelix/sensors/identity"
	"github.com/xhelix/xhelix/sensors/lsmaudit"
	"github.com/xhelix/xhelix/sensors/memory"
	"github.com/xhelix/xhelix/sensors/netids"
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
	log.Info("xhelix starting",
		"preset", cfg.Preset,
		"config", cfgPath,
		"version", version.Version,
		"commit", version.Commit,
	)

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

	// Alert sinks
	sinks := buildSinks(cfg.Alerts.Sinks, log)
	bus := alert.NewBus(sinks, 4096, log)

	ctx, cancel := signal.NotifyContext(parent,
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	// Bus pump
	go bus.Run(ctx)

	// Enforcement plane
	quarantine := enforce.NewQuarantine(enforce.DefaultSignalFn)
	soakDays := uint(30)
	if cfg.Response.SoakDays > 0 {
		soakDays = cfg.Response.SoakDays
	}
	soak := enforce.NewSoak(soakDays)
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
	if cfg.Forensic.Enabled {
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
			Logger: log,
		})
		_ = respEngine.Start(ctx)
		log.Info("response engine enabled")
	}

	// Exec-deny guard — fanotify FAN_OPEN_EXEC_PERM to prevent execve
	// of deny-listed binaries before they ever run. Independent of the
	// alert pipeline; runs continuously.
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
	// Declared early so emit's closure (assigned later) can capture
	// them; their actual instances are created further down.
	var dedupe *alertdedupe.Engine
	var liveHub *liveHubT
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
		if sessionTracker != nil {
			sessionTracker.IngestAlert(a)
		}
		if respEngine != nil {
			respEngine.OnAlert(a)
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
		// Broadcast to live SSE subscribers.
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
		if err := ruleEngine.Load(bundledRules); err != nil {
			log.Warn("failed to compile bundled rules", "err", err)
		} else {
			log.Info("rules loaded", "count", len(bundledRules))
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
	if err := apiSrv.Start(ctx); err != nil {
		log.Warn("LocalAPI failed to start", "err", err)
	} else {
		log.Info("LocalAPI listening", "socket", apiSock)
	}

	// Threat intel
	var intelMgr *intel.Manager
	if cfg.Intel.Enabled {
		intelMgr = intel.NewManager(intel.DefaultFeeds, filepath.Join(cfg.Agent.StateDir, "intel"), log)
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
				log.Info("forensics chain ready", "dir", chainDir)
			}
		}
	}

	// Event channel
	events := make(chan model.Event, 4096)

	hostname, _ := os.Hostname()

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
		fimSensor := fimsensor.NewSensor(fimDb, cfg.Sensors.FIM.WatchPaths, hostname, 5*time.Minute)
		activeSensors = append(activeSensors, fimSensor)
		log.Info("fim sensor configured", "db", fimDb, "paths", len(cfg.Sensors.FIM.WatchPaths))
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
	webServer := web.NewServer(web.Config{
		Addr:        webBindAddr(cfg),
		Log:         log,
		Store:       hot,
		Bus:         bus,
		Sensors:     activeSensors,
		Rules:       ruleEngine,
		Quarantine:  quarantine,
		Soak:        soak,
		PanicSwitch: panicSwitch,
	})
	enterpriseSrv := startWebServer(ctx, log, cfg, webServer, sessionTracker, banner, ruleEngine, soak, &uiStats{
		hot: hot, bus: bus, sessionTracker: sessionTracker, banner: banner,
	})

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
	go dispatch(ctx, log, events, hot, ruleEngine, corrEngine, bus, webServer,
		quarantine, soak, panicSwitch, yaraScanner, intelMgr, mlDetector,
		procTree, forensicsChain, imgCache, sessionTracker,
		beaconDet, dnsexfilDet, baselineAgg,
		cgroupClassifier, connTable, dnsCollector,
		shmDet, brandDet,
		emit)

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

func dispatch(
	ctx context.Context,
	log *slog.Logger,
	events <-chan model.Event,
	hot *store.HotStore,
	eng *rules.Engine,
	corr *correlator.Engine,
	bus *alert.Bus,
	webSrv *web.Server,
	quarantine *enforce.Quarantine,
	soak *enforce.Soak,
	panicSwitch *enforce.PanicSwitch,
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
) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-events:
			// Feed session tracker first — it consumes identity
			// events to open/close sessions and tags subsequent
			// process spawns with the active session.
			if sessionTracker != nil {
				sessionTracker.Ingest(ev)
			}
			// Per-binary baseline aggregator. Every event becomes a
			// counter increment in the matching (binary, hour) window.
			if baselineAgg != nil {
				baselineAgg.Observe(ev)
			}
			// Feed proc tree
			if procTree != nil {
				switch ev.Sensor {
				case "ebpf.spawn", "ebpf.proc":
					procTree.OnSpawn(proctree.Node{
						PID:       ev.PID,
						PPID:      ev.ParentPID,
						Comm:      ev.Comm,
						Image:     ev.Tags["image"],
						UID:       ev.UID,
						CGroupID:  ev.CGroupID,
						Container: ev.Container,
					})
				case "ebpf.exit":
					procTree.OnExit(ev.PID)
					if cgroupClassifier != nil {
						cgroupClassifier.Forget(ev.PID)
					}
				default:
					procTree.Touch(ev.PID)
				}
			}

			// Classify pid into cgroup class and stamp the event so
			// downstream rules + UI can filter user/system/container.
			// Cached after first call; no-op on subsequent events.
			if cgroupClassifier != nil && ev.PID != 0 {
				if info := cgroupClassifier.Classify(ev.PID); info.Class != cgroupclass.ClassUnknown {
					ev.Tags["cgroup_class"] = info.Class.String()
					if info.Unit != "" {
						ev.Tags["cgroup_unit"] = info.Unit
					}
					if info.UserID != "" {
						ev.Tags["cgroup_user_id"] = info.UserID
					}
					if info.ContainerID != "" && ev.Tags["container_id"] == "" {
						ev.Tags["container_id"] = info.ContainerID
					}
				}
			}

			if connTable != nil && ev.Sensor == "ebpf.net" && ev.Tags["kind"] == "net_connect" {
				feedConnstate(connTable, cgroupClassifier, ev)
			}
			if connTable != nil && ev.Sensor == "ebpf.net" && ev.Tags["kind"] == "net_bytes" {
				feedConnstateBytes(connTable, ev)
			}

			// Enrich with image hash
			if imgCache != nil && ev.Sensor == "ebpf.spawn" {
				if path := ev.Tags["path"]; path != "" {
					if img, err := imgCache.Compute(ctx, path); err == nil {
						ev.Tags["image_sha256"] = img.SHA256
					}
				}
			}

			// Store
			if err := hot.Insert(ctx, ev); err != nil {
				log.Warn("hot store insert", "err", err)
			}

			// Chain
			if forensicsChain != nil {
				if err := forensicsChain.Add(ev); err != nil {
					log.Warn("chain add failed", "err", err)
				}
			}

			// Rules
			if eng != nil {
				eng.Eval(ctx, ev)
			}

			// Correlator
			if corr != nil {
				corr.Ingest(ctx, ev)
			}

			// YARA scan on execve events
			if yaraScanner != nil && yaraScanner.Enabled() && ev.Sensor == "ebpf.spawn" {
				if a := yaraScanner.ScanEvent(ctx, ev); a != nil {
					bus.Send(*a)
					if webSrv != nil {
						webSrv.AddAlert(*a)
					}
				}
			}

			// ── Detector wire-ups (Integration #4) ──────────────
			// On every spawn event, run argv-shape classifiers.
			if ev.Sensor == "ebpf.spawn" || ev.Sensor == "ebpf.proc" {
				exe := ev.Image
				argv := splitArgv(ev.Tags["argv"])
				parentExe := ev.Tags["parent_exe"]

				// LOLBin context scoring
				if v := lolbin.Classify(lolbin.Spawn{
					Exe: exe, Argv: argv, ParentExe: parentExe,
					CGroupClass: ev.Tags["cgroup_class"],
				}); v.Severity >= lolbin.SeverityMedium {
					emit(model.Alert{
						Event: ev, RuleID: "lolbin.suspicious",
						Reason: fmt.Sprintf("LOLBin %s in suspicious context: %s",
							v.Tool, strings.Join(v.Reasons, "; ")),
						Mode: model.ModeDetect,
					})
				}
				// Reverse-shell argv shape
				if rs := revshell.Best(argv); rs.Confidence >= 70 {
					emit(model.Alert{
						Event: ev, RuleID: "revshell.detected",
						Reason: fmt.Sprintf("Reverse-shell pattern %s (conf %d): %s",
							rs.Pattern, rs.Confidence, rs.Description),
						Mode: model.ModeDetect,
					})
				}
				// tmpfs exec
				if shmDet != nil {
					if v := shmDet.Evaluate(shmguard.Spawn{
						Exe: exe, Argv: argv, UID: ev.UID,
					}); v.Severity >= shmguard.SeverityHigh {
						emit(model.Alert{
							Event: ev, RuleID: "shm.exec",
							Reason: "exec from " + v.Mount + ": " + strings.Join(v.Reasons, "; "),
							Mode:   model.ModeDetect,
						})
					}
				}
				// Webshell heuristic (php/python/node/ruby/perl -e with exec patterns)
				if wsh := webshellguard.Scan(webshellguard.Spec{
					Exe: exe, Argv: argv, ParentExe: parentExe,
				}); wsh.Family != webshellguard.FamilyNone && wsh.Confidence >= 70 {
					emit(model.Alert{
						Event: ev, RuleID: "webshell.argv",
						Reason: fmt.Sprintf("webshell %s (conf %d): %s",
							wsh.Family, wsh.Confidence, wsh.Reason),
						Mode: model.ModeDetect,
					})
				}
			}

			// Capability escalation (capset tracepoint).
			if ev.Sensor == "ebpf.cap" && ev.Tags["capset"] == "true" {
				eff := parseHexUint64(ev.Tags["cap_effective"])
				if f := capwatch.Classify(capwatch.Change{
					EffectiveAfter: eff,
					PID:            ev.PID, Comm: ev.Comm, Exe: ev.Image,
				}); f.Severity >= capwatch.SeverityHigh && len(f.Gained) > 0 {
					emit(model.Alert{
						Event: ev, RuleID: "cap.gained",
						Reason: "gained capabilities: " + strings.Join(f.Gained, ", "),
						Mode:   model.ModeDetect,
					})
				}
			}

			// Container-escape (pivot_root + unshare).
			if ev.Sensor == "ebpf.ns" {
				var spec contescape.Spec
				spec.PID = ev.PID
				spec.Comm = ev.Comm
				spec.Exe = ev.Image
				spec.CGroupClass = ev.Tags["cgroup_class"]
				if ev.Tags["kind"] == "pivot_root" {
					spec.Syscall = contescape.SyscallPivotRoot
				} else if ev.Tags["kind"] == "unshare" {
					spec.Syscall = contescape.SyscallUnshare
					spec.Flags = parseHexUint64(ev.Tags["unshare_flags"])
				}
				if spec.Syscall != 0 {
					if f := contescape.Classify(spec); f.Severity >= contescape.SeverityHigh {
						emit(model.Alert{
							Event: ev, RuleID: "contescape.detected",
							Reason: strings.Join(f.Reasons, "; "),
							Mode:   model.ModeDetect,
						})
					}
				}
			}

			// Ptrace classifier (existing ebpf ptrace events).
			if ev.Tags["ptrace_attach"] == "true" {
				if f := ptraceguard.Classify(ptraceguard.Spec{
					Request:    parseUint32(ev.Tags["ptrace_request"]),
					SourcePID:  ev.PID, SourceComm: ev.Comm, SourceExe: ev.Image,
					TargetPID:  parseUint32(ev.Tags["ptrace_target_pid"]),
					TargetComm: ev.Tags["ptrace_target"],
					CGroupClass: ev.Tags["cgroup_class"],
				}); f.Severity >= ptraceguard.SeverityHigh {
					emit(model.Alert{
						Event: ev, RuleID: "ptrace.suspicious",
						Reason: f.RequestName + " — " + strings.Join(f.Reasons, "; "),
						Mode:   model.ModeDetect,
					})
				}
			}

			// Cloud-metadata abuse on outbound connects.
			if ev.Sensor == "ebpf.net" && ev.Tags["kind"] == "net_connect" {
				if hit, ok := cloudmeta.Classify(cloudmeta.Context{
					IP: ev.Tags["dst_ip"], Comm: ev.Comm,
					ParentExe: ev.Tags["parent_exe"],
				}); ok && hit.Severity >= cloudmeta.SeverityHigh {
					emit(model.Alert{
						Event: ev, RuleID: "metadata.access_by_unexpected",
						Reason: hit.Reason + " (" + string(hit.Provider) + ")",
						Mode:   model.ModeDetect,
					})
				}
			}

			// Brand-local phishing on DNS queries.
			if brandDet != nil && ev.Sensor == "netids" && ev.Tags["event_type"] == "dns" {
				if qname := ev.Tags["dns_qname"]; qname != "" {
					if m := brandDet.Classify(qname); m.Family != brandcheck.FamilyNone &&
						m.Severity >= brandcheck.SeverityHigh {
						emit(model.Alert{
							Event: ev, RuleID: "phishing.brand_lookalike",
							Reason: string(m.Family) + " of " + m.Brand + ": " + m.Reason,
							Mode:   model.ModeDetect,
						})
					}
				}
			}

			// ── End detector wire-ups ─────────────────────────

			// Threat intel on network events
			if intelMgr != nil && (ev.Sensor == "ebpf.net" || ev.Sensor == "netids") {
				for _, tag := range []string{"dst_ip", "src_ip"} {
					if ipStr := ev.Tags[tag]; ipStr != "" {
						if ip := net.ParseIP(ipStr); ip != nil && intelMgr.IsBad(ip) {
							a := model.Alert{
								Event:  ev,
								RuleID: "intel.bad_ip",
								Reason: fmt.Sprintf("Known malicious IP (%s): %s", tag, ipStr),
								Mode:   model.ModeDetect,
							}
							bus.Send(a)
							if webSrv != nil {
								webSrv.AddAlert(a)
							}
						}
					}
				}
			}

			// Beacon detection on outbound connect events
			if beaconDet != nil && (ev.Sensor == "ebpf.net" || ev.Sensor == "ebpf.tcp_connect") {
				if dst := ev.Tags["dst_ip"]; dst != "" {
					port := uint16(0)
					if p := ev.Tags["dst_port"]; p != "" {
						var pp int
						_, _ = fmt.Sscanf(p, "%d", &pp)
						port = uint16(pp)
					}
					if v := beaconDet.Observe(beacon.Event{
						PID:     ev.PID,
						Comm:    ev.Comm,
						DstIP:   dst,
						DstPort: port,
						At:      time.Now(),
					}); v != nil {
						ae := ev
						ae.Tags["beacon_count"] = fmt.Sprintf("%d", v.Count)
						ae.Tags["beacon_mean_gap_s"] = fmt.Sprintf("%.1f", v.MeanGap.Seconds())
						ae.Tags["beacon_jitter_cv"] = fmt.Sprintf("%.3f", v.JitterCV)
						emit(model.Alert{
							Event:  ae,
							RuleID: "beacon.periodic_callback",
							Reason: fmt.Sprintf("Periodic callback to %s:%d every %s (CV %.2f, %d samples)",
								v.Key.DstIP, v.Key.DstPort, v.MeanGap.Round(time.Second), v.JitterCV, v.Count),
							Mode: model.ModeDetect,
						})
					}
				}
			}

			// DNS observation collector — link qname → pid so the
			// next outbound connect to a resolved IP gets the qname
			// stamped on its connstate row.
			if dnsCollector != nil && ev.Sensor == "netids" && ev.Tags["event_type"] == "dns" {
				qname := ev.Tags["dns_qname"]
				qtype := ev.Tags["dns_qtype"]
				if qname != "" {
					obs := dnsresolver.Observation{
						Query: dnsresolver.Query{
							At: ev.Time, QName: qname, QType: qtype,
							Upstream: ev.Tags["dns_upstream"],
						},
						Answer: dnsresolver.Answer{
							IPs: splitCSV(ev.Tags["dns_answers"]),
						},
						PID: ev.PID,
						Exe: ev.Image,
					}
					dnsCollector.Observe(obs)
				}
			}

			// DNS exfiltration / tunneling
			if dnsexfilDet != nil && ev.Sensor == "netids" && ev.Tags["event_type"] == "dns" {
				qname := ev.Tags["dns_qname"]
				qtype := ev.Tags["dns_qtype"]
				if qname != "" {
					if v := dnsexfilDet.Observe(dnsexfil.Event{
						Domain: qname, QType: qtype, At: time.Now(),
					}); v != nil {
						ae := ev
						ae.Tags["dnsexfil_reasons"] = strings.Join(v.Reasons, ",")
						ae.Tags["dnsexfil_avg_label_len"] = fmt.Sprintf("%.1f", v.AvgLabelLen)
						ae.Tags["dnsexfil_avg_entropy"] = fmt.Sprintf("%.2f", v.AvgEntropy)
						ae.Tags["dnsexfil_txt_frac"] = fmt.Sprintf("%.2f", v.TxtFraction)
						emit(model.Alert{
							Event: ae,
							RuleID: "dnsexfil.tunnel_pattern",
							Reason: fmt.Sprintf("DNS tunnel-shaped traffic to %s (%d queries, signals: %s)",
								v.RegDomain, v.Queries, strings.Join(v.Reasons, "+")),
							Mode: model.ModeDetect,
						})
					}
				}
			}

			// NetIDS detectors on DNS events
			if ev.Sensor == "netids" && ev.Tags["event_type"] == "dns" {
				qname := ev.Tags["dns_qname"]
				if qname != "" {
					score := netids.DGAScore(qname)
					if score > 0.7 {
						a := model.Alert{
							Event:  ev,
							RuleID: "netids.dga",
							Reason: fmt.Sprintf("DGA score %.2f for %s", score, qname),
							Mode:   model.ModeDetect,
						}
						bus.Send(a)
						if webSrv != nil {
							webSrv.AddAlert(a)
						}
					}
				}
			}

			// ML anomaly detection
			if mlDetector != nil && mlDetector.Observe(ev) {
				a := model.Alert{
					Event:  ev,
					RuleID: "ml.anomaly",
					Reason: fmt.Sprintf("Anomalous behavior: %s uid=%d", ev.Comm, ev.UID),
					Mode:   model.ModeDetect,
				}
				bus.Send(a)
				if webSrv != nil {
					webSrv.AddAlert(a)
				}
			}

			// Automated response for critical events
			if ev.Severity >= model.SeverityCritical && quarantine != nil && ev.PID != 0 {
				if panicSwitch != nil && panicSwitch.Armed() {
					log.Warn("panic switch armed; skipping quarantine", "pid", ev.PID)
				} else {
					ruleID := "ungated"
					if ev.Rule != "" {
						ruleID = ev.Rule
					}
					if soak != nil {
						soak.Track(ruleID, ev.Time)
						promotable, _ := soak.Promotable(ruleID, ev.Time)
						if promotable {
							if _, err := quarantine.Stop(ev.PID, ev.Comm, ev.Tags["image"], ruleID); err != nil {
								log.Warn("quarantine failed", "pid", ev.PID, "err", err)
							} else {
								log.Info("quarantined", "pid", ev.PID, "comm", ev.Comm, "rule", ruleID)
							}
						}
					} else {
						if _, err := quarantine.Stop(ev.PID, ev.Comm, ev.Tags["image"], ruleID); err != nil {
							log.Warn("quarantine failed", "pid", ev.PID, "err", err)
						} else {
							log.Info("quarantined", "pid", ev.PID, "comm", ev.Comm, "rule", ruleID)
						}
					}
				}
			}

			// Gated critical alert
			if ev.Severity >= model.SeverityCritical {
				a := model.Alert{
					Event:  ev,
					RuleID: "ungated",
					Reason: ev.Tags["msg"],
					Mode:   model.ModeDetect,
				}
				bus.Send(a)
				if webSrv != nil {
					webSrv.AddAlert(a)
				}
			}
		}
	}
}

func runSBOMDiff(
	ctx context.Context,
	baseline *sbom.Baseline,
	host string,
	out chan<- model.Event,
	interval time.Duration,
	log *slog.Logger,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			diff, err := baseline.Diff()
			if err != nil {
				log.Warn("sbom diff failed", "err", err)
				continue
			}
			for _, ev := range diff.ToEvents(host) {
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func loadOrGenerateEd25519Key(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(data), nil
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

func buildSinks(specs []config.SinkConfig, log *slog.Logger) []model.Sink {
	var out []model.Sink
	for _, s := range specs {
		switch s.Kind {
		case "stdout":
			out = append(out, alert.NewStdoutSink())
		case "file":
			fs, err := alert.NewFileSink(s.Path)
			if err != nil {
				log.Warn("file sink", "err", err, "path", s.Path)
				continue
			}
			out = append(out, fs)
		default:
			log.Warn("unknown sink kind", "kind", s.Kind)
		}
	}
	if len(out) == 0 {
		out = append(out, alert.NewStdoutSink())
	}
	return out
}

// hostnameOrEmpty returns the result of os.Hostname or "" on error.
// Used by the webhook formatter at startup before the dispatch loop
// has its hostname captured.
func hostnameOrEmpty() string {
	h, _ := os.Hostname()
	return h
}

// bannerOrNil returns the banner cast to the response.NetBanner
// interface, or nil if no banner is configured. Avoids a typed-nil
// gotcha in interface assignments.
func bannerOrNil(b *netban.Banner) response.NetBanner {
	if b == nil {
		return nil
	}
	return b
}

// remediatorOrNil — same pattern for remediator.
func remediatorOrNil(r *remediate.Remediator) response.Remediator {
	if r == nil {
		return nil
	}
	return r
}

// hostBannerOrNil — netban.Banner satisfies response.HostBanner, but
// returning a typed nil here would defeat == nil checks downstream.
func hostBannerOrNil(b *netban.Banner) response.HostBanner {
	if b == nil {
		return nil
	}
	return b
}

// snapshotterOrNil — same pattern for forensic.Snapshotter.
func snapshotterOrNil(s *forensic.Snapshotter) response.Snapshotter {
	if s == nil {
		return nil
	}
	return s
}

// buildExecGuardRules turns "deny:/tmp/" / "deny_prefix:/var/tmp/" /
// "deny_suffix:.sh" / "deny_contains:/.cache/" / "deny_eq:/usr/bin/foo"
// strings from config into execguard.Rule values. Unprefixed strings
// are treated as PathHasPrefix (the most common case). Returns nil
// when the input is empty so the caller can fall back to defaults.
func buildExecGuardRules(specs []string) []execguard.Rule {
	if len(specs) == 0 {
		return nil
	}
	out := make([]execguard.Rule, 0, len(specs))
	for _, s := range specs {
		r := execguard.Rule{Decision: execguard.Deny, Reason: "config: " + s}
		switch {
		case len(s) > 12 && s[:12] == "deny_prefix:":
			r.PathHasPrefix = s[12:]
		case len(s) > 12 && s[:12] == "deny_suffix:":
			r.PathHasSuffix = s[12:]
		case len(s) > 14 && s[:14] == "deny_contains:":
			r.PathContains = s[14:]
		case len(s) > 8 && s[:8] == "deny_eq:":
			r.PathEquals = s[8:]
		case len(s) > 5 && s[:5] == "deny:":
			r.PathHasPrefix = s[5:]
		default:
			r.PathHasPrefix = s
		}
		out = append(out, r)
	}
	return out
}

// scoreOneWindow runs both the set-diff scorer and the rate detector
// against one freshly-flushed baseline Window, and synthesises an
// Alert through the response pipeline whenever either fires.
//
// The Verdict + RateVerdict are also logged at INFO so the operator
// can see scoring activity in journalctl, even before any alert fires.
func scoreOneWindow(log *slog.Logger, scorer *baseline.Scorer, rate *baseline.RateDetector,
	w *baseline.Window, emit func(model.Alert)) {
	if w == nil {
		return
	}
	// emit is declared as a var early in runDaemon and assigned
	// later — there's a startup window where the baseline scoring
	// goroutine could fire before emit is assigned. Don't panic;
	// just skip the alert (a flushed window without an emit is
	// already on disk via the store).
	if emit == nil {
		return
	}
	if scorer != nil {
		if v := scorer.Score(w, time.Now().UTC()); v != nil {
			log.Warn("baseline scorer: behavioural deviation",
				"binary", v.Binary,
				"new_endpoints", v.NewEndpoints,
				"new_children", v.NewChildren,
				"new_file_writes", v.NewFileWrites,
				"new_syscalls", v.NewSyscalls,
				"baseline_windows", v.BaselineWindows,
				"hours_since_first", v.HoursSinceFirst,
			)
			ev := model.NewEvent("baseline.scorer", model.SeverityWarn)
			ev.Comm = w.Binary
			ev.Image = w.Binary
			ev.Time = w.Hour
			ev.Tags["binary"] = v.Binary
			if len(v.NewEndpoints) > 0 {
				ev.Tags["new_endpoints"] = strings.Join(v.NewEndpoints, ",")
			}
			if len(v.NewChildren) > 0 {
				ev.Tags["new_children"] = strings.Join(v.NewChildren, ",")
			}
			if len(v.NewFileWrites) > 0 {
				ev.Tags["new_file_writes"] = strings.Join(v.NewFileWrites, ",")
			}
			if len(v.NewSyscalls) > 0 {
				ev.Tags["new_syscalls"] = strings.Join(v.NewSyscalls, ",")
			}
			emit(model.Alert{
				Event:  ev,
				RuleID: "baseline.behavioural_deviation",
				Reason: fmt.Sprintf("Binary %s deviated: %s", v.Binary,
					summariseVerdict(v)),
				Mode: model.ModeDetect,
			})
		}
	}
	if rate != nil {
		if r := rate.Observe(w); r != nil {
			log.Warn("baseline rate: spike",
				"binary", r.Binary,
				"current_events", r.CurrentEvents,
				"baseline_mean", r.BaselineMean,
				"sigma_above", r.SigmaAbove,
			)
			ev := model.NewEvent("baseline.rate", model.SeverityWarn)
			ev.Comm = w.Binary
			ev.Image = w.Binary
			ev.Time = w.Hour
			ev.Tags["binary"] = r.Binary
			ev.Tags["current_events"] = fmt.Sprintf("%d", r.CurrentEvents)
			ev.Tags["baseline_mean"] = fmt.Sprintf("%.1f", r.BaselineMean)
			ev.Tags["sigma_above"] = fmt.Sprintf("%.2f", r.SigmaAbove)
			emit(model.Alert{
				Event:  ev,
				RuleID: "baseline.rate_spike",
				Reason: fmt.Sprintf("Binary %s rate spike: %d events vs baseline mean %.0f (%.1fσ)",
					r.Binary, r.CurrentEvents, r.BaselineMean, r.SigmaAbove),
				Mode: model.ModeDetect,
			})
		}
	}
}

func summariseVerdict(v *baseline.Verdict) string {
	parts := []string{}
	if n := len(v.NewEndpoints); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new endpoint(s)", n))
	}
	if n := len(v.NewChildren); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new child comm(s)", n))
	}
	if n := len(v.NewFileWrites); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new file write target(s)", n))
	}
	if n := len(v.NewSyscalls); n > 0 {
		parts = append(parts, fmt.Sprintf("%d new sensor(s)", n))
	}
	return strings.Join(parts, "; ")
}

func newLogger(cfg config.LoggingConfig) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	var w *os.File = os.Stdout
	if cfg.Destination == "stderr" {
		w = os.Stderr
	}

	var h slog.Handler
	if cfg.Format == "json" {
		h = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	} else {
		h = slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	}
	return slog.New(h)
}

// splitCSV is a forgiving comma-and-space splitter used for the
// dns_answers tag emitted by sensors/netids. Empty input returns nil.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// feedConnstateBytes folds a net_bytes ebpf event into connstate's
// per-flow BytesIn/BytesOut counters. Cheap; non-fatal on missing tags.
func feedConnstateBytes(tab *connstate.Table, ev model.Event) {
	dst := ev.Tags["dst_ip"]
	if dst == "" {
		return
	}
	addr, err := netip.ParseAddr(dst)
	if err != nil {
		return
	}
	var dport, sport uint16
	if p := ev.Tags["dst_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		dport = uint16(pp)
	}
	if p := ev.Tags["src_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		sport = uint16(pp)
	}
	var nbytes uint64
	if b := ev.Tags["bytes"]; b != "" {
		_, _ = fmt.Sscanf(b, "%d", &nbytes)
	}
	if nbytes == 0 {
		return
	}
	var dir uint8
	if ev.Tags["dir"] == "in" {
		dir = 1
	}
	tab.UpdateBytes(connstate.Tuple{
		Proto: connstate.ProtoTCP, SrcPort: sport,
		DstAddr: addr, DstPort: dport,
	}, dir, nbytes)
}

// feedConnstate converts an ebpf.net net_connect event into a
// connstate.ConnectEvent and inserts it. Tolerates missing fields:
// source port is currently zero (eBPF sys_enter_connect can't see
// it pre-bind — see docs/IMPLEMENTATION_TRACKER.md T0.4).
func feedConnstate(tab *connstate.Table, classifier *cgroupclass.Classifier, ev model.Event) {
	dstStr := ev.Tags["dst_ip"]
	if dstStr == "" {
		return
	}
	dstAddr, err := netip.ParseAddr(dstStr)
	if err != nil {
		return
	}
	port := uint16(0)
	if p := ev.Tags["dst_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		port = uint16(pp)
	}
	srcPort := uint16(0)
	if p := ev.Tags["src_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		srcPort = uint16(pp)
	}
	tuple := connstate.Tuple{
		Proto:   connstate.ProtoTCP,
		SrcPort: srcPort,
		DstAddr: dstAddr,
		DstPort: port,
	}
	ce := connstate.ConnectEvent{
		Time:  ev.Time,
		PID:   ev.PID,
		PPID:  ev.ParentPID,
		Comm:  ev.Comm,
		Exe:   ev.Image,
		Tuple: tuple,
	}
	if classifier != nil && ev.PID != 0 {
		info := classifier.Classify(ev.PID)
		ce.CGroupClass = info.Class
		ce.Unit = info.Unit
		ce.UserID = info.UserID
	}
	if sha := ev.Tags["image_sha256"]; sha != "" {
		ce.ExeSHA = sha
	}
	tab.OnConnect(ce)
}

// ── Integration helpers ────────────────────────────────────────

// runActivityPersister snapshots the live conn table, clusters
// flows into activities, and writes them to the history store.
func runActivityPersister(ctx context.Context, log *slog.Logger,
	clusterer *activity.Clusterer, tab *connstate.Table, store *storehistory.Store) {

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()

	// We track which conn-table rows we've already shipped via
	// (pid, opened_at_unix). Real implementations key on a real
	// flow ID; this is a smaller correct-by-construction approach
	// for the integration MVP.
	seen := map[string]struct{}{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			snap := tab.Snapshot()
			for _, c := range snap {
				key := fmt.Sprintf("%d|%s|%d", c.PID, c.Tuple.DstAddr.String(), c.OpenedAt.UnixNano())
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				clusterer.Add(activity.Flow{
					ProcessID: int64(c.PID),
					Proto:     c.Tuple.Proto.String(),
					DstIP:     c.Tuple.DstAddr.String(),
					DstPort:   c.Tuple.DstPort,
					DNSQName:  c.DNSName,
					OpenedAt:  c.OpenedAt,
					ClosedAt:  c.ClosedAt,
					BytesIn:   c.BytesIn,
					BytesOut:  c.BytesOut,
					Verdict:   activity.VerdictGreen,
				})
			}
			// Bound the seen map to recent samples.
			if len(seen) > 100_000 {
				seen = map[string]struct{}{}
			}

			closed := clusterer.Flush(time.Now())
			for _, a := range closed {
				cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if _, err := store.InsertActivity(cctx, storehistory.Activity{
					ProcessID:    a.ProcessID,
					StartedAt:    a.StartedAt,
					EndedAt:      a.EndedAt,
					PrimaryHost:  a.PrimaryHost,
					RelatedHosts: a.RelatedHosts,
					PrimaryIP:    a.PrimaryIP,
					RelatedIPs:   a.RelatedIPs,
					Countries:    a.Countries,
					ASNs:         a.ASNs,
					BytesIn:      a.BytesIn,
					BytesOut:     a.BytesOut,
					FlowCount:    a.FlowCount,
					Verdict:      string(a.Verdict),
					VerdictScore: a.VerdictScore,
					Reasons:      a.Reasons,
					Protocols:    a.Protocols,
				}); err != nil {
					log.Warn("history insert failed", "err", err)
				}
				cancel()
			}
		}
	}
}

// runHistoryPruner periodically prunes the history store.
func runHistoryPruner(ctx context.Context, log *slog.Logger, store *storehistory.Store) {
	t := time.NewTicker(1 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			res, err := store.Prune(cctx, storehistory.DefaultRetention(), time.Now())
			cancel()
			if err != nil {
				log.Warn("history prune failed", "err", err)
				continue
			}
			log.Info("history prune ok",
				"flows", res.Flows, "dns", res.DNSQueries,
				"activities", res.Activities, "processes", res.Processes,
				"sessions", res.Sessions)
		}
	}
}

// runHeartbeatWriter writes /run/xhelix.heartbeat for the Rust
// watchdog. Best-effort — if the runtime dir doesn't exist or
// isn't writable, we log once and skip.
func runHeartbeatWriter(ctx context.Context, log *slog.Logger, runtimeDir string) {
	if runtimeDir == "" {
		runtimeDir = "/run"
	}
	path := filepath.Join(runtimeDir, "xhelix.heartbeat")
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			data := []byte(fmt.Sprintf("%d\n", now.Unix()))
			if err := os.WriteFile(path, data, 0o644); err != nil {
				if first {
					log.Warn("heartbeat write failed; watchdog will see stale", "err", err)
					first = false
				}
				continue
			}
		}
	}
}

// runIdlePoller advances the idle-hint detector every 5s.
func runIdlePoller(ctx context.Context, log *slog.Logger, det *idlehint.Detector) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, err := det.Poll()
			if err != nil {
				// Polling /proc/interrupts can fail in containers
				// without /proc bind-mounted; log once.
				log.Debug("idlehint poll", "err", err)
			}
		}
	}
}

// runShmRefresher reloads the tmpfs mount snapshot every minute
// so newly-added shmguard.Detector mounts pick up.
func runShmRefresher(ctx context.Context, log *slog.Logger, det *shmguard.Detector) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			det.Refresh(loadTmpfsMounts(log))
		}
	}
}

// loadTmpfsMounts reads /proc/mounts and returns tmpfs paths.
func loadTmpfsMounts(log *slog.Logger) []string {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		log.Debug("loadTmpfsMounts", "err", err)
		return nil
	}
	defer f.Close()
	d := shmguard.FromProcMounts(f)
	return d.Mounts()
}

// splitArgv parses a space-separated argv string.
func splitArgv(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// parseHexUint64 parses "0x..." or decimal; 0 on error.
func parseHexUint64(s string) uint64 {
	if s == "" {
		return 0
	}
	s = strings.TrimPrefix(s, "0x")
	var v uint64
	_, _ = fmt.Sscanf(s, "%x", &v)
	return v
}

// parseUint32 parses decimal; 0 on error.
func parseUint32(s string) uint32 {
	if s == "" {
		return 0
	}
	var v uint32
	_, _ = fmt.Sscanf(s, "%d", &v)
	return v
}

// registerLocalAPIHandlers wires the daemon's pkg/localapi.Server
// to handlers backed by the daemon's live state.
func registerLocalAPIHandlers(srv *localapi.Server, hist *storehistory.Store,
	supp *suppression.Store, dedupe *alertdedupe.Engine, tab *connstate.Table,
	hub *liveHubT, vctx *verdictCtx, ph *procHistory, log *slog.Logger) {

	srv.RegisterHandler("history.list", func(ctx context.Context, _ json.RawMessage) (any, error) {
		if hist == nil {
			return map[string]any{"activities": []any{}}, nil
		}
		// Direct SQL via the store's DB handle; cheap convenient view.
		rows, err := hist.DB().QueryContext(ctx, `
			SELECT id, process_id, started_at, ended_at, primary_host,
			       primary_ip, bytes_in, bytes_out, flow_count, verdict
			FROM activities
			WHERE started_at >= ?
			ORDER BY started_at DESC LIMIT 200`,
			time.Now().Add(-24*time.Hour).Unix())
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []map[string]any
		for rows.Next() {
			var (
				id, pid, start, end                  int64
				bytesIn, bytesOut                    uint64
				flows                                int
				host, ip, verdict                    string
			)
			_ = rows.Scan(&id, &pid, &start, &end, &host, &ip, &bytesIn, &bytesOut, &flows, &verdict)
			out = append(out, map[string]any{
				"id":           id,
				"process_id":   pid,
				"started_at":   time.Unix(start, 0).Format(time.RFC3339),
				"ended_at":     time.Unix(end, 0).Format(time.RFC3339),
				"primary_host": host,
				"primary_ip":   ip,
				"bytes_in":     bytesIn,
				"bytes_out":    bytesOut,
				"flow_count":   flows,
				"verdict":      verdict,
			})
		}
		return map[string]any{"activities": out}, nil
	})

	srv.RegisterHandler("processes.list", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return processesList(tab, vctx, ph)
	})

	srv.RegisterHandler("process.detail", func(ctx context.Context, raw json.RawMessage) (any, error) {
		return processDetail(tab, vctx, ph, raw)
	})

	srv.RegisterHandler("verdict.explain", func(ctx context.Context, raw json.RawMessage) (any, error) {
		return verdictExplain(vctx, raw)
	})

	srv.RegisterHandler("policy.get", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return policyGet(vctx)
	})

	srv.RegisterHandler("policy.save", func(ctx context.Context, raw json.RawMessage) (any, error) {
		return policySave(vctx, raw)
	})

	srv.RegisterHandler("policy.toggle_telemetry", func(ctx context.Context, raw json.RawMessage) (any, error) {
		return policyToggleTelemetry(vctx, raw)
	})

	srv.RegisterHandler("policy.upsert_app", func(ctx context.Context, raw json.RawMessage) (any, error) {
		return policyUpsertApp(vctx, raw)
	})

	srv.RegisterHandler("process.investigate", func(ctx context.Context, raw json.RawMessage) (any, error) {
		return processInvestigate(ctx, raw)
	})

	srv.RegisterHandler("alerts.list", func(ctx context.Context, _ json.RawMessage) (any, error) {
		clusters := dedupe.Promote(time.Now(), alertdedupe.SeverityNotice)
		out := make([]map[string]any, 0, len(clusters))
		for _, c := range clusters {
			out = append(out, map[string]any{
				"rule_id":  c.RuleID,
				"exe":      c.Exe,
				"exe_sha":  c.ExeSHA,
				"dst_ip":   c.DstIP,
				"count":    c.Count,
				"score":    c.Score,
				"severity": c.Severity.String(),
				"reasons":  c.Reasons,
			})
		}
		return map[string]any{"alerts": out}, nil
	})

	srv.RegisterHandler("suppression.add", func(ctx context.Context, raw json.RawMessage) (any, error) {
		var req struct {
			RuleID, ExeSHA, DstIP, Reason string
			TTLSeconds                    int64 `json:"ttl_seconds"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		key := suppression.DefaultKey(req.RuleID, req.ExeSHA, req.DstIP)
		ttl := time.Duration(req.TTLSeconds) * time.Second
		e := supp.Add(key, suppression.Reason(req.Reason), ttl, "ui")
		return map[string]any{"ok": true, "key": string(e.Key)}, nil
	})

	srv.RegisterHandler("enforce.action", func(ctx context.Context, raw json.RawMessage) (any, error) {
		// Hook into pkg/enforce — for the MVP we just log the
		// request and return ack. The full quarantine path is
		// wired separately in the bus → response pipeline.
		log.Info("enforce request", "raw", string(raw))
		return map[string]any{"ok": true, "deferred": true}, nil
	})

	srv.RegisterHandler("intent.poll", func(ctx context.Context, _ json.RawMessage) (any, error) {
		// MVP — no pending prompts. Real implementation queues
		// prompts from the dispatch path when a borderline rule
		// fires (e.g. large upload with idle user).
		return map[string]any{}, nil
	})

	srv.RegisterHandler("intent.decide", func(ctx context.Context, raw json.RawMessage) (any, error) {
		log.Info("intent decision", "raw", string(raw))
		return map[string]any{"ok": true}, nil
	})

	// stream.events — server-streaming endpoint that the UI's
	// "live" tab subscribes to. We push every alert as it fires
	// + a periodic conn-state snapshot.
	srv.RegisterStreamer("stream.events", func(ctx context.Context, _ json.RawMessage, out chan<- any) error {
		sub := hub.subscribe(64)
		defer hub.unsubscribe(sub)
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case ev := <-sub:
				select {
				case out <- ev:
				case <-ctx.Done():
					return nil
				}
			case <-t.C:
				stats := tab.Stats()
				snap := map[string]any{
					"kind":     "stats",
					"ts":       time.Now().Format(time.RFC3339),
					"live":     stats.Live,
					"closed":   stats.Closed,
					"by_class": stats.ByClass,
				}
				select {
				case out <- snap:
				case <-ctx.Done():
					return nil
				}
			}
		}
	})
}
