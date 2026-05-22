package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/activity"
	"github.com/xhelix/xhelix/pkg/alert"
	"github.com/xhelix/xhelix/pkg/alertdedupe"
	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/config"
	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/execguard"
	"github.com/xhelix/xhelix/pkg/forensic"
	"github.com/xhelix/xhelix/pkg/idlehint"
	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/netban"
	"github.com/xhelix/xhelix/pkg/remediate"
	"github.com/xhelix/xhelix/pkg/response"
	"github.com/xhelix/xhelix/pkg/sbom"
	"github.com/xhelix/xhelix/pkg/shmguard"
	"github.com/xhelix/xhelix/pkg/store"
	storehistory "github.com/xhelix/xhelix/pkg/store/history"
	"github.com/xhelix/xhelix/pkg/suppression"
)

// This file holds helper functions that runDaemon + dispatch call
// into. Extracted from run.go in P-RF.7 to keep the god-file under
// 2000 lines. NO behavior changes — same code, same package, just
// across a file boundary.

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
			opts := alert.FileSinkOptions{
				MaxSizeBytes: int64(s.RotateSizeMB) * 1024 * 1024,
				Keep:         int(s.Keep),
			}
			fs, err := alert.NewFileSinkWithOptions(s.Path, opts)
			if err != nil {
				log.Warn("file sink", "err", err, "path", s.Path)
				continue
			}
			log.Info("file sink configured", "path", s.Path,
				"rotate_mb", s.RotateSizeMB, "keep", s.Keep)
			out = append(out, fs)
		case "webhook", "slack", "teams":
			// 'webhook' is the generic kind; 'slack' / 'teams' are
			// operator-friendly aliases. The WebhookSink itself
			// auto-detects the format from the URL host.
			if s.URL == "" {
				log.Warn("webhook sink missing url; skipping", "kind", s.Kind)
				continue
			}
			h, _ := os.Hostname()
			out = append(out, alert.NewWebhookSink(s.URL, h))
			log.Info("webhook sink configured", "kind", s.Kind, "url_host", urlHost(s.URL))
		default:
			log.Warn("unknown sink kind", "kind", s.Kind)
		}
	}
	if len(out) == 0 {
		out = append(out, alert.NewStdoutSink())
	}
	return out
}

// compactTags returns a small subset of event tags that the TUI
// alerts list needs. Keeps payload small per-row; full tags are
// available via tui.alert_detail.
func compactTags(tags map[string]string) map[string]string {
	if tags == nil {
		return nil
	}
	keep := []string{
		"dst_ip", "dst_port", "src_ip", "sni", "http_host", "dest_class",
		"app_id", "app_kind", "honey_marker", "sealed_path",
		"argv", "qname", "dns_answers",
	}
	out := map[string]string{}
	for _, k := range keep {
		if v, ok := tags[k]; ok && v != "" {
			out[k] = v
		}
	}
	return out
}

// urlHost extracts the hostname from a URL for logging without
// leaking the full path (which may contain a secret webhook token).
func urlHost(u string) string {
	// quick parse — don't import net/url just for this
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	if j := strings.IndexAny(rest, "/?"); j >= 0 {
		rest = rest[:j]
	}
	return rest
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

// runHotStorePruner enforces retention + size cap on the hot store.
// Fixes the bug where retention_hours + max_size_mb were declared
// in xhelix.yaml but never enforced (see ERRORS.md for the 14GB
// hot.db incident).
func runHotStorePruner(ctx context.Context, log *slog.Logger, h *store.HotStore, retention time.Duration, maxBytes int64) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			cutoff := time.Now().Add(-retention).UnixNano()
			byTime, err := h.Prune(cctx, cutoff)
			if err != nil {
				log.Warn("hot prune (time) failed", "err", err)
				cancel()
				continue
			}
			bySize, err := h.PruneBySize(cctx, maxBytes)
			if err != nil {
				log.Warn("hot prune (size) failed", "err", err)
				cancel()
				continue
			}
			size, _ := h.FileSize()
			cancel()
			if byTime > 0 || bySize > 0 {
				log.Info("hot store pruned",
					"by_time_rows", byTime, "by_size_rows", bySize,
					"file_bytes", size, "retention", retention,
					"max_bytes", maxBytes)
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
				id, pid, start, end int64
				bytesIn, bytesOut   uint64
				flows               int
				host, ip, verdict   string
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
