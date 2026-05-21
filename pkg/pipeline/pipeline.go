// Package pipeline owns the per-event handling logic. One Handle()
// call per incoming model.Event runs every enrichment, persistence,
// rule-engine evaluation, and inline-detector emission xhelix
// performs. The dispatch goroutine in cmd/xhelix retains the
// for-select event-loop and just calls Handle().
//
// Extracted from cmd/xhelix/run.go's dispatch() function in
// P-RF.7b. NO behavior changes — same code, same call order, just
// across a package boundary so:
//   * Pipeline can be constructed with mock dependencies in tests
//   * dispatch() in cmd/xhelix is now ~30 lines (channel plumbing)
//   * Future refactors (P-RF.8/9) can break Handle apart into
//     smaller methods without touching the daemon entrypoint
//
// See REFACTOR_ROADMAP.md §2 for the design intent.
package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/autobaseline"
	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/beacon"
	"github.com/xhelix/xhelix/pkg/cronclassify"
	"github.com/xhelix/xhelix/pkg/brandcheck"
	"github.com/xhelix/xhelix/pkg/capwatch"
	"github.com/xhelix/xhelix/pkg/catalog"
	"github.com/xhelix/xhelix/pkg/cgroupclass"
	"github.com/xhelix/xhelix/pkg/chain"
	"github.com/xhelix/xhelix/pkg/cloudmeta"
	"github.com/xhelix/xhelix/pkg/coldstore"
	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/contescape"
	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/dnsexfil"
	"github.com/xhelix/xhelix/pkg/imagecache"
	"github.com/xhelix/xhelix/pkg/intel"
	"github.com/xhelix/xhelix/pkg/lolbin"
	"github.com/xhelix/xhelix/pkg/ml"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/ptraceguard"
	"github.com/xhelix/xhelix/pkg/revshell"
	"github.com/xhelix/xhelix/pkg/rules"
	"github.com/xhelix/xhelix/pkg/runtimeallow"
	"github.com/xhelix/xhelix/pkg/session"
	"github.com/xhelix/xhelix/pkg/shmguard"
	"github.com/xhelix/xhelix/pkg/store"
	"github.com/xhelix/xhelix/pkg/webshellguard"
	"github.com/xhelix/xhelix/pkg/yara"
	"github.com/xhelix/xhelix/sensors/dnsresolver"
	"github.com/xhelix/xhelix/sensors/netids"
)

// Pipeline holds every per-event dependency in one place. nil
// fields are tolerated — each branch in Handle() checks before use.
// The daemon constructs a single Pipeline and passes it to the
// dispatch goroutine.
type Pipeline struct {
	Log              *slog.Logger
	HotStore         *store.HotStore
	Rules            *rules.Engine
	Correlator       *correlator.Engine
	YaraScanner      *yara.Scanner
	IntelMgr         *intel.Manager
	MLDetector       *ml.AnomalyDetector
	ProcTree         *proctree.Graph
	ForensicsChain   *chain.Chain
	ImageCache       *imagecache.Cache
	SessionTracker   *session.Tracker
	BeaconDet        *beacon.Detector
	DNSExfilDet      *dnsexfil.Detector
	BaselineAgg      *baseline.Aggregator
	CGroupClassifier *cgroupclass.Classifier
	ConnTable        *connstate.Table
	DNSCollector     *dnsresolver.Collector
	ShmDet           *shmguard.Detector
	BrandDet         *brandcheck.Detector
	Catalog          *catalog.Catalog
	ColdStore        *coldstore.Store

	// RuntimeAllow recognises well-known userland runtimes that
	// exercise primitives xhelix flags as suspicious. When the
	// allowlist matches, Handle() sets event.tags["jit_allowlisted"]
	// to "true" so downstream rules can branch. Nil = empty
	// allowlist (no events tagged).
	RuntimeAllow *runtimeallow.Set

	// AutoBaseline drives the day-0 silent observation + day-1+
	// IsKnown query. When in ModeObserve, Handle() records
	// (image, behavior) and tags the event `baseline_observing=true`
	// so rules can suppress destructive actions. When in ModeDetect,
	// Handle() queries IsKnown and tags `baseline_known=true` on
	// matches so rules can branch. Nil is safe (no-op).
	AutoBaseline *autobaseline.Manager

	// Emit is the alert-bus sink. Required if any rule, detector,
	// or threat-intel branch can fire. Pipeline never holds an
	// alert bus directly — the daemon wires its own bus into a
	// closure and passes it as Emit.
	Emit func(model.Alert)
}

// Handle processes one event end-to-end. The full per-event chain:
//
//  1. Durable persistence (cold store) — non-blocking, drops on
//     overflow.
//  2. Session tracker ingest — identity events open/close sessions.
//  3. Per-binary baseline counter increment.
//  4. LOTL scoring on exec events (P-B.7).
//  5. Proc-tree update (spawn/exit/touch).
//  6. cgroup classification + event tagging.
//  7. Conn-state updates on net events.
//  8. Image-hash enrichment on spawn events.
//  9. Hot-store insert.
// 10. Evidence chain.Add (signed batch).
// 11. Rule engine evaluation.
// 12. Correlator ingest.
// 13. YARA scan on exec.
// 14. Argv-shape detectors (LOLBin, revshell, shm exec, webshell).
// 15. Capability-escalation classifier (capwatch).
// 16. Container-escape classifier (contescape).
// 17. ptrace classifier (ptraceguard).
// 18. Cloud-metadata abuse on outbound connect.
// 19. Brand-lookalike on DNS.
// 20. Threat-intel IP match on net events.
// 21. Beacon detector on outbound connect.
// 22. DNS observation collector (links qname → pid).
// 23. DNS exfiltration / tunneling detector.
// 24. NetIDS DGA scoring on DNS queries.
// 25. ML anomaly detector.
// 26. Ungated critical-severity alert.
//
// Same order as before P-RF.7b. Any reordering changes behavior
// and must be diff-tested against the golden corpus.
func (p *Pipeline) Handle(ctx context.Context, ev model.Event) {
	// Runtime-allowlist tag enrichment (P-PS.25). Set
	// event.tags["jit_allowlisted"] = "true" when the event's image
	// OR parent_image matches a known userland runtime. Rules in
	// pkg/response/policy.go and rule yamls already consult this
	// tag — setting it here is the systematic FP-reduction lever.
	if p.RuntimeAllow != nil {
		parentImage := ev.Tags["parent_image"]
		parentComm := ev.Tags["parent_comm"]
		if p.RuntimeAllow.MatchAny(ev.Image, ev.Comm) ||
			p.RuntimeAllow.MatchAny(parentImage, parentComm) {
			if ev.Tags == nil {
				ev.Tags = map[string]string{}
			}
			ev.Tags["jit_allowlisted"] = "true"
		}
	}

	// Autobaseline (P-AB.1): self-configuring per-host suppression.
	// In ModeObserve we record (image, behavior) silently and tag
	// the event so destructive rules know they're in the learning
	// window. In ModeDetect we tag matches against the sealed
	// profile so rules can branch on baseline_known.
	if p.AutoBaseline != nil {
		switch p.AutoBaseline.Mode() {
		case autobaseline.ModeObserve:
			if b, ok := autobaseline.EventToBehavior(ev); ok {
				p.AutoBaseline.Observe(autobaseline.ImageKey(ev), b)
			}
			if ev.Tags == nil {
				ev.Tags = map[string]string{}
			}
			ev.Tags["baseline_observing"] = "true"
		case autobaseline.ModeDetect:
			if b, ok := autobaseline.EventToBehavior(ev); ok {
				if p.AutoBaseline.IsKnown(autobaseline.ImageKey(ev), b) {
					if ev.Tags == nil {
						ev.Tags = map[string]string{}
					}
					ev.Tags["baseline_known"] = "true"
				}
			}
		}
	}

	// Cron classifier (P-AB.8). When a FIM event touches a cron
	// path, read the file and stamp content/owner tags so the
	// rule engine can fire on the malware shapes (curl|bash,
	// /tmp scripts, web-user-added entries) without needing a
	// sandbox.
	if (ev.Sensor == "fim" || ev.Sensor == "fim.drift") && ev.Tags != nil {
		if path := ev.Tags["path"]; isCronPath(path) {
			tags := cronclassify.Classify(path)
			for k, v := range tags {
				ev.Tags[k] = v
			}
			if score := cronclassify.Suspicion(tags); score > 0 {
				ev.Tags["cron_suspicion"] = fmt.Sprintf("%d", score)
			}
		}
	}

	// Durable persistence first. Non-blocking; the cold
	// store drops on overflow and counts it. Done up front
	// so even events that the downstream enrichment fails
	// to process are still recorded.
	if p.ColdStore != nil {
		evCopy := ev
		p.ColdStore.Submit(&evCopy)
	}
	// Feed session tracker first — it consumes identity
	// events to open/close sessions and tags subsequent
	// process spawns with the active session.
	if p.SessionTracker != nil {
		p.SessionTracker.Ingest(ev)
	}
	// Per-binary baseline aggregator. Every event becomes a
	// counter increment in the matching (binary, hour) window.
	if p.BaselineAgg != nil {
		p.BaselineAgg.Observe(ev)
	}
	// LOTL scoring (P-B.7): on exec events, look up the
	// (binary, parent_comm) risk score from the catalog
	// and stamp it on the event. CEL rules then fire on
	// thresholds. Skips entirely if the binary isn't a
	// tracked LOTL binary — fast path for the 95% case.
	if p.Catalog != nil &&
		(ev.Sensor == "ebpf.spawn" || ev.Sensor == "ebpf.proc") &&
		p.Catalog.LOTLBinary(ev.Comm) {
		parentComm := ev.Tags["parent_comm"]
		// No sensor stamps parent_comm today — derive it from
		// procTree if available.
		if parentComm == "" && p.ProcTree != nil && ev.ParentPID != 0 {
			if anc := p.ProcTree.Ancestors(ev.ParentPID, 1); len(anc) > 0 {
				parentComm = anc[0].Comm
			}
		}
		if score, ok := p.Catalog.LOTLScore(ev.Comm, parentComm); ok {
			if ev.Tags == nil {
				ev.Tags = map[string]string{}
			}
			ev.Tags["lotl_score"] = fmt.Sprintf("%d", score)
			if parentComm != "" {
				ev.Tags["parent_comm"] = parentComm
			}
		}
	}

	// Feed proc tree
	if p.ProcTree != nil {
		switch ev.Sensor {
		case "ebpf.spawn", "ebpf.proc":
			p.ProcTree.OnSpawn(proctree.Node{
				PID:       ev.PID,
				PPID:      ev.ParentPID,
				Comm:      ev.Comm,
				Image:     ev.Tags["image"],
				UID:       ev.UID,
				CGroupID:  ev.CGroupID,
				Container: ev.Container,
			})
		case "ebpf.exit":
			p.ProcTree.OnExit(ev.PID)
			if p.CGroupClassifier != nil {
				p.CGroupClassifier.Forget(ev.PID)
			}
		default:
			p.ProcTree.Touch(ev.PID)
		}
	}

	// Classify pid into cgroup class and stamp the event so
	// downstream rules + UI can filter user/system/container.
	// Cached after first call; no-op on subsequent events.
	if p.CGroupClassifier != nil && ev.PID != 0 {
		if info := p.CGroupClassifier.Classify(ev.PID); info.Class != cgroupclass.ClassUnknown {
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

	if p.ConnTable != nil && ev.Sensor == "ebpf.net" && ev.Tags["kind"] == "net_connect" {
		feedConnstate(p.ConnTable, p.CGroupClassifier, ev)
	}
	if p.ConnTable != nil && ev.Sensor == "ebpf.net" && ev.Tags["kind"] == "net_bytes" {
		feedConnstateBytes(p.ConnTable, ev)
	}

	// Enrich with image hash
	if p.ImageCache != nil && ev.Sensor == "ebpf.spawn" {
		if path := ev.Tags["path"]; path != "" {
			if img, err := p.ImageCache.Compute(ctx, path); err == nil {
				ev.Tags["image_sha256"] = img.SHA256
			}
		}
	}

	// Store
	if p.HotStore != nil {
		if err := p.HotStore.Insert(ctx, ev); err != nil {
			p.Log.Warn("hot store insert", "err", err)
		}
	}

	// Chain
	if p.ForensicsChain != nil {
		if err := p.ForensicsChain.Add(ev); err != nil {
			p.Log.Warn("chain add failed", "err", err)
		}
	}

	// Rules
	if p.Rules != nil {
		p.Rules.Eval(ctx, ev)
	}

	// Correlator
	if p.Correlator != nil {
		p.Correlator.Ingest(ctx, ev)
	}

	// YARA scan on execve events
	if p.YaraScanner != nil && p.YaraScanner.Enabled() && ev.Sensor == "ebpf.spawn" {
		if a := p.YaraScanner.ScanEvent(ctx, ev); a != nil {
			p.Emit(*a)
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
			p.Emit(model.Alert{
				Event: ev, RuleID: "lolbin.suspicious",
				Reason: fmt.Sprintf("LOLBin %s in suspicious context: %s",
					v.Tool, strings.Join(v.Reasons, "; ")),
				Mode: model.ModeDetect,
			})
		}
		// Reverse-shell argv shape
		if rs := revshell.Best(argv); rs.Confidence >= 70 {
			p.Emit(model.Alert{
				Event: ev, RuleID: "revshell.detected",
				Reason: fmt.Sprintf("Reverse-shell pattern %s (conf %d): %s",
					rs.Pattern, rs.Confidence, rs.Description),
				Mode: model.ModeDetect,
			})
		}
		// tmpfs exec
		if p.ShmDet != nil {
			if v := p.ShmDet.Evaluate(shmguard.Spawn{
				Exe: exe, Argv: argv, UID: ev.UID,
			}); v.Severity >= shmguard.SeverityHigh {
				p.Emit(model.Alert{
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
			p.Emit(model.Alert{
				Event: ev, RuleID: "webshell.argv",
				Reason: fmt.Sprintf("webshell %s (conf %d): %s",
					wsh.Family, wsh.Confidence, wsh.Reason),
				Mode: model.ModeDetect,
			})
		}
	}

	// Capability escalation (capset tracepoint).
	//
	// P-PS.25: skip when the runtime-allowlist matched (typically
	// sudo, su, systemd, runc — all of which legitimately gain
	// capability sets by design). The signal is preserved in the
	// event's tags for takeover scoring; only the standalone alert
	// is suppressed to keep operator triage focused on anomalous
	// capability gains.
	if ev.Sensor == "ebpf.cap" && ev.Tags["capset"] == "true" {
		eff := parseHexUint64(ev.Tags["cap_effective"])
		if f := capwatch.Classify(capwatch.Change{
			EffectiveAfter: eff,
			PID:            ev.PID, Comm: ev.Comm, Exe: ev.Image,
		}); f.Severity >= capwatch.SeverityHigh && len(f.Gained) > 0 &&
			ev.Tags["jit_allowlisted"] != "true" {
			p.Emit(model.Alert{
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
				p.Emit(model.Alert{
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
			Request:   parseUint32(ev.Tags["ptrace_request"]),
			SourcePID: ev.PID, SourceComm: ev.Comm, SourceExe: ev.Image,
			TargetPID:   parseUint32(ev.Tags["ptrace_target_pid"]),
			TargetComm:  ev.Tags["ptrace_target"],
			CGroupClass: ev.Tags["cgroup_class"],
		}); f.Severity >= ptraceguard.SeverityHigh {
			p.Emit(model.Alert{
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
			p.Emit(model.Alert{
				Event: ev, RuleID: "metadata.access_by_unexpected",
				Reason: hit.Reason + " (" + string(hit.Provider) + ")",
				Mode:   model.ModeDetect,
			})
		}
	}

	// Brand-local phishing on DNS queries.
	if p.BrandDet != nil && ev.Sensor == "netids" && ev.Tags["event_type"] == "dns" {
		if qname := ev.Tags["dns_qname"]; qname != "" {
			if m := p.BrandDet.Classify(qname); m.Family != brandcheck.FamilyNone &&
				m.Severity >= brandcheck.SeverityHigh {
				p.Emit(model.Alert{
					Event: ev, RuleID: "phishing.brand_lookalike",
					Reason: string(m.Family) + " of " + m.Brand + ": " + m.Reason,
					Mode:   model.ModeDetect,
				})
			}
		}
	}

	// ── End detector wire-ups ─────────────────────────

	// Threat intel on network events
	if p.IntelMgr != nil && (ev.Sensor == "ebpf.net" || ev.Sensor == "netids") {
		for _, tag := range []string{"dst_ip", "src_ip"} {
			if ipStr := ev.Tags[tag]; ipStr != "" {
				if ip := net.ParseIP(ipStr); ip != nil && p.IntelMgr.IsBad(ip) {
					p.Emit(model.Alert{
						Event:  ev,
						RuleID: "intel.bad_ip",
						Reason: fmt.Sprintf("Known malicious IP (%s): %s", tag, ipStr),
						Mode:   model.ModeDetect,
					})
				}
			}
		}
	}

	// Beacon detection on outbound connect events
	if p.BeaconDet != nil && (ev.Sensor == "ebpf.net" || ev.Sensor == "ebpf.tcp_connect") {
		if dst := ev.Tags["dst_ip"]; dst != "" {
			port := uint16(0)
			if pp := ev.Tags["dst_port"]; pp != "" {
				var n int
				_, _ = fmt.Sscanf(pp, "%d", &n)
				port = uint16(n)
			}
			if v := p.BeaconDet.Observe(beacon.Event{
				PID:     ev.PID,
				Comm:    ev.Comm,
				DstIP:   dst,
				DstPort: port,
				// P-RF.9g H2: use the sensor-stamped event time,
				// not wall-clock. Wall-clock breaks replay
				// determinism + skews beacon-period analysis
				// when events arrive batched.
				At: ev.Time,
			}); v != nil {
				ae := ev
				ae.Tags["beacon_count"] = fmt.Sprintf("%d", v.Count)
				ae.Tags["beacon_mean_gap_s"] = fmt.Sprintf("%.1f", v.MeanGap.Seconds())
				ae.Tags["beacon_jitter_cv"] = fmt.Sprintf("%.3f", v.JitterCV)
				p.Emit(model.Alert{
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
	if p.DNSCollector != nil && ev.Sensor == "netids" && ev.Tags["event_type"] == "dns" {
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
			p.DNSCollector.Observe(obs)
		}
	}

	// DNS exfiltration / tunneling
	if p.DNSExfilDet != nil && ev.Sensor == "netids" && ev.Tags["event_type"] == "dns" {
		qname := ev.Tags["dns_qname"]
		qtype := ev.Tags["dns_qtype"]
		if qname != "" {
			if v := p.DNSExfilDet.Observe(dnsexfil.Event{
				// P-RF.9g H2: ev.Time, not time.Now() — same
				// reason as the beacon detector above.
				Domain: qname, QType: qtype, At: ev.Time,
			}); v != nil {
				ae := ev
				ae.Tags["dnsexfil_reasons"] = strings.Join(v.Reasons, ",")
				ae.Tags["dnsexfil_avg_label_len"] = fmt.Sprintf("%.1f", v.AvgLabelLen)
				ae.Tags["dnsexfil_avg_entropy"] = fmt.Sprintf("%.2f", v.AvgEntropy)
				ae.Tags["dnsexfil_txt_frac"] = fmt.Sprintf("%.2f", v.TxtFraction)
				p.Emit(model.Alert{
					Event:  ae,
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
				p.Emit(model.Alert{
					Event:  ev,
					RuleID: "netids.dga",
					Reason: fmt.Sprintf("DGA score %.2f for %s", score, qname),
					Mode:   model.ModeDetect,
				})
			}
		}
	}

	// ML anomaly detection
	if p.MLDetector != nil && p.MLDetector.Observe(ev) {
		p.Emit(model.Alert{
			Event:  ev,
			RuleID: "ml.anomaly",
			Reason: fmt.Sprintf("Anomalous behavior: %s uid=%d", ev.Comm, ev.UID),
			Mode:   model.ModeDetect,
		})
	}

	// Gated critical alert
	if ev.Severity >= model.SeverityCritical {
		p.Emit(model.Alert{
			Event:  ev,
			RuleID: "ungated",
			Reason: ev.Tags["msg"],
			Mode:   model.ModeDetect,
		})
	}
}

// Run is the standard event-loop wrapper. Returns when ctx is
// cancelled or events is closed. The daemon's dispatch goroutine
// can now be reduced to:
//   go p.Run(ctx, eventsCh)
func (p *Pipeline) Run(ctx context.Context, events <-chan model.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			p.Handle(ctx, ev)
		}
	}
}

// isCronPath reports whether path is a cron drop-in location worth
// classifying. Keeping the list short avoids running the classifier
// on every FIM event.
func isCronPath(path string) bool {
	if path == "" {
		return false
	}
	if path == "/etc/crontab" || path == "/etc/anacrontab" {
		return true
	}
	switch {
	case strings.HasPrefix(path, "/etc/cron."):
		return true
	case strings.HasPrefix(path, "/var/spool/cron/"):
		return true
	}
	return false
}
