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
	"strconv"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/autobaseline"
	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/beacon"
	"github.com/xhelix/xhelix/pkg/assetclass"
	"github.com/xhelix/xhelix/pkg/brp"
	brpphase "github.com/xhelix/xhelix/pkg/brp/phase"
	"github.com/xhelix/xhelix/pkg/brp/writerattr"
	"github.com/xhelix/xhelix/pkg/egressguard"
	"github.com/xhelix/xhelix/pkg/incidentgraph"
	"github.com/xhelix/xhelix/pkg/sshbrute"
	"github.com/xhelix/xhelix/pkg/secrettaint"
	"github.com/xhelix/xhelix/pkg/integrity"
	"github.com/xhelix/xhelix/pkg/verify"
	"github.com/xhelix/xhelix/pkg/burstdet"
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
	"github.com/xhelix/xhelix/pkg/appident"
	"github.com/xhelix/xhelix/pkg/dnsexfil"
	"github.com/xhelix/xhelix/pkg/egressmon"
	"github.com/xhelix/xhelix/pkg/imagecache"
	"github.com/xhelix/xhelix/pkg/vhostcorr"
	"github.com/xhelix/xhelix/pkg/intel"
	"github.com/xhelix/xhelix/pkg/lineage"
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
	"github.com/xhelix/xhelix/pkg/source"
	"github.com/xhelix/xhelix/pkg/store"
	"github.com/xhelix/xhelix/pkg/webshellguard"
	"github.com/xhelix/xhelix/pkg/yara"
	"github.com/xhelix/xhelix/pkg/snicheck"
	"github.com/xhelix/xhelix/sensors/dnsresolver"
	"github.com/xhelix/xhelix/sensors/procscrape"
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

	// FileReadBurst / SpawnBurst (P-AB.13) — per-PID sliding-window
	// counters that fire when a single PID opens or spawns at a
	// rate higher than a healthy workload would. Catches the
	// credential-scan stage of Megalodon and TeamTNT-class
	// malware where one process reads hundreds of files (grep for
	// AWS keys) or spawns dozens of children (find / grep loop).
	// Nil-safe.
	FileReadBurst *burstdet.Counter
	SpawnBurst    *burstdet.Counter

	// IPTimeSeries persists per-IP bytes-in/out time-buckets for
	// the graph view. Nil-safe — operator may run egress observer
	// without timeseries persistence to save disk.
	IPTimeSeries *egressmon.IPTimeSeries

	// EgressObserver (P-EGRESS.M1) classifies outbound connects and
	// records per-lineage destination counters. Nil-safe; when the
	// `egress.observe` config flag is false the daemon doesn't
	// construct one. When non-nil, Handle() calls Observe on every
	// outbound connect event and stamps the resulting class onto
	// event.Tags["dest_class"] so sinks + rules can see it.
	EgressObserver *egressmon.Observer

	// AppIdent identifies app names from event signals (cgroup, exe,
	// argv). Nil-safe; identification is skipped when nil. Stamps
	// event.Tags["app_id"] for downstream analytics + grouping.
	AppIdent *appident.Identifier

	// VhostCorr correlates inbound HTTP requests with subsequent
	// outbound connects so analytics can attribute outbound bytes
	// to the originating virtual host. Nil-safe.
	VhostCorr *vhostcorr.Correlator

	// Emit is the alert-bus sink. Required if any rule, detector,
	// or threat-intel branch can fire. Pipeline never holds an
	// alert bus directly — the daemon wires its own bus into a
	// closure and passes it as Emit.
	Emit func(model.Alert)

	// ProcScrape applies the procfs-read allowlist to events
	// produced by sensors/ebpf's XH_EV_PROC_SCRAPE program. When
	// non-nil, Handle() invokes Enrich() on every proc_scrape
	// event so rules can branch on cred_proc_scrape.
	ProcScrape *procscrape.Sensor

	// SNICheck flags outbound TLS connections that lack an SNI
	// extension. Pipeline calls Note() on every outbound connect
	// to a TLS port; the detector evaluates ~800ms later by
	// inspecting connstate for an attached SNI.
	SNICheck *snicheck.Detector

	// SourceMinter mints v2 SourceAnchors from identity events
	// (sshd accept, PAM session open, sudo / su, cron fire, systemd
	// unit start). Non-mintable events are no-ops. Nil-safe.
	//
	// Anchors persist to SQLite at /var/lib/xhelix/source.db and
	// populate the in-memory lineage.Store in lockstep so the hot
	// rule-engine path sees them immediately. T01 / Phase A1.
	SourceMinter *source.Minter

	// FileTaint tracks per-path writer provenance for file-mediated
	// causality. FIM write events record (path → writer's CausalSet);
	// file-read events look up the writer and merge its set into the
	// reader's CausalSet via ProcTree.MergeCausalSet. Nil-safe.
	// T02 / Phase A2 commit 3.
	FileTaint *source.FileTaint

	// SourceStore is the persistent SQLite-backed source-graph store.
	// When set, Pipeline.Handle auto-records GraphEvents for any
	// event carrying a non-zero source_anchor_id tag, populating the
	// source_events table that the correlation-graph UI queries.
	// Nil-safe. T04 / Phase B1 commit 4.
	SourceStore *source.Store

	// BRPMatcher resolves an event's binary to a signed Behavioral
	// Reference Profile. Nil-safe — when absent, every event resolves
	// as Unprofiled (which the runtime treats as log-only). T05/T06.
	BRPMatcher *brp.Matcher
	// BRPRuntime evaluates EventFacts against a resolved profile.
	// Required if BRPMatcher is set; ignored otherwise.
	BRPRuntime *brp.Runtime
	// BRPPhases tracks per-PID lifecycle phase for envelope decisions.
	// Nil-safe — when absent, phase is reported as "unknown".
	BRPPhases *brpphase.Tracker

	// BRPWriterCache caches recent (path → writer) attributions from
	// eBPF file_write events so FIM events arriving moments later can
	// recover the writer identity that inotify doesn't carry. Nil-safe.
	BRPWriterCache *writerattr.Cache

	// IntegrityTester runs pkg/integrity's T1-T5 authentic-upgrade
	// policy on (writerPID, path, sha). Used by the BRP runtime as
	// the IntegrityAuthentic trust signal. Nil-safe.
	IntegrityTester *integrity.Tester

	// VerifyEngine is the Tier-2 verifier (T07). When set, BRP Verify
	// decisions involving protected paths are routed through it and the
	// final outcome (benign / suspicious / promote) is stamped on the
	// event. Nil-safe — when absent, the existing brp.verify_protected_path
	// interim alert path still emits.
	VerifyEngine *verify.Engine

	// BRPEdges holds operator-signed inter-app interaction edges. When
	// set, the verifier's CrossApp domain reads from this for stronger
	// cross-app trust evidence. Nil-safe.
	BRPEdges *brp.EdgeSet

	// AssetResolver classifies paths, sockets, and hosts into stable
	// asset classes (pkg/assetclass). When set, every event with a
	// path/dst_socket/dst_ip gets an `asset_class` tag, which the
	// verifier's asset-context domain reads. Nil-safe.
	AssetResolver assetclass.Resolver

	// SecretTaint tracks per-lineage secret-touch state. When set, the
	// pipeline observes secret-source events into the store, propagates
	// taint parent→child via ProcTree.OnSpawn, and stamps `secret_class`
	// + `secret_taint` tags on events from tainted lineages.
	// Nil-safe. Phase B.2.
	SecretTaint secrettaint.Store

	// SSHBrute counts SSH auth failures per source IP and fires the
	// `ssh_bruteforce` alert when N failures from one IP land within
	// window M (Phase J.1). Reads identity.sshd events tagged
	// outcome=failure. Nil-safe.
	SSHBrute *sshbrute.Detector

	// IncidentGraph assembles correlated incidents from per-event and
	// per-alert streams (Phase D.1). Pipeline calls Observe(event) at
	// the tail of Handle; the daemon wraps Emit to call ObserveAlert.
	// Nil-safe — when absent, no incident assembly happens.
	IncidentGraph incidentgraph.Engine

	// EgressGuard is the per-event egress decision surface (Phase C).
	// For every net_connect event the pipeline calls Decide, stamps the
	// `egress_decision` tag, and if mode==Enforce and decision==Deny
	// calls ApplyDeny to push the deny to the kernel backend.
	// Nil-safe — when absent, no egress enforcement happens.
	EgressGuard egressguard.Guard
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

	// Burst detectors (P-AB.13). Per-PID sliding-window counters
	// that emit a synthetic alert when a single PID's
	// file-open-rate or spawn-rate crosses a threshold (the
	// steady-state shape of credential-scan / workspace-recon
	// malware). JIT runtimes are exempt via jit_allowlisted set
	// earlier in this function.
	//
	// We don't gate on baseline_observing here — burst bursts are
	// loud-by-construction and a Megalodon-shaped attack on day 0
	// should still produce a visible signal even while the
	// autobaseline learns. The response engine's gate still
	// strips destructive actions during observe.
	if ev.PID != 0 && ev.Tags["jit_allowlisted"] != "true" {
		now := time.Now().UTC()
		// Process-spawn burst: count ebpf.proc/spawn events
		// keyed by PARENT pid (the spawner is what we want to
		// flag, not each child).
		if p.SpawnBurst != nil && ev.Sensor == "ebpf.proc" &&
			ev.Tags["kind"] == "proc_spawn" && ev.ParentPID != 0 {
			if cross, count := p.SpawnBurst.Observe(ev.ParentPID, now); cross {
				p.emitBurst(ev, "process_spawn_burst", ev.ParentPID, count,
					"PID spawned >threshold children in window")
			}
		}
		// File-read burst: any ebpf event whose kind is file_open
		// or whose tag indicates a path read. xhelix's eBPF
		// emits kind=file_open on openat for tracked watch paths;
		// we count on that.
		if p.FileReadBurst != nil && ev.Sensor == "ebpf" &&
			ev.Tags["kind"] == "file_open" {
			if cross, count := p.FileReadBurst.Observe(ev.PID, now); cross {
				p.emitBurst(ev, "file_read_burst", ev.PID, count,
					"PID opened >threshold files in window")
			}
		}
		// File-mediated taint inheritance (T02 commit 3): on file_open
		// events for tracked paths, fetch the writer's provenance from
		// FileTaint and merge it into the reader's CausalSet. The
		// reader's PrimarySource is unchanged unless the reader has no
		// prior source — in which case we attribute the writer's
		// primary as the reader's PrimarySource via AttributeSource.
		// Nil-safe.
		if p.FileTaint != nil && p.ProcTree != nil &&
			ev.Sensor == "ebpf" && ev.Tags["kind"] == "file_open" &&
			ev.PID != 0 {
			if path := ev.Tags["path"]; path != "" {
				if prov, ok := p.FileTaint.Lookup(path); ok {
					p.ProcTree.MergeCausalSet(ev.PID, prov.Set)
					if prov.LastWriterPrimary != 0 {
						p.ProcTree.AttributeSource(ev.PID, prov.LastWriterPrimary)
					}
					// Stamp the writer hint on the event so downstream
					// rules + sinks can correlate without a second
					// lookup.
					ev.Tags["file_writer_primary"] = fmt.Sprintf("%d", uint64(prov.LastWriterPrimary))
					ev.Tags["file_writer_set_hash"] = fmt.Sprintf("%016x", prov.SetHash)
				}
			}
		}
		// Clean up PID counters on proc_exit so PID reuse doesn't
		// carry false history.
		if ev.Sensor == "ebpf.proc" && ev.Tags["kind"] == "proc_exit" {
			if p.SpawnBurst != nil {
				p.SpawnBurst.Forget(ev.PID)
			}
			if p.FileReadBurst != nil {
				p.FileReadBurst.Forget(ev.PID)
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

	// File-mediated taint provenance recording (T02 commit 3): on FIM
	// write events for tracked paths, record (path → writer's
	// CausalSet). Later file_open events on the same path will look
	// this up and inherit the writer's set into the reader's
	// CausalSet. Nil-safe.
	if p.FileTaint != nil && p.ProcTree != nil &&
		(ev.Sensor == "fim" || ev.Sensor == "fim.drift") &&
		ev.PID != 0 && ev.Tags != nil &&
		(ev.Tags["write"] == "true" || ev.Tags["create"] == "true") {
		if path := ev.Tags["path"]; path != "" {
			primary, cs := p.ProcTree.SourceOf(ev.PID)
			if primary != 0 || !cs.IsEmpty() {
				p.FileTaint.RecordWrite(path, primary, cs, ev.Time)
			}
		}
	}

	// Durable persistence first. Non-blocking; the cold
	// store drops on overflow and counts it.
	//
	// HIGH-VOLUME FILTER (2026-05-25): drop noisy event classes from
	// cold persistence. ebpf.net alone produced 15.8M rows/day (~89%
	// of cold.db) and pushed disk to 98% in <24h. Network telemetry
	// stays in the hot store, the forensic chain, and the source
	// graph — those are the actually-queried surfaces. Cold persists
	// only the events operators ever forensically replay against.
	//
	// Filter strategy:
	//   - ebpf.net: drop entirely (15.8M/day; high volume, low forensic value)
	//   - heartbeat: drop (liveness only; chain already has it)
	//   - ebpf.self: drop (daemon internal noise)
	//   - everything else: persist
	if p.ColdStore != nil && shouldPersistCold(ev) {
		evCopy := ev
		p.ColdStore.Submit(&evCopy)
	}
	// Feed session tracker first — it consumes identity
	// events to open/close sessions and tags subsequent
	// process spawns with the active session.
	if p.SessionTracker != nil {
		p.SessionTracker.Ingest(ev)
	}
	// Mint v2 SourceAnchors from identity events. The minter
	// inspects ev.Tags and is a no-op for non-mintable events,
	// so we can call it on every event cheaply. Errors are
	// logged not propagated — anchor persistence failure must
	// not stop the rule engine. T01.
	if p.SourceMinter != nil {
		if id, err := p.SourceMinter.MintFromEvent(ctx, ev); err != nil && p.Log != nil {
			p.Log.Warn("source anchor mint failed", "err", err)
		} else if id != 0 {
			// Stamp the new anchor id on the originating event so the
			// rule engine and downstream sinks can correlate.
			if ev.Tags == nil {
				ev.Tags = map[string]string{}
			}
			ev.Tags["source_anchor_id"] = fmt.Sprintf("%d", uint64(id))
			// If the identity event carries a known PID (e.g. PAM
			// session_open carries the session leader's pid), attach
			// the new anchor to the live process so subsequent events
			// inherit via proctree. T02 — propagation.
			if ev.PID != 0 && p.ProcTree != nil {
				p.ProcTree.AttributeSource(ev.PID, lineage.LineageID(id))
			}
		}
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
			// If the spawn event carries an explicit source_anchor_id
			// (sensor pre-attribution, rare), honour it. Otherwise
			// proctree.OnSpawn inherits PrimarySource + CausalSet from
			// the parent PID automatically. T02.
			var explicitSource lineage.LineageID
			if sa := ev.Tags["source_anchor_id"]; sa != "" {
				if n, err := strconv.ParseUint(sa, 10, 64); err == nil {
					explicitSource = lineage.LineageID(n)
				}
			}
			p.ProcTree.OnSpawn(proctree.Node{
				PID:           ev.PID,
				PPID:          ev.ParentPID,
				Comm:          ev.Comm,
				Image:         ev.Tags["image"],
				UID:           ev.UID,
				CGroupID:      ev.CGroupID,
				Container:     ev.Container,
				PrimarySource: explicitSource,
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
		// snicheck: queue a deferred SNI check for this outbound
		// connect. The detector itself filters by port + allowlist.
		if p.SNICheck != nil {
			if dst := ev.Tags["dst_ip"]; dst != "" {
				if ip := net.ParseIP(dst); ip != nil {
					port := uint16(0)
					if pp := ev.Tags["dst_port"]; pp != "" {
						var n int
						_, _ = fmt.Sscanf(pp, "%d", &n)
						port = uint16(n)
					}
					p.SNICheck.Note(ev.PID, ev.Comm, ev.Image, ev.UID, ip, port)
				}
			}
		}
	}
	if p.ConnTable != nil && ev.Sensor == "ebpf.net" && ev.Tags["kind"] == "net_bytes" {
		feedConnstateBytes(p.ConnTable, ev)
	}

	// Procscrape allowlist verdict — tags cred_proc_scrape=true
	// when an unallowlisted reader opened /proc/<other-pid>/{environ,
	// maps,mem,auxv}. Runs before rule eval so rules can branch on
	// the verdict; runs before HotStore.Insert so persisted events
	// carry the tag for forensic review.
	if p.ProcScrape != nil && ev.Tags["kind"] == "proc_scrape" {
		p.ProcScrape.Enrich(&ev)
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

	// Correlator. Stamp event.CGroupID into Tags so correlator
	// rules can group_by:cgroup_id (Phase J.2 dropped-binary chain
	// rule depends on this; extractGroup only reads Tags).
	if p.Correlator != nil {
		if ev.CGroupID != 0 {
			if ev.Tags == nil {
				ev.Tags = map[string]string{}
			}
			if ev.Tags["cgroup_id"] == "" {
				ev.Tags["cgroup_id"] = strconv.FormatUint(ev.CGroupID, 10)
			}
		}
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
		// T02 commit 4 — injection attribution: the ptrace target
		// inherits the attacker's source. If the target already had a
		// different source, this flips its CausalSet to Ambiguous,
		// which the verification engine treats as "PrimarySource
		// conflicted" — a hard signal of compromise.
		if p.ProcTree != nil {
			if targetPID := parseUint32(ev.Tags["ptrace_target_pid"]); targetPID != 0 {
				attackerPrimary, attackerSet := p.ProcTree.SourceOf(ev.PID)
				if attackerPrimary != 0 {
					p.ProcTree.AttributeSource(targetPID, attackerPrimary)
				}
				if !attackerSet.IsEmpty() {
					p.ProcTree.MergeCausalSet(targetPID, attackerSet)
				}
			}
		}
	}

	// T02 commit 4 — outbound source attribution: stamp the connecting
	// PID's PrimarySource + CausalSet hash on the event so downstream
	// detectors (connstate, egressmon, cloud-meta, brand-lookalike,
	// IOC match) can attribute the flow to a session without a second
	// lookup. Empty when the PID has no attribution yet (e.g. pre-mint
	// daemons), which is fine — the tag stays absent and downstream
	// rules can branch on its presence.
	if p.ProcTree != nil && ev.Sensor == "ebpf.net" &&
		ev.Tags["kind"] == "net_connect" && ev.PID != 0 {
		primary, cs := p.ProcTree.SourceOf(ev.PID)
		if primary != 0 {
			if ev.Tags == nil {
				ev.Tags = map[string]string{}
			}
			ev.Tags["source_anchor_id"] = fmt.Sprintf("%d", uint64(primary))
			ev.Tags["source_set_hash"] = fmt.Sprintf("%016x", cs.Hash())
			if cs.Ambiguous() {
				ev.Tags["source_ambiguous"] = "true"
			}
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

	// Vhost correlation (P-EGRESS.M1.vhost) — when a worker receives
	// an inbound HTTPS request, note the Host header so subsequent
	// outbound connects from the same pid can be attributed.
	if p.VhostCorr != nil && ev.PID != 0 {
		if host := ev.Tags["http_host"]; host != "" {
			p.VhostCorr.Note(ev.PID, host)
		}
	}

	// App identification (P-EGRESS.M1.app) — derive a sticky AppID
	// for this lineage and stamp ev.Tags["app_id"]. Nil-safe.
	// Done before the egress observer block so the observer sees the
	// app via SetAppID.
	if p.AppIdent != nil && (ev.PID != 0 || ev.CGroupID != 0) {
		sig := appident.Signals{
			LineageID:  uint64(ev.CGroupID),
			CgroupPath: ev.Container, // ev.Container holds cgroup path on Linux events
			ExePath:    ev.Image,
			ArgvJoined: ev.Tags["argv"],
			Comm:       ev.Comm,
		}
		// Stable-lineage fix: when the sensor didn't stamp CGroupID,
		// resolve it from /proc/<pid>/cgroup → /sys/fs/cgroup/... inode.
		// Survives worker PID churn within the same cgroup.
		if sig.LineageID == 0 && ev.PID != 0 {
			if cgid := appident.ResolveCGroupID(ev.PID); cgid != 0 {
				sig.LineageID = cgid
				ev.CGroupID = cgid
				if ev.Tags == nil {
					ev.Tags = map[string]string{}
				}
				ev.Tags["cgroup_id_resolved"] = "proc"
			}
		}
		if sig.LineageID == 0 {
			sig.LineageID = uint64(ev.PID)
		}
		// Many sensor event types don't populate Container/Image/argv
		// (e.g. tcp_connect from kprobe only has PID + dst). Enrich
		// from /proc/<pid>/* before identification so heuristics get
		// the signals they need. The identifier caches per-lineage so
		// this proc work happens only on first sight per lineage.
		if sig.CgroupPath == "" || sig.ExePath == "" || sig.ArgvJoined == "" {
			sig = appident.EnrichFromProc(ev.PID, sig)
		}
		a := p.AppIdent.Identify(sig)
		if !a.Empty() {
			if ev.Tags == nil {
				ev.Tags = map[string]string{}
			}
			ev.Tags["app_id"] = a.String()
			// app_name is the bare app name (no :vhost suffix). BRP's
			// matcher compares against ProfileKey.App which is just the
			// name — using app_id would never match because it carries
			// the vhost.
			ev.Tags["app_name"] = a.Name
			if a.Kind != "" {
				ev.Tags["app_kind"] = string(a.Kind)
			}
			if p.EgressObserver != nil {
				lid := egressmon.LineageID(ev.CGroupID)
				if lid == 0 {
					lid = egressmon.LineageID(ev.PID)
				}
				p.EgressObserver.SetAppID(lid, a.String(), string(a.Kind))
			}
		}
	}

	// Egress observer (P-EGRESS.M1) — classify every outbound connect
	// and stamp the result on event tags; tally bytes on outbound
	// sendmsg events. Mode-1 is pure data: no enforcement.
	// Nil-safe; observer is non-nil only when `egress.observe: true`.
	if p.EgressObserver != nil {
		dst := ev.Tags["dst_ip"]
		if dst != "" {
			ip := net.ParseIP(dst)
			if ip != nil {
				port := uint16(0)
				if pp := ev.Tags["dst_port"]; pp != "" {
					var n int
					_, _ = fmt.Sscanf(pp, "%d", &n)
					port = uint16(n)
				}
				lid := egressmon.LineageID(ev.CGroupID)
				if lid == 0 {
					lid = egressmon.LineageID(ev.PID)
				}
				sni := ev.Tags["sni"]
				if sni == "" {
					sni = ev.Tags["http_host"]
				}
				// Tuning sprint: when SNI isn't on the event (most
				// connect events don't carry it because TLS Hello
				// fires after connect), consult connstate. The dpi
				// sensor attaches SNI to the Conn row when it parses
				// the ClientHello — usually within ~150ms of connect.
				if sni == "" && p.ConnTable != nil && ev.PID != 0 {
					sni = lookupSNIFromConnstate(p.ConnTable, ev.PID, dst, port)
				}
				// Inbound vhost attribution: if a recent HTTPS request
				// noted a Host header for this pid, stamp it onto the
				// outbound event so analytics can roll up by vhost.
				if p.VhostCorr != nil {
					if vh, ok := p.VhostCorr.Lookup(ev.PID); ok {
						if ev.Tags == nil {
							ev.Tags = map[string]string{}
						}
						ev.Tags["inbound_vhost"] = vh
					}
				}
				// Branch on event kind: connect vs sendmsg-out bytes.
				switch {
				case ev.Tags["outbound"] == "true":
					d := p.EgressObserver.Observe(lid, ip, sni, port)
					if ev.Tags == nil {
						ev.Tags = map[string]string{}
					}
					ev.Tags["dest_class"] = string(d.Class)
					if d.Source != "" {
						ev.Tags["dest_class_source"] = d.Source
					}
				case ev.Tags["kind"] == "net_bytes" && ev.Tags["dir"] == "out":
					if bs := ev.Tags["bytes"]; bs != "" {
						var n uint64
						_, _ = fmt.Sscanf(bs, "%d", &n)
						p.EgressObserver.ObserveBytes(lid, ip, sni, port, n)
						if p.IPTimeSeries != nil {
							p.IPTimeSeries.RecordOut(ip, n, ev.Time)
						}
					}
				case ev.Tags["kind"] == "net_bytes" && ev.Tags["dir"] == "in":
					if bs := ev.Tags["bytes"]; bs != "" {
						var n uint64
						_, _ = fmt.Sscanf(bs, "%d", &n)
						if p.IPTimeSeries != nil {
							p.IPTimeSeries.RecordIn(ip, n, ev.Time)
						}
					}
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

	// T04 commit 4 — auto-record source-attributed GraphEvent.
	//
	// If the event reached this point with a non-zero source_anchor_id
	// (set by the minter or inherited by proctree propagation) AND the
	// SourceStore is wired, we append a row into source_events. This
	// is what the correlation-graph UI queries.
	//
	// Errors are logged not propagated — graph-store insert failure must
	// not affect the rule engine or other downstream sinks.
	if p.SourceStore != nil {
		p.recordGraphEvent(ctx, ev)
	}

	// Secret-taint observation (Phase B.2). Runs BEFORE the asset-class
	// and BRP eval blocks so subsequent stages see the post-touch
	// state. Two passes:
	//  1. ObserveTouch on secret-source events (file reads to canonical
	//     secret paths, metadata access, procscrape, credbroker).
	//  2. Stamp `secret_class` + `secret_taint` tags on every event
	//     whose lineage is already tainted.
	//
	// Parent→child inheritance happens via the proctree OnSpawn hook
	// (wired separately at daemon startup); not duplicated here.
	if p.SecretTaint != nil {
		if class, isSecret := secrettaint.ClassifyEvent(ev); isSecret {
			lineage := lineageIDFromEvent(ev)
			if lineage != 0 {
				p.SecretTaint.ObserveTouch(secrettaint.Touch{
					PID:         ev.PID,
					LineageID:   lineage,
					SecretClass: class,
					Path:        ev.Tags["path"],
					At:          ev.Time,
				})
				if ev.Tags == nil {
					ev.Tags = map[string]string{}
				}
				ev.Tags["secret_class"] = string(class)
			}
		}
		// Stamp current taint state on every event from a tainted lineage.
		if lineage := lineageIDFromEvent(ev); lineage != 0 {
			if state := p.SecretTaint.StateForLineage(lineage); state != secrettaint.TaintClean {
				if ev.Tags == nil {
					ev.Tags = map[string]string{}
				}
				ev.Tags["secret_taint"] = state.String()
			}
		}
	}

	// Asset classification (Phase B.1). Stamp `asset_class` tag from
	// path / socket / host context so the verifier's asset-context
	// domain and incidentgraph evidence weighting have stable semantic
	// classes to read. Runs BEFORE BRP eval so evaluateBRP can include
	// the class in verify.Input.
	if p.AssetResolver != nil && ev.Tags != nil {
		role := ev.Tags["app_role"]
		if path := ev.Tags["path"]; path != "" {
			if c := p.AssetResolver.ClassifyPath(path, role); c != assetclass.ClassUnknown {
				ev.Tags["asset_class"] = string(c)
			}
		} else if sock := ev.Tags["dst_socket"]; sock != "" {
			if c := p.AssetResolver.ClassifySocket(sock); c != assetclass.ClassUnknown {
				ev.Tags["asset_class"] = string(c)
			}
		} else if ip := ev.Tags["dst_ip"]; ip != "" {
			sni := ev.Tags["sni"]
			var port uint16
			if portStr := ev.Tags["dst_port"]; portStr != "" {
				if n, err := strconv.ParseUint(portStr, 10, 16); err == nil {
					port = uint16(n)
				}
			}
			if c := p.AssetResolver.ClassifyHost(ip, sni, port); c != assetclass.ClassUnknown {
				ev.Tags["asset_class"] = string(c)
			}
		}
	}

	// Egressguard decision (Phase C.2). For net_connect events only,
	// build a Request from BRP+asset+secret context already stamped
	// above and call Guard.Decide. The decision is stamped on the
	// event tags; if mode==Enforce and decision==Deny, ApplyDeny
	// pushes the deny to the kernel backend.
	if p.EgressGuard != nil && ev.Sensor == "ebpf.net" &&
		ev.Tags != nil && ev.Tags["kind"] == "net_connect" {
		req := egressguard.Request{
			PID:         ev.PID,
			LineageID:   lineageIDFromEvent(ev),
			CGroupID:    ev.CGroupID,
			AppName:     ev.Tags["app_name"],
			AppRole:     ev.Tags["app_role"],
			DestIP:      ev.Tags["dst_ip"],
			SNI:         ev.Tags["sni"],
			DNSName:     ev.Tags["dst_dns"],
			DestClass:   ev.Tags["dest_class"],
			AssetClass:  ev.Tags["asset_class"],
			SecretTaint: ev.Tags["secret_taint"],
			At:          ev.Time,
		}
		if portStr := ev.Tags["dst_port"]; portStr != "" {
			if n, err := strconv.ParseUint(portStr, 10, 16); err == nil {
				req.DestPort = uint16(n)
			}
		}
		d, reason := p.EgressGuard.Decide(req)
		ev.Tags["egress_decision"] = d.String()
		ev.Tags["egress_reason"] = reason
		if d == egressguard.EgressDeny {
			destKey := fmt.Sprintf("%s:%d", req.DestIP, req.DestPort)
			_ = p.EgressGuard.ApplyDeny(req.LineageID, destKey, 5*time.Minute)
			if p.Emit != nil {
				ruleID := "egressguard.shadow_deny"
				if p.EgressGuard.Mode() == egressguard.ModeEnforce {
					ruleID = "egressguard.deny"
				}
				p.Emit(model.Alert{
					Event:  ev,
					RuleID: ruleID,
					Reason: fmt.Sprintf("egressguard deny: %s (mode=%s backend=%s)",
						reason, p.EgressGuard.Mode().String(), p.EgressGuard.BackendName()),
					Mode:  model.ModeDetect,
					Class: 2,
				})
			}
		}
	}

	// BRP runtime evaluation (T06). When a profile library is loaded,
	// resolve the actor and stamp brp_decision / brp_reason on the
	// event tags. DecisionHardDeny additionally emits a critical alert
	// via the bus so response/enforce sinks see it.
	//
	// Nil-safe: if BRPMatcher or BRPRuntime is unset, do nothing.
	if p.BRPMatcher != nil && p.BRPRuntime != nil {
		p.evaluateBRP(ev)
	}

	// SSH brute-force detection (Phase J.1). Observe identity.sshd
	// failures; emit ssh_bruteforce alert when threshold crossed.
	if p.SSHBrute != nil && p.Emit != nil &&
		ev.Sensor == "identity.sshd" && ev.Tags["outcome"] == "failure" {
		obs := p.SSHBrute.Observe(ev.Tags["src_ip"], ev.Tags["user"], ev.Time)
		if obs.Fired {
			users := make([]string, 0, len(obs.UserAttempts))
			for u := range obs.UserAttempts {
				users = append(users, u)
			}
			alertEv := model.NewEvent("identity.sshd", model.SeverityHigh)
			alertEv.Host = ev.Host
			alertEv.Tags["service"] = "sshd"
			alertEv.Tags["src_ip"] = obs.SourceIP
			alertEv.Tags["failures"] = strconv.Itoa(obs.Failures)
			alertEv.Tags["window"] = obs.Window.String()
			alertEv.Tags["users"] = strings.Join(users, ",")
			p.Emit(model.Alert{
				Event:  alertEv,
				RuleID: "ssh_bruteforce",
				Reason: "SSH brute-force pattern: " + strconv.Itoa(obs.Failures) +
					" failures from " + obs.SourceIP + " in " + obs.Window.String(),
				Mode:  model.ModeDetect,
				Class: 2,
			})
		}
	}

	// Incident-graph observation (Phase D.1). Bridges every enriched
	// event into the incidentgraph engine, where it's grouped by
	// source_anchor_id (or lineage fallback) into an Incident. Alerts
	// fan in via the daemon's Emit wrapper, not from here.
	// Nil-safe.
	if p.IncidentGraph != nil {
		p.observeIncident(ev)
	}
}

// recordGraphEvent translates a model.Event into a source.GraphEvent
// when the event carries source_anchor_id, then appends to the
// persistent store. Filters out noise (events without source attribution
// or with kinds we don't graph) before the SQL insert.
func (p *Pipeline) recordGraphEvent(ctx context.Context, ev model.Event) {
	if ev.Tags == nil {
		return
	}
	saStr := ev.Tags["source_anchor_id"]
	if saStr == "" || saStr == "0" {
		return
	}
	sa, err := strconv.ParseUint(saStr, 10, 64)
	if err != nil || sa == 0 {
		return
	}
	kind := classifyEventKind(ev)
	if kind == "" {
		// Not a graphable event class.
		return
	}
	g := source.GraphEvent{
		SourceAnchorID: lineage.LineageID(sa),
		Time:           ev.Time,
		PID:            ev.PID,
		ParentPID:      ev.ParentPID,
		Kind:           kind,
		Comm:           ev.Comm,
		UID:            ev.UID,
		Severity:       severityFromModel(ev.Severity),
	}
	// Pull target-* fields from common tag positions.
	if path := ev.Tags["path"]; path != "" {
		g.TargetPath = path
	}
	if image := ev.Tags["image"]; image != "" {
		g.TargetImage = image
	}
	if host := ev.Tags["dst_ip"]; host != "" {
		g.TargetHost = host
	} else if host := ev.Tags["dst_host"]; host != "" {
		g.TargetHost = host
	}
	if portStr := ev.Tags["dst_port"]; portStr != "" {
		if n, perr := strconv.ParseUint(portStr, 10, 16); perr == nil {
			g.TargetPort = uint16(n)
		}
	}
	if sock := ev.Tags["dst_socket"]; sock != "" {
		g.TargetSocket = sock
	}
	if hash := ev.Tags["source_set_hash"]; hash != "" {
		// Hex string from net_connect stamping; store raw hash.
		if n, perr := strconv.ParseUint(hash, 16, 64); perr == nil {
			g.CausalSetHash = n
		}
	}
	if _, err := p.SourceStore.RecordEvent(ctx, g); err != nil && p.Log != nil {
		p.Log.Debug("source graph event record failed", "err", err, "kind", kind)
	}
}

// classifyEventKind maps a model.Event onto a source.EventKind based
// on Sensor + Tags. Returns "" for events we don't graph (rules-only
// alerts, health probes, etc.).
func classifyEventKind(ev model.Event) source.EventKind {
	tags := ev.Tags
	// Identity events (from sensors/identity).
	if strings.HasPrefix(ev.Sensor, "identity.") || tags["service"] == "sshd" ||
		tags["service"] == "pam" || tags["service"] == "sudo" ||
		tags["service"] == "su" || tags["service"] == "cron" {
		return source.KindIdentity
	}
	// Spawn / exit / exec.
	if ev.Sensor == "ebpf.spawn" || ev.Sensor == "ebpf.proc" {
		switch tags["kind"] {
		case "proc_spawn":
			return source.KindSpawn
		case "proc_exit":
			return source.KindExit
		case "proc_exec":
			return source.KindExec
		}
	}
	// Network.
	if ev.Sensor == "ebpf.net" {
		switch tags["kind"] {
		case "net_connect":
			return source.KindNetConnect
		case "net_listen":
			return source.KindNetListen
		case "net_accept":
			return source.KindNetAccept
		}
	}
	if ev.Sensor == "netids" && tags["event_type"] == "dns" {
		return source.KindDNSQuery
	}
	// File events: FIM writes/creates, ebpf file_open for tracked paths.
	if ev.Sensor == "fim" || ev.Sensor == "fim.drift" {
		if tags["write"] == "true" || tags["create"] == "true" || tags["delete"] == "true" {
			return source.KindFileWrite
		}
	}
	if ev.Sensor == "ebpf" && tags["kind"] == "file_open" {
		return source.KindFileRead
	}
	// Capability + namespace.
	if ev.Sensor == "ebpf.cap" && tags["capset"] == "true" {
		return source.KindCapChange
	}
	if ev.Sensor == "ebpf.ns" {
		return source.KindNSChange
	}
	// High-signal kernel events (any sensor).
	if tags["ptrace_attach"] == "true" {
		return source.KindPtrace
	}
	if tags["memfd_exec"] == "true" {
		return source.KindMemfdExec
	}
	if tags["cred_proc_scrape"] == "true" || tags["secret_read"] == "true" {
		return source.KindSecretAccess
	}
	if tags["persistence"] == "true" {
		return source.KindPersistence
	}
	return ""
}

// severityFromModel maps the daemon's model.Severity to source.Severity.
func severityFromModel(s model.Severity) source.Severity {
	switch s {
	case model.SeverityHigh:
		return source.SeverityHigh
	case model.SeverityCritical:
		return source.SeverityCritical
	case model.SeverityWarn:
		return source.SeverityWarn
	case model.SeverityNotice:
		return source.SeverityInfo
	}
	return source.SeverityInfo
}

// evaluateBRP resolves a profile for the actor and runs the runtime
// decision. The decision is always stamped onto event tags (brp_decision,
// brp_reason, brp_profile, brp_confidence, brp_phase); a DecisionHardDeny
// additionally emits an alert via the bus so response/enforce sinks can
// act on it.
//
// Match input derives from event-time fields. App / version / role are
// pulled from tags set by AppIdent (P-AB.18) if present; otherwise the
// matcher will see empty fields and fall back to ConfidenceUnprofiled.
// That's the conservative default — no profile, no enforcement.
func (p *Pipeline) evaluateBRP(ev model.Event) {
	// Action classification: only known actions get a meaningful
	// envelope check. For everything else evaluateBRP still runs
	// (invariants like ptrace / memfd_exec must fire regardless of
	// matched profile), but the envelope check is a no-op.
	action := brpActionFromEvent(ev)
	if action == "" {
		return
	}

	// Prefer app_name (bare name, set by AppIdent block) over app_id
	// (name:vhost) — the matcher's ProfileKey.App is the bare name.
	appName := ev.Tags["app_name"]
	if appName == "" {
		appName = ev.Tags["app_id"]
	}
	mi := brp.MatchInput{
		BinaryHash: ev.Tags["sha256"],
		App:        appName,
		Version:    ev.Tags["app_version"],
		OSFamily:   ev.Tags["os_family"],
		Role:       ev.Tags["app_role"],
	}
	mr := p.BRPMatcher.Match(mi)

	facts := brp.EventFacts{
		PID:     ev.PID,
		Comm:    ev.Comm,
		ExePath: ev.Image,
		Action:  action,
	}
	// Writer attribution recovery: if this is a FIM-style event with no
	// actor info, look up a recent eBPF write to the same path.
	if facts.PID == 0 && facts.Comm == "" && p.BRPWriterCache != nil {
		pathTag := ev.Tags["path"]
		if pathTag != "" && isWriteActionString(action) {
			if w, ok := p.BRPWriterCache.Lookup(pathTag, ev.Time); ok {
				facts.PID = w.PID
				facts.Comm = w.Comm
				facts.ExePath = w.ExePath
				ev.Tags["brp_attribution"] = "writerattr_cache"
			}
		}
	}
	// Multi-signal trust corroboration (BRP rule B requires score >= 2).
	if p.IntegrityTester != nil && facts.PID != 0 && isWriteActionString(action) {
		if v := p.IntegrityTester.Verify(facts.PID, ev.Tags["path"], ev.Tags["sha256"]); v.Authentic {
			facts.Trust.IntegrityAuthentic = true
		}
	}
	if cgcls := ev.Tags["cgroup_class"]; cgcls == "system" {
		facts.Trust.CGroupRole = "system"
	}
	if p.ProcTree != nil && facts.PID != 0 {
		if anc := p.ProcTree.Ancestors(facts.PID, 0); len(anc) > 0 {
			for _, a := range anc {
				if brp.TrustedSystemWriters[a.Comm] {
					facts.Trust.ParentTrusted = true
					break
				}
			}
		}
	}
	if path := ev.Tags["path"]; path != "" {
		facts.Path = path
	}
	if mode := ev.Tags["mode"]; mode != "" {
		facts.Mode = mode
	}
	if target := ev.Tags["image"]; target != "" {
		facts.TargetImage = target
	} else if ev.Image != "" && (action == "exec" || action == "process_spawn") {
		facts.TargetImage = ev.Image
	}
	if host := ev.Tags["dst_ip"]; host != "" {
		facts.DestHost = host
	} else if host := ev.Tags["dst_host"]; host != "" {
		facts.DestHost = host
	}
	if portStr := ev.Tags["dst_port"]; portStr != "" {
		if n, err := strconv.ParseUint(portStr, 10, 16); err == nil {
			facts.DestPort = uint16(n)
		}
	}
	if sock := ev.Tags["dst_socket"]; sock != "" {
		facts.DestSocket = sock
	}
	if mr.Profile != nil {
		facts.Role = mr.Profile.Key.Role
	}

	// Record eBPF-derived write events into the writer-attribution cache
	// so any FIM event for the same path arriving moments later can
	// recover the writer identity.
	if p.BRPWriterCache != nil && facts.PID != 0 && facts.Comm != "" &&
		isWriteActionString(action) && ev.Sensor != "fim" && ev.Sensor != "fim.drift" {
		if pathTag := ev.Tags["path"]; pathTag != "" {
			p.BRPWriterCache.Record(pathTag, writerattr.Writer{
				PID: facts.PID, Comm: facts.Comm, ExePath: facts.ExePath,
				When: ev.Time,
			})
		}
	}

	decision, reason := p.BRPRuntime.Evaluate(mr, facts)

	if ev.Tags == nil {
		ev.Tags = map[string]string{}
	}
	ev.Tags["brp_decision"] = decision.String()
	ev.Tags["brp_reason"] = reason
	ev.Tags["brp_confidence"] = mr.Confidence.String()
	if mr.Profile != nil {
		ev.Tags["brp_profile"] = mr.Profile.ProfileID
	}
	if p.BRPPhases != nil && ev.PID != 0 {
		// Signal-driven transitions: SIGHUP → Reload, SIGSEGV/abort → Degraded.
		if sig := ev.Tags["signal"]; sig != "" {
			p.BRPPhases.ObserveSignal(ev.PID, sig, ev.Time)
		}
		ph := p.BRPPhases.Observe(ev.PID, ev.Time)
		ev.Tags["brp_phase"] = ph.String()
	}

	if p.Emit != nil {
		profileID := ""
		if mr.Profile != nil {
			profileID = mr.Profile.ProfileID
		}
		switch decision {
		case brp.DecisionHardDeny:
			p.Emit(model.Alert{
				Event:  ev,
				RuleID: "brp.hard_deny",
				Reason: fmt.Sprintf("BRP hard-deny (profile=%s): %s", profileID, reason),
				Mode:   model.ModeDetect,
				Class:  1,
			})
		case brp.DecisionVerify:
			// Route through the verifier engine (T07) when wired. The
			// engine scores the event across multiple domains and returns
			// a final outcome: benign / suspicious / promote.
			//
			// Behavior by outcome:
			//   benign     — suppress (do not alert)
			//   suspicious — emit brp.verify_protected_path Class=3
			//   promote    — emit brp.hard_deny Class=1 (re-promoted)
			//
			// If no verifier is wired, fall back to the interim path:
			// emit Class=3 only for protected-path writes.
			if p.VerifyEngine != nil {
				// Build aux context for the verifier from event tags. All
				// fields are optional — domains zero-score on missing data.
				vin := verify.Input{
					Facts:              facts,
					Decision:           decision,
					BRPReason:          reason,
					Phase:              ev.Tags["brp_phase"],
					IntegrityAuthentic: facts.Trust.IntegrityAuthentic,
					DestClass:          ev.Tags["dest_class"],
					JITAllowlisted:     ev.Tags["jit_allowlisted"] == "true",
				}
				// BaselineKnown — prefer direct AutoBaseline.Manager
				// call (explicit dependency); fall back to the tag set
				// earlier in Handle. Both end up false in ModeObserve.
				if p.AutoBaseline != nil {
					if b, ok := autobaseline.EventToBehavior(ev); ok {
						vin.BaselineKnown = p.AutoBaseline.IsKnown(
							autobaseline.ImageKey(ev), b)
					}
				}
				if !vin.BaselineKnown {
					vin.BaselineKnown = ev.Tags["baseline_known"] == "true"
				}
				if saStr := ev.Tags["source_anchor_id"]; saStr != "" {
					if n, err := strconv.ParseUint(saStr, 10, 64); err == nil {
						vin.SourceAnchorID = n
					}
				}
				vin.AnchorKind = ev.Tags["source_anchor_kind"]
				vin.ActorApp = ev.Tags["app_name"]
				// Phase B.3: feed asset-class + secret-taint into the
				// verifier. Tags were stamped earlier in Handle by the
				// B.1 (assetclass) and B.2 (secrettaint) blocks.
				vin.AssetClass = ev.Tags["asset_class"]
				vin.SecretTaint = ev.Tags["secret_taint"]
				if p.SecretTaint != nil {
					if lineage := lineageIDFromEvent(ev); lineage != 0 {
						for _, c := range p.SecretTaint.ClassesForLineage(lineage) {
							vin.SecretClasses = append(vin.SecretClasses, string(c))
						}
					}
				}
				// TargetApp: for exec/spawn use the target image basename;
				// for net_connect use the dst app classification if set.
				if action == "exec" || action == "process_spawn" {
					if ti := facts.TargetImage; ti != "" {
						if idx := strings.LastIndex(ti, "/"); idx >= 0 {
							vin.TargetApp = ti[idx+1:]
						} else {
							vin.TargetApp = ti
						}
					}
				} else if action == "net_connect" {
					vin.TargetApp = ev.Tags["dst_app"]
				}
				// Operator-signed edge corroboration.
				if p.BRPEdges != nil && vin.ActorApp != "" && vin.TargetApp != "" {
					dest := facts.DestSocket
					if dest == "" && facts.DestHost != "" {
						dest = fmt.Sprintf("%s:%d", facts.DestHost, facts.DestPort)
					}
					if ok, _ := p.BRPEdges.Allows(vin.ActorApp, vin.TargetApp, action, dest); ok {
						vin.EdgeAllowed = true
					}
				}
				vr := p.VerifyEngine.Evaluate(vin)
				ev.Tags["verify_outcome"] = vr.Outcome.String()
				ev.Tags["verify_score"] = fmt.Sprintf("%.2f", vr.Score)
				switch vr.Outcome {
				case verify.OutcomePromote:
					p.Emit(model.Alert{
						Event:  ev,
						RuleID: "brp.hard_deny",
						Reason: fmt.Sprintf("BRP verify→promote (profile=%s, score=%.2f): %s [%s]",
							profileID, vr.Score, reason, vr.Reason),
						Mode:  model.ModeDetect,
						Class: 1,
					})
				case verify.OutcomeSuspicious:
					p.Emit(model.Alert{
						Event:  ev,
						RuleID: "brp.verify_protected_path",
						Reason: fmt.Sprintf("BRP verify→suspicious (profile=%s, score=%.2f): %s [%s]",
							profileID, vr.Score, reason, vr.Reason),
						Mode:  model.ModeDetect,
						Class: 3,
					})
				}
				// OutcomeBenign → no alert
			} else if strings.Contains(reason, "protected path") {
				p.Emit(model.Alert{
					Event:  ev,
					RuleID: "brp.verify_protected_path",
					Reason: fmt.Sprintf("BRP verify (profile=%s): %s", profileID, reason),
					Mode:   model.ModeDetect,
					Class:  3,
				})
			}
		}
	}
}

// shouldPersistCold returns true if the event should land in the cold
// store. Used to filter out the highest-volume noise classes that
// otherwise destroy disk space. Hot store + forensic chain + source
// graph still receive every event — only the long-retention cold
// archive is filtered.
//
// Class drops (driven by 2026-05-25 incident analysis):
//   - ebpf.net: 15.8M events/day on a single dev host. Persisted
//     connect/listen tuples are queryable via hot.db for hours and
//     via the source graph indefinitely. Cold persistence adds little
//     forensic value at this volume.
//   - heartbeat: liveness only. Chain has it.
//   - ebpf.self: daemon-internal events. Not useful for IR.
//
// All other sensors persist normally. The drop list is intentionally
// SHORT to minimize risk of dropping evidence operators actually need.
func shouldPersistCold(ev model.Event) bool {
	switch ev.Sensor {
	case "ebpf.net", "heartbeat", "ebpf.self":
		return false
	}
	return true
}

// lineageIDFromEvent returns the lineage identifier for secret-taint
// keying. Prefers source_anchor_id when present (provenance-stable);
// falls back to cgroup_id (per-service stable); finally falls back to
// pid (per-process; tainted at process-grain only).
//
// Returns 0 if none of the above is available — taint cannot be
// keyed without an identifier, and the caller will no-op.
func lineageIDFromEvent(ev model.Event) uint64 {
	if ev.Tags != nil {
		if saStr := ev.Tags["source_anchor_id"]; saStr != "" && saStr != "0" {
			if n, err := strconv.ParseUint(saStr, 10, 64); err == nil && n != 0 {
				return n
			}
		}
	}
	if ev.CGroupID != 0 {
		return ev.CGroupID
	}
	return uint64(ev.PID)
}

// isWriteActionString mirrors brp's internal isWriteAction. Kept here so
// the pipeline doesn't need to import every brp internal — and so the
// runtime stays the single source of truth for write-action classification
// while the pipeline can still cheaply gate writer-attribution lookups.
func isWriteActionString(a string) bool {
	switch a {
	case "file_write", "file_create", "file_truncate", "file_append",
		"file_chmod", "file_chown", "file_link", "file_rename", "file_unlink":
		return true
	}
	return false
}

// brpActionFromEvent maps a model.Event to a brp.EventFacts.Action token.
// Returns "" for events the BRP runtime has no decision for (e.g. DNS,
// health probes, identity events that are anchor-mints not behavior).
func brpActionFromEvent(ev model.Event) string {
	tags := ev.Tags
	switch ev.Sensor {
	case "ebpf.proc", "ebpf.spawn":
		switch tags["kind"] {
		case "proc_spawn":
			return "process_spawn"
		case "proc_exec":
			return "exec"
		case "ptrace_attach":
			return "ptrace_attach"
		case "memfd_exec":
			return "memfd_exec"
		case "process_vm_writev":
			return "process_vm_writev"
		}
	case "ebpf.file", "fim", "fim.drift":
		switch tags["kind"] {
		case "file_write", "file_create", "file_truncate", "file_append":
			return tags["kind"]
		case "file_open", "file_read":
			return "file_open"
		}
		// FIM (inotify) stamps boolean tags (create/write/delete/attrib)
		// rather than `kind`. fim.drift sometimes emits no kind at all.
		// Map both shapes onto BRP write actions so the runtime gets a
		// chance to evaluate protected-path writes from these sensors.
		switch {
		case tags["create"] == "true":
			return "file_create"
		case tags["write"] == "true":
			return "file_write"
		case tags["attrib"] == "true":
			return "file_chmod"
		}
		if ev.Sensor == "fim.drift" {
			return "file_write"
		}
	case "ebpf.net":
		switch tags["kind"] {
		case "net_connect":
			return "net_connect"
		case "net_listen":
			return "net_listen"
		}
	}
	return ""
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

// emitBurst constructs and emits a burst alert. Centralised so
// file-read-burst and process-spawn-burst share the same shape;
// the rule engine doesn't need an explicit rule because the burst
// IS the detection.
func (p *Pipeline) emitBurst(triggerEv model.Event, ruleID string, pid uint32, count int, reason string) {
	if p.Emit == nil {
		return
	}
	ev := model.NewEvent("burstdet", model.SeverityHigh)
	ev.Time = time.Now().UTC()
	ev.Host = triggerEv.Host
	ev.PID = pid
	ev.Comm = triggerEv.Comm
	ev.Image = triggerEv.Image
	ev.UID = triggerEv.UID
	ev.ProcTree = triggerEv.ProcTree
	ev.Tags["kind"] = ruleID
	ev.Tags["count"] = fmt.Sprintf("%d", count)
	ev.Tags["reason"] = reason
	ev.Tags["trigger_sensor"] = triggerEv.Sensor
	p.Emit(model.Alert{
		Event:  ev,
		RuleID: ruleID,
		Reason: reason,
		Class:  2, // strong exploit signal
	})
}
