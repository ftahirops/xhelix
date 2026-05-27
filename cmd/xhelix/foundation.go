package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"net"

	"github.com/xhelix/xhelix/pkg/adminguard"
	"github.com/xhelix/xhelix/pkg/budget"
	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/catalog"
	"github.com/xhelix/xhelix/pkg/coldstore"
	"github.com/xhelix/xhelix/pkg/eac"
	"github.com/xhelix/xhelix/pkg/egress"
	"github.com/xhelix/xhelix/pkg/evidence"
	"github.com/xhelix/xhelix/pkg/hotgraph"
	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/nonce"
	"github.com/xhelix/xhelix/pkg/passport"
	"github.com/xhelix/xhelix/pkg/policy"
	"github.com/xhelix/xhelix/pkg/assetclass"
	"github.com/xhelix/xhelix/pkg/brp"
	brpphase "github.com/xhelix/xhelix/pkg/brp/phase"
	"github.com/xhelix/xhelix/pkg/brp/writerattr"
	"github.com/xhelix/xhelix/pkg/egressguard"
	"github.com/xhelix/xhelix/pkg/incidentgraph"
	"github.com/xhelix/xhelix/pkg/cdndetect"
	"github.com/xhelix/xhelix/pkg/flowstats"
	"github.com/xhelix/xhelix/pkg/longwindow"
	"github.com/xhelix/xhelix/pkg/pkgmgr"
	"github.com/xhelix/xhelix/pkg/secrettaint"
	"github.com/xhelix/xhelix/pkg/sshbrute"
	"github.com/xhelix/xhelix/pkg/integrity"
	"github.com/xhelix/xhelix/pkg/verify"
	"github.com/xhelix/xhelix/pkg/reqcontract"
	"github.com/xhelix/xhelix/pkg/source"
)

// defaultCatalogPaths lists candidate paths for the DLCF catalog,
// in priority order. The first one that loads cleanly wins; a
// missing file is not an error (DLCF is opt-in for v1).
var defaultCatalogPaths = []string{
	"/etc/xhelix/dlcf/catalog.yaml",
	"/usr/lib/xhelix/ruleset/dlcf/catalog.yaml",
}

// defaultEgressPaths is the analogous list for the Egress Valve
// destination policy.
var defaultEgressPaths = []string{
	"/etc/xhelix/dlcf/egress.yaml",
	"/usr/share/xhelix/ruleset/dlcf/egress.yaml",
}

// defaultAdminGuardPaths is the analogous list for the admin
// IP/ASN allow-list (P-B.0b).
var defaultAdminGuardPaths = []string{
	"/etc/xhelix/dlcf/admin_allowlist.yaml",
	"/usr/share/xhelix/ruleset/dlcf/admin_allowlist.yaml",
}

// foundationContext groups the Phase-1 evidence-truth primitives:
// the Event Admission Controller, the lineage minter + origin store,
// and the daemon's own canonical ProcKey for universal self-exclusion.
//
// It is constructed once at daemon startup and shared by handlers
// that need a stable view of what's wired.
type foundationContext struct {
	StartedAt   time.Time
	SelfProcKey canonical.ProcKey

	EAC       *eac.Controller
	Minter    *lineage.Minter
	Origins   *lineage.Store
	Classes   *lineage.ClassRegistry
	ProcCache *canonical.ProcKeyCache

	// SourceStore is the SQLite-backed v2 SourceAnchor store. Nil if
	// the parent directory is not writable — the daemon still runs but
	// anchors aren't persisted. T01 / Phase A1.
	SourceStore *source.Store
	// SourceMinter wires identity-event mint logic against SourceStore,
	// Minter (id allocator), and Origins (in-memory hot path). Nil-safe.
	SourceMinter *source.Minter
	// FileTaint is the in-memory per-path writer-provenance tracker.
	// Always constructed (no persistence yet); bounded LRU + 24h TTL.
	// T02 / Phase A2 commit 3.
	FileTaint *source.FileTaint

	// BRPMatcher resolves binaries to signed Behavioral Reference Profiles.
	// Loaded from /etc/xhelix/brp/*.signed.json with trust root from
	// /etc/xhelix/brp/trusted-keys.d/*.pub. Nil-safe — if no profiles
	// or no trust root, every binary resolves as Unprofiled. T05.
	BRPMatcher *brp.Matcher
	// BRPRuntime evaluates EventFacts against a resolved profile.
	// Stateless. Constructed with DefaultInvariants() unless an operator
	// override is loaded.
	BRPRuntime *brp.Runtime
	// BRPPhases is the per-PID phase state machine. T06.
	BRPPhases *brpphase.Tracker

	// BRPWriterCache caches eBPF-derived writer attribution so FIM events
	// can recover the writer identity.
	BRPWriterCache *writerattr.Cache
	// IntegrityTester runs the T1-T5 authentic-upgrade policy. Used as
	// the IntegrityAuthentic trust signal for protected-path writes.
	IntegrityTester *integrity.Tester
	// VerifyEngine is the Tier-2 verifier (T07 first-cut).
	VerifyEngine *verify.Engine
	// BRPEdges holds operator-signed inter-app interaction edges.
	BRPEdges *brp.EdgeSet
	// AssetResolver classifies paths/sockets/hosts into asset classes.
	AssetResolver assetclass.Resolver
	// SecretTaint tracks per-lineage secret-touch state.
	SecretTaint secrettaint.Store
	// EgressGuard handles per-event egress decisions. Phase C.
	EgressGuard egressguard.Guard
	// IncidentGraph assembles correlated incidents from events + alerts (Phase D.1).
	IncidentGraph incidentgraph.Engine
	// IncidentStore is the audit-trail backing for IncidentGraph.
	IncidentStore *incidentgraph.Store
	// SSHBrute is the per-source-IP SSH auth-failure counter (Phase J.1).
	SSHBrute *sshbrute.Detector
	// PkgMgr tracks package-manager transaction windows (Phase K.2).
	PkgMgr *pkgmgr.Store
	// LongWindow is the disk-backed long-horizon event journal (Phase H.2).
	LongWindow *longwindow.Store
	// CDNDNS is the Phase H.4 per-process recent-DNS cache used by
	// the CDN cloaking classifier.
	CDNDNS *cdndetect.DNSCache
	// FlowStats is the Phase H.1 per-image rolling byte counter.
	FlowStats *flowstats.Counters

	// DLCF subsystem (P7). May be nil if no catalog is configured.
	Catalog   *catalog.Catalog
	Budgets   *budget.Tracker
	Egress     *egress.Policy
	Passports  *passport.Store
	AdminGuard *adminguard.Guard
	HotGraph    *hotgraph.Graph
	ColdStore   *coldstore.Store
	Evidence    *evidence.Aggregator
	ReqContract *reqcontract.Store
	Nonces      *nonce.Store
}

// newFoundationContext constructs and starts the Phase-1 primitives.
// The EAC begins admitting events immediately but its Out() channel
// is consumed by the dispatch wiring elsewhere — this constructor
// is responsible only for liveness, not routing.
func newFoundationContext(parent context.Context) (*foundationContext, error) {
	selfPID := uint32(os.Getpid())
	self, err := canonical.ReadProcKey(selfPID)
	if err != nil {
		// Couldn't read our own /proc entry — extremely unusual, but
		// EAC self-exclusion still works on pid alone, so keep going.
		self = canonical.ProcKey{PID: selfPID}
	}

	fc := &foundationContext{
		StartedAt:   time.Now(),
		SelfProcKey: self,
		EAC: eac.New(eac.Config{
			ReorderWindow: 100 * time.Millisecond,
			InQueueSize:   8192,
			OutQueueSize:  8192,
			MaxBufferSize: 16384,
			SelfPID:       selfPID,
		}),
		Minter:    lineage.NewMinter(),
		Origins:   lineage.NewStore(),
		Classes:   lineage.NewClassRegistry(),
		ProcCache: canonical.NewProcKeyCache(canonical.CacheOptions{}),
	}
	// Prime the cache with the daemon's own ProcKey — every
	// self-exclusion check pays the cold cost otherwise.
	fc.ProcCache.Put(self)
	// Pre-register the well-known DLCF data classes so bit positions
	// are deterministic at startup (rather than depending on the
	// order in which sensors first touch them).
	for _, name := range []string{
		"public", "pii", "contact", "customer_order",
		"credentials", "payment_token", "api_key",
		"source_code", "backup", "canary",
	} {
		_, _ = fc.Classes.Bit(name)
	}

	// Try to load a DLCF catalog from one of the well-known paths.
	// Missing catalog is not fatal — DLCF is opt-in for v1.
	for _, p := range defaultCatalogPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		cat, err := catalog.Load(p)
		if err != nil {
			// Catalog exists but is malformed — that IS worth
			// surfacing; downstream handlers will still get nil
			// and tolerate it, but the operator should know.
			fc.Catalog = nil
			break
		}
		fc.Catalog = cat
		break
	}

	// Budget tracker is always created, even without a catalog,
	// so callers can register ad-hoc keys.
	fc.Budgets = budget.NewTracker(budget.Caps{})

	// Egress Valve: load destination policy from disk if present.
	// Missing file = empty policy = every tainted lineage denied
	// outbound until the operator opts in to destinations.
	fc.Egress = egress.New(fc.Classes)
	for _, p := range defaultEgressPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := fc.Egress.Load(p); err == nil {
			break
		}
	}

	// Data Passport store. Key lives separately from the chain
	// signing key — different responsibilities.
	passportKeyPath := "/var/lib/xhelix/passport.key"
	if priv, err := loadOrGenerateEd25519Key(passportKeyPath); err == nil {
		fc.Passports = passport.NewStore(priv)
		fc.Egress.AttachPassportSource(fc.Passports)
	} else {
		// Verify-only store with no key — issuance will error
		// clearly, but the Valve still works against static rules.
		fc.Passports = passport.NewStore(nil)
	}

	// Passport sweeper — drop expired/old-revoked records every minute.
	go fc.sweepPassports(parent)

	// Hot causal graph (P2.1/P2.2). Bounded LRU + retention sweep
	// driven by a goroutine below. Not yet wired into the dispatch
	// loop — sensors will populate it during P-RC.
	fc.HotGraph = hotgraph.New(hotgraph.Options{
		MaxNodes:        65536,
		ExitedRetention: 30 * time.Minute,
	})
	go fc.sweepHotGraph(parent)

	// Evidence aggregator (P2.4). Buckets repeated alerts by
	// (rule_id, kind, exe_sha, target_class, cgroup, origin_type,
	// 1-min window) — turning noisy rules into one rolled-up row.
	fc.Evidence = evidence.New(evidence.Options{})
	go fc.sweepEvidence(parent)

	// Nonce store (P-B.2). Single-use HMAC nonces for sensitive
	// endpoints — replay-resistance. Distinct key from reqcontract
	// because the trust scope is different (nonces only authorise
	// one redemption; contracts identify a request).
	nonceKeyPath := "/var/lib/xhelix/nonce.key"
	if nk, err := loadOrGenerateRCKey(nonceKeyPath); err == nil {
		if ns, err := nonce.NewStore(nk, 0); err == nil {
			fc.Nonces = ns
			go fc.sweepNonces(parent)
		}
	}

	// Request Contract store (P-RC.1). Per-HTTP-request capability
	// tokens, HMAC-signed, 30s default TTL. Substrate for the
	// behavioral defenses in BEHAVIORAL_DEFENSE.md.
	rcKeyPath := "/var/lib/xhelix/reqcontract.key"
	if rcKey, err := loadOrGenerateRCKey(rcKeyPath); err == nil {
		if rcStore, err := reqcontract.NewStore(rcKey, 0); err == nil {
			fc.ReqContract = rcStore
			go fc.sweepReqContract(parent)
		}
	}

	// Cold store (P2.3). Durable per-day-partitioned event store.
	// Best-effort: failure to open isn't fatal — the daemon still
	// runs without cold persistence. Path lives under StateDir.
	coldPath := "/var/lib/xhelix/cold.db"
	if cs, err := coldstore.New(coldstore.Options{
		Path:          coldPath,
		RetentionDays: 3, // 3-day local retention; off-host mirror
		// (was 14d; reduced 2026-05-24 after cold.db reached 21GB in 2
		// days at observed event rate. 14d × 12M events/day was
		// untenable on a 100GB rootfs. Operators with larger disks
		// can override via cfg.Store.Cold.RetentionDays.)
		// (P-CJ.10) is expected to hold longer history.
	}); err == nil {
		fc.ColdStore = cs
		fc.ColdStore.Start(parent)
		// Daily 03:00 UTC tick to drop old day-partitions. Pruning
		// is cheap (DROP TABLE) so doing it once a day is fine.
		go fc.pruneColdStore(parent)
	}

	// Admin route IP/ASN allow-list (P-B.0b). Tier-1 deterministic
	// guard. No geoip provider passed for v1 — daemon main wires
	// one in via SetGeoIP() if available.
	fc.AdminGuard = adminguard.New(nil)
	for _, p := range defaultAdminGuardPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := fc.AdminGuard.Load(p); err == nil {
			break
		}
	}

	fc.EAC.Start(parent)

	// Sweep ancient origin metadata every minute. Keeps the store
	// bounded; sessions older than 24 h are forensic-only and live
	// in the audit chain.
	go fc.sweepOrigins(parent)

	// Open the persistent SourceAnchor store. Missing parent dir or
	// write failure is non-fatal — Minter is nil-safe and the daemon
	// keeps running with in-memory-only Origins. T01 / Phase A1.
	if st, err := source.Open("/var/lib/xhelix/source.db"); err == nil {
		fc.SourceStore = st
		hostname, _ := os.Hostname()
		fc.SourceMinter = source.NewMinter(st, fc.Minter, fc.Origins, hostname)
		go fc.sweepSourceAnchors(parent)
	}

	// File-mediated taint tracker (in-memory only). Always constructed.
	// T02 commit 3.
	fc.FileTaint = source.NewFileTaint(0, 0) // 0 → defaults (4096 paths, 24h TTL)
	go fc.sweepFileTaint(parent)

	// BRP runtime substrate (T05/T06). Trust root loaded from
	// /etc/xhelix/brp/trusted-keys.d/*.pub. Profile library loaded
	// from /usr/share/xhelix/brp/ (vendor) and /etc/xhelix/brp/
	// (operator overlays). Missing dirs are not errors — daemon keeps
	// running with an empty library (every event = Unprofiled).
	fc.BRPMatcher, fc.BRPRuntime = buildBRP(parent)
	fc.BRPPhases = brpphase.NewTracker(0, 0, 0) // default windows
	fc.BRPWriterCache = writerattr.NewCache(0, 0)
	fc.IntegrityTester = integrity.NewTester()
	fc.VerifyEngine = verify.NewEngine()
	// EdgeSet uses the same trust root as the profile matcher. Loads
	// /etc/xhelix/brp/edges.d/*.edge.json — operator-signed inter-app
	// interaction allowlists. Empty dir is a valid configuration.
	{
		trust := loadBRPTrustRoot("/etc/xhelix/brp/trusted-keys.d")
		fc.BRPEdges = brp.NewEdgeSet(trust)
		if loaded, rejected, err := fc.BRPEdges.LoadDir("/etc/xhelix/brp/edges.d"); err == nil {
			if loaded > 0 || rejected > 0 {
				slog.Info("brp edges loaded", "loaded", loaded, "rejected", rejected)
			}
		}
	}

	// Asset class resolver (Phase B.1). Operator overrides loaded from
	// /etc/xhelix/assetclass.d/*.yaml; static rules apply universally
	// and cannot be relaxed.
	{
		opRules, opErrs := assetclass.LoadOperatorRules("/etc/xhelix/assetclass.d")
		for _, e := range opErrs {
			slog.Warn("assetclass operator rule error", "err", e)
		}
		if len(opRules) > 0 {
			fc.AssetResolver = assetclass.NewWithOverrides(opRules)
			slog.Info("assetclass resolver ready", "operator_overrides", len(opRules))
		} else {
			fc.AssetResolver = assetclass.NewStaticResolver()
			slog.Info("assetclass resolver ready", "operator_overrides", 0)
		}
	}

	// Secret-taint store (Phase B.2). 24h TTL — long enough for legit
	// long-running sessions, short enough that abandoned tainted
	// lineages don't accumulate. Operator can override later if needed.
	fc.SecretTaint = secrettaint.NewStore(24 * time.Hour)
	slog.Info("secrettaint store ready", "ttl", "24h")
	go fc.sweepSecretTaint(parent)

	// Egressguard (Phase C.2). Default mode = OBSERVE at foundation
	// construction. Mode is RE-SET in run.go after config load via
	// egressguard.NewGuard re-construction with the config-derived
	// mode. Foundation has no access to cfg.
	{
		backend, name := egressguard.SelectBackend(egressguard.ModeObserve)
		profiles := egressguard.NewBRPProfileLookup(fc.BRPMatcher)
		fc.EgressGuard = egressguard.NewGuard(backend, profiles, egressguard.ModeObserve)
		slog.Info("egressguard ready",
			"backend", name,
			"mode", "observe",
			"note", "mode may be overridden in run.go from cfg.Hardening.Egressguard.Mode")
	}
	go fc.sweepBRPPhases(parent)
	go fc.sweepBRPWriterCache(parent)

	// Incident graph (Phase D.1). 30-minute activity window for the
	// in-memory engine; Phase H.2 will introduce a parallel
	// long-window engine. Persistence at /var/lib/xhelix/incidents.db
	// — failures are logged but never block startup; the daemon
	// continues with an in-memory-only engine.
	{
		base := incidentgraph.NewEngine(30 * time.Minute)
		store, err := incidentgraph.OpenStore("/var/lib/xhelix/incidents.db")
		if err != nil {
			slog.Warn("incidentgraph store unavailable; running in-memory only", "err", err)
			fc.IncidentGraph = base
		} else {
			persisting, err := incidentgraph.NewPersistingEngine(base, store)
			if err != nil {
				slog.Warn("incidentgraph rehydrate failed; running in-memory only", "err", err)
				_ = store.Close()
				fc.IncidentGraph = base
			} else {
				fc.IncidentStore = store
				fc.IncidentGraph = persisting
				slog.Info("incidentgraph ready", "store", store.Path(),
					"hydrated_open", persisting.Size())
			}
		}
		go fc.sweepIncidents(parent)
	}

	// Package-manager log monitor (Phase K.2). Tails apt/dpkg/dnf/snap
	// log files; maintains active transaction windows so the pipeline
	// can stamp `pkg_install_window=true` on events arriving during a
	// transaction. This suppresses correlator chains like
	// dropped_binary_lifecycle on legitimate apt-get install flows.
	{
		fc.PkgMgr = pkgmgr.New(slog.Default())
		slog.Info("pkgmgr ready", "tailers", "apt+dpkg+dnf+snap")
		go fc.sweepPkgMgr(parent)
		go func() {
			if err := pkgmgr.TailApt(parent, fc.PkgMgr, "/var/log/apt/history.log"); err != nil {
				slog.Warn("pkgmgr: apt tailer exited", "err", err)
			}
		}()
		go func() {
			if err := pkgmgr.TailDpkg(parent, fc.PkgMgr, "/var/log/dpkg.log"); err != nil {
				slog.Warn("pkgmgr: dpkg tailer exited", "err", err)
			}
		}()
		go func() {
			if err := pkgmgr.TailDnf(parent, fc.PkgMgr, "/var/log/dnf.rpm.log"); err != nil {
				slog.Warn("pkgmgr: dnf tailer exited", "err", err)
			}
		}()
		go func() {
			if err := pkgmgr.TailSnap(parent, fc.PkgMgr, "/var/log/snapd.log"); err != nil {
				slog.Warn("pkgmgr: snap tailer exited", "err", err)
			}
		}()
	}

	// CDN cloaking DNS cache (Phase H.4). 2-minute retention,
	// 32 names per process — bounds memory while giving enough
	// signal for domain-fronting detection.
	{
		fc.CDNDNS = cdndetect.NewDNSCache(2*time.Minute, 32)
		slog.Info("cdndetect ready", "retention", "2m", "per_proc", 32)
	}

	// Per-image rolling byte counters (Phase H.1). 1-minute window
	// at 5s buckets. Pipeline updates on net_bytes; net_connect
	// events get stamped with current totals.
	{
		fc.FlowStats = flowstats.New(time.Minute, 5*time.Second)
		slog.Info("flowstats ready", "window", "1m", "bucket", "5s")
		go fc.sweepFlowStats(parent)
	}

	// Long-window event journal + threshold poller (Phase H.2).
	// Disk-backed at /var/lib/xhelix/longwindow.db. Pipeline records
	// per-net_connect (image, "egress_ip", dst_ip); a poller fires
	// when a configured threshold is met over a long window.
	{
		path := "/var/lib/xhelix/longwindow.db"
		st, err := longwindow.OpenStore(path)
		if err != nil {
			slog.Warn("longwindow: open failed; continuing without long-window correlation",
				"path", path, "err", err)
		} else {
			fc.LongWindow = st
			slog.Info("longwindow ready", "path", path)
			go fc.sweepLongWindow(parent)
			// Poller is started by run.go after the alert bus is up so
			// threshold breaches can be published as model.Alert.
		}
	}

	// SSH brute-force detector (Phase J.1). Defaults: 20 failures /
	// 60s window / 5-min cooldown. Sweep stale per-source state
	// every 5 min.
	{
		threshold, window, cooldown := sshbrute.Defaults()
		fc.SSHBrute = sshbrute.NewDetector(threshold, window, cooldown)
		slog.Info("sshbrute ready",
			"threshold", threshold, "window", window.String(),
			"cooldown", cooldown.String())
		go fc.sweepSSHBrute(parent)
	}

	return fc, nil
}

// sweepPkgMgr runs the package-manager window cleanup once per minute.
// Keeps windows around for 5 minutes after they end so late-arriving
// events still get the tag.
func (fc *foundationContext) sweepPkgMgr(ctx context.Context) {
	if fc.PkgMgr == nil {
		return
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			fc.PkgMgr.Sweep(now, 5*time.Minute)
		}
	}
}

// sweepLongWindow purges long-window events older than 7 days every
// hour, keeping disk usage bounded. 7 days is enough for the default
// 24h slow-C2 rule; operators wanting longer windows can extend.
func (fc *foundationContext) sweepLongWindow(ctx context.Context) {
	if fc.LongWindow == nil {
		return
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			n, err := fc.LongWindow.Sweep(7*24*time.Hour, now)
			if err != nil {
				slog.Warn("longwindow: sweep failed", "err", err)
			} else if n > 0 {
				slog.Info("longwindow: swept", "rows", n)
			}
		}
	}
}

// LongWindowRules returns the default H.2 threshold ruleset. Public
// so run.go can use it when starting the poller against the alert
// bus.
func LongWindowRules() []longwindow.Rule {
	return []longwindow.Rule{
		{
			ID:        "h2.slow_egress_fanout_24h",
			Tag:       "egress_ip",
			Mode:      longwindow.ModeDistinctValue,
			Window:    24 * time.Hour,
			Threshold: 20,
			Severity:  "high",
			Desc:      "Process reached ≥20 distinct destination IPs within 24h — slow C2 beacon or fan-out scan suspected.",
		},
	}
}

// sweepFlowStats prunes idle per-image entries from the rolling
// byte counters every 2 minutes.
func (fc *foundationContext) sweepFlowStats(ctx context.Context) {
	if fc.FlowStats == nil {
		return
	}
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if d := fc.FlowStats.Sweep(now); d > 0 {
				slog.Info("flowstats: swept idle images", "dropped", d)
			}
		}
	}
}

// sweepSSHBrute runs the per-source-IP cleanup once every 5 minutes.
func (fc *foundationContext) sweepSSHBrute(ctx context.Context) {
	if fc.SSHBrute == nil {
		return
	}
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			fc.SSHBrute.Sweep(now)
		}
	}
}

// sweepIncidents runs the in-memory engine's TTL sweeper once per
// minute. Closed incidents stay in the audit table; only the working
// set shrinks.
func (fc *foundationContext) sweepIncidents(ctx context.Context) {
	if fc.IncidentGraph == nil {
		return
	}
	type sweeper interface{ Sweep(time.Time) []string }
	sw, ok := fc.IncidentGraph.(sweeper)
	if !ok {
		// PersistingEngine embeds Engine; reach through.
		type embedded interface{ Sweep(time.Time) []string }
		if pe, ok := fc.IncidentGraph.(*incidentgraph.PersistingEngine); ok {
			sw = pe.Engine.(embedded)
		} else {
			return
		}
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			_ = sw.Sweep(now)
		}
	}
}

// buildBRP loads the trust root + signed profile library at startup.
// Returns a Matcher (possibly empty) and a Runtime with DefaultInvariants.
// Never fails — missing trust root or library is logged and treated as
// "no profiles loaded", which is the safe default.
func buildBRP(ctx context.Context) (*brp.Matcher, *brp.Runtime) {
	trust := loadBRPTrustRoot("/etc/xhelix/brp/trusted-keys.d")
	m := brp.NewMatcher(trust)
	for _, dir := range []string{"/usr/share/xhelix/brp", "/etc/xhelix/brp"} {
		loaded, rejected, err := m.LoadDir(dir)
		if err != nil {
			slog.Warn("brp load dir failed", "dir", dir, "err", err)
			continue
		}
		if loaded > 0 || rejected > 0 {
			slog.Info("brp profile library loaded",
				"dir", dir, "loaded", loaded, "rejected", rejected)
		}
	}
	slog.Info("brp matcher ready",
		"profiles", m.Size(), "trusted_signers", len(trust))
	r := brp.NewRuntime(brp.DefaultInvariants())
	return m, r
}

// loadBRPTrustRoot reads every *.pub file under dir as a base64-encoded
// Ed25519 public key. The file's basename (without .pub) becomes the
// signer name. Missing dir → empty map.
func loadBRPTrustRoot(dir string) map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			slog.Warn("brp trust root: read failed", "path", path, "err", err)
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			slog.Warn("brp trust root: base64 decode failed",
				"path", path, "err", err)
			continue
		}
		if len(decoded) != ed25519.PublicKeySize {
			slog.Warn("brp trust root: key wrong length",
				"path", path, "len", len(decoded), "want", ed25519.PublicKeySize)
			continue
		}
		signer := strings.TrimSuffix(e.Name(), ".pub")
		out[signer] = ed25519.PublicKey(decoded)
	}
	return out
}

// sweepSecretTaint periodically reclaims TTL-expired taint entries.
// Runs hourly; the store's internal Sweep audit-logs each forget.
func (fc *foundationContext) sweepSecretTaint(ctx context.Context) {
	if fc.SecretTaint == nil {
		return
	}
	m := secrettaint.AsMemStore(fc.SecretTaint)
	if m == nil {
		return
	}
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_ = m.Sweep(now)
		}
	}
}

// parseEgressguardMode maps the operator yaml token to the typed
// egressguard.Mode. Unknown / empty → ModeObserve (safe default).
func parseEgressguardMode(s string) egressguard.Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "shadow":
		return egressguard.ModeShadow
	case "enforce":
		return egressguard.ModeEnforce
	}
	return egressguard.ModeObserve
}

// sweepBRPWriterCache periodically reclaims stale attribution entries.
// Runs every 10s; the cache TTL is 5s so this keeps the LRU tight.
func (fc *foundationContext) sweepBRPWriterCache(ctx context.Context) {
	if fc.BRPWriterCache == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			fc.BRPWriterCache.Sweep(now)
		}
	}
}

// sweepBRPPhases periodically drops PID entries older than 24h so the
// tracker stays bounded across daemon lifetime.
func (fc *foundationContext) sweepBRPPhases(ctx context.Context) {
	if fc.BRPPhases == nil {
		return
	}
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			fc.BRPPhases.Sweep(now, 24*time.Hour)
		}
	}
}

func (fc *foundationContext) Stop() {
	if fc == nil {
		return
	}
	if fc.EAC != nil {
		fc.EAC.Stop()
	}
	if fc.ColdStore != nil {
		_ = fc.ColdStore.Close()
	}
	if fc.SourceStore != nil {
		_ = fc.SourceStore.Close()
	}
}

// loadOrGenerateRCKey returns the HMAC key for Request Contracts,
// reading it from disk if present, generating + persisting one
// otherwise. Distinct from the chain key and passport key (different
// trust scopes).
func loadOrGenerateRCKey(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) >= 32 {
		return data, nil
	}
	k, err := reqcontract.GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, k, 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func (fc *foundationContext) sweepNonces(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fc.Nonces != nil {
				fc.Nonces.Sweep(time.Now().UTC())
			}
		}
	}
}

func (fc *foundationContext) sweepReqContract(ctx context.Context) {
	// Tick every 10 s — most expiry happens via lazy-delete on
	// Lookup, but bursty idle workloads need the periodic broom.
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fc.ReqContract != nil {
				fc.ReqContract.Sweep(time.Now().UTC())
			}
		}
	}
}

func (fc *foundationContext) sweepEvidence(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fc.Evidence != nil {
				// Drop buckets that haven't been touched in 1 h
				// AND aren't promoted.
				fc.Evidence.Sweep(time.Now().Add(-time.Hour))
			}
		}
	}
}

// pruneColdStore drops day-partition tables past the retention
// horizon. Runs every hour; the DROP TABLE itself is instant.
// Closes the cold.db unbounded-growth gap (task #154).
func (fc *foundationContext) pruneColdStore(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	// Run once at startup so a long-stopped daemon catches up.
	if fc.ColdStore != nil {
		if dropped, err := fc.ColdStore.DropOldDays(time.Now()); err == nil && len(dropped) > 0 {
			// Log via stderr fallback — fc.log not in scope here.
			_ = dropped
		}
	}
	// Size-based backstop. Even with 3-day retention, high event volume
	// can fill disk inside the retention window. 2026-05-25 incident:
	// 18GB in 24h at 12-18M events/day pushed disk to 98% before
	// retention kicked in. 8GB cap fits comfortably on a 100GB rootfs
	// alongside the chain (~10GB), hot store (~1GB), and other state.
	const coldMaxBytes int64 = 8 * 1024 * 1024 * 1024
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fc.ColdStore != nil {
				_, _ = fc.ColdStore.DropOldDays(time.Now())
				_, _ = fc.ColdStore.DropDaysOverSize(coldMaxBytes)
			}
		}
	}
}

func (fc *foundationContext) sweepHotGraph(ctx context.Context) {
	// Run every minute — retention windows are O(min), nodes
	// shouldn't sit around past the next tick after expiry.
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fc.HotGraph != nil {
				fc.HotGraph.Sweep(time.Now())
			}
		}
	}
}

func (fc *foundationContext) sweepPassports(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if fc.Passports != nil {
				fc.Passports.Sweep(time.Now().UTC())
			}
		}
	}
}

func (fc *foundationContext) sweepOrigins(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fc.Origins.SweepOlderThan(time.Now().Add(-24 * time.Hour))
		}
	}
}

// sweepFileTaint prunes per-path writer-provenance entries older than
// the FileTaint's TTL. Cadence chosen to match the lazy-expiry behaviour
// of Lookup() so memory stays bounded under churn. T02 commit 3.
func (fc *foundationContext) sweepFileTaint(ctx context.Context) {
	if fc.FileTaint == nil {
		return
	}
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fc.FileTaint.SweepOlderThan(time.Now().Add(-24 * time.Hour))
		}
	}
}

// sweepSourceAnchors prunes persisted SourceAnchors older than 30 days.
// Anchors are forensic-grade evidence; longer retention than in-memory
// Origins (which sweep at 24h) so cross-session and delayed-persistence
// queries can still walk back to the original entry point.
func (fc *foundationContext) sweepSourceAnchors(ctx context.Context) {
	if fc.SourceStore == nil {
		return
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = fc.SourceStore.SweepOlderThan(ctx, time.Now().Add(-30*24*time.Hour))
		}
	}
}

// healthSnapshot is the shape returned by health.snapshot. Stable
// JSON contract — fields added with omitempty, removed never.
type healthSnapshot struct {
	Version    string              `json:"version"`
	StartedAt  string              `json:"started_at"`
	UptimeSecs int64               `json:"uptime_secs"`
	Self       healthSelfBlock     `json:"self"`
	EAC        healthEACBlock      `json:"eac"`
	ProcCache  healthProcCacheBlock `json:"proc_cache"`
	HotGraph   healthHotGraphBlock  `json:"hot_graph"`
	ColdStore  healthColdStoreBlock `json:"cold_store"`
	Evidence   healthEvidenceBlock  `json:"evidence"`
	ReqContract healthReqContractBlock `json:"req_contract"`
	Nonces      healthNonceBlock       `json:"nonces"`
	Lineage    healthLineageBlock  `json:"lineage"`
	DLCF       healthDLCFBlock     `json:"dlcf"`
	Runtime    healthRuntimeBlock  `json:"runtime"`
}

type healthDLCFBlock struct {
	CatalogLoaded  bool   `json:"catalog_loaded"`
	CatalogSource  string `json:"catalog_source,omitempty"`
	CatalogClasses int    `json:"catalog_classes,omitempty"`
	CatalogTables  int    `json:"catalog_tables,omitempty"`
	CatalogRoutes  int    `json:"catalog_routes,omitempty"`
	TrackedBudgets int    `json:"tracked_budgets"`
	EgressLoaded   bool   `json:"egress_loaded"`
	EgressSource   string `json:"egress_source,omitempty"`
	EgressRules    int    `json:"egress_rules,omitempty"`
	EgressChecks   uint64 `json:"egress_checks"`
	EgressDenied   uint64 `json:"egress_denied"`
	PassportActive int    `json:"passport_active"`
	PassportKeyID  string `json:"passport_key_id,omitempty"`
	AdminGuardRules   int    `json:"admin_guard_rules"`
	AdminGuardChecks  uint64 `json:"admin_guard_checks"`
	AdminGuardDenied  uint64 `json:"admin_guard_denied"`
	AdminGuardSource  string `json:"admin_guard_source,omitempty"`
}

type healthSelfBlock struct {
	PID        uint32 `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	ProcKey    string `json:"proc_key"`
}

type healthEACBlock struct {
	Admitted      uint64 `json:"admitted"`
	Drops         uint64 `json:"drops"`
	LossEvents    uint64 `json:"loss_events"`
	BufferSize    int    `json:"buffer_size"`
	ReorderWindow string `json:"reorder_window"`
}

type healthNonceBlock struct {
	IssuedOutstanding int    `json:"issued_outstanding"`
	ConsumedInWindow  int    `json:"consumed_in_window"`
	IssuedTotal       uint64 `json:"issued_total"`
	OK                uint64 `json:"ok"`
	Replayed          uint64 `json:"replayed"`
	Expired           uint64 `json:"expired"`
	BadSig            uint64 `json:"bad_signature"`
	NotIssued         uint64 `json:"not_issued"`
	InvalidScope      uint64 `json:"invalid_scope"`
}

type healthReqContractBlock struct {
	Size     int    `json:"size"`
	MaxSize  int    `json:"max_size"`
	Issued   uint64 `json:"issued"`
	Lookups  uint64 `json:"lookups"`
	LookupOK uint64 `json:"lookup_ok"`
	Expired  uint64 `json:"expired"`
	Rejected uint64 `json:"rejected"`
	Evicted  uint64 `json:"evicted"`
}

type healthEvidenceBlock struct {
	Buckets    int    `json:"buckets"`
	MaxBuckets int    `json:"max_buckets"`
	Promoted   int    `json:"promoted"`
	Observed   uint64 `json:"observed"`
	Dropped    uint64 `json:"dropped"`
	Swept      uint64 `json:"swept"`
}

type healthColdStoreBlock struct {
	Path         string `json:"path,omitempty"`
	QueueSize    int    `json:"queue_size"`
	QueueCap     int    `json:"queue_cap"`
	Submitted    uint64 `json:"submitted"`
	Written      uint64 `json:"written"`
	Dropped      uint64 `json:"dropped"`
	Batches      uint64 `json:"batches"`
	FlushErrs    uint64 `json:"flush_errs"`
	CurrentTable string `json:"current_table,omitempty"`
}

type healthHotGraphBlock struct {
	Nodes          int    `json:"nodes"`
	MaxNodes       int    `json:"max_nodes"`
	Pins           int    `json:"pins"`
	Inserts        uint64 `json:"inserts"`
	Evicts         uint64 `json:"evicts"`
	EvictsLRU      uint64 `json:"evicts_lru"`
	EvictsExitTTL  uint64 `json:"evicts_exit_ttl"`
	EvictsCapacity uint64 `json:"evicts_capacity"`
}

type healthProcCacheBlock struct {
	Size     int     `json:"size"`
	MaxSize  int     `json:"max_size"`
	TTLSecs  int     `json:"ttl_secs"`
	Hits     uint64  `json:"hits"`
	Misses   uint64  `json:"misses"`
	Evicts   uint64  `json:"evicts"`
	HitRatio float64 `json:"hit_ratio"`
}

type healthLineageBlock struct {
	StoredOrigins   int      `json:"stored_origins"`
	TaintedLineages int      `json:"tainted_lineages"`
	RegisteredClasses []string `json:"registered_classes,omitempty"`
}

type healthRuntimeBlock struct {
	NumGoroutine int    `json:"num_goroutine"`
	MemAllocMB   uint64 `json:"mem_alloc_mb"`
	NumCPU       int    `json:"num_cpu"`
	Goroot       string `json:"goroot,omitempty"`
}

// registerFoundationHandlers wires the foundation + DLCF observability
// surfaces into the LocalAPI:
//
//   - health.snapshot   — overall daemon health (EAC + lineage + runtime)
//   - catalog.stats     — Data Catalog counters + source path
//   - catalog.reload    — re-read the catalog YAML
//   - catalog.lookup    — classify a table/path/secret on demand
//   - taint.snapshot    — list lineages with non-empty taint + class names
//   - budget.usage      — per-key budget totals and exceeded flags
func registerFoundationHandlers(srv *localapi.Server, fc *foundationContext) {
	if srv == nil || fc == nil {
		return
	}
	srv.RegisterHandler("health.snapshot", func(_ context.Context, _ json.RawMessage) (any, error) {
		return fc.snapshot(), nil
	})
	srv.RegisterHandler("hotgraph.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.HotGraph == nil {
			return map[string]any{"enabled": false}, nil
		}
		return fc.HotGraph.Stats(), nil
	})
	srv.RegisterHandler("graph.ancestors", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.HotGraph == nil {
			return nil, errors.New("hot graph not initialised")
		}
		var req struct {
			PID        uint32 `json:"pid"`
			StartTicks uint64 `json:"start_ticks"`
			Depth      int    `json:"depth"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.PID == 0 {
			return nil, errors.New("pid required")
		}
		if req.Depth == 0 {
			req.Depth = -1
		}
		key := canonical.ProcKey{PID: req.PID, StartTicks: req.StartTicks}
		nodes := fc.HotGraph.Ancestors(key, req.Depth)
		return map[string]any{"count": len(nodes), "nodes": nodes}, nil
	})
	srv.RegisterHandler("graph.descendants", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.HotGraph == nil {
			return nil, errors.New("hot graph not initialised")
		}
		var req struct {
			PID        uint32 `json:"pid"`
			StartTicks uint64 `json:"start_ticks"`
			Depth      int    `json:"depth"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.PID == 0 {
			return nil, errors.New("pid required")
		}
		if req.Depth == 0 {
			req.Depth = -1
		}
		key := canonical.ProcKey{PID: req.PID, StartTicks: req.StartTicks}
		nodes := fc.HotGraph.Descendants(key, req.Depth)
		return map[string]any{"count": len(nodes), "nodes": nodes}, nil
	})
	srv.RegisterHandler("graph.lineage", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.HotGraph == nil {
			return nil, errors.New("hot graph not initialised")
		}
		var req struct {
			LineageID uint64 `json:"lineage_id"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.LineageID == 0 {
			return nil, errors.New("lineage_id required")
		}
		nodes := fc.HotGraph.ByLineage(lineage.LineageID(req.LineageID))
		return map[string]any{"count": len(nodes), "nodes": nodes}, nil
	})
	srv.RegisterHandler("graph.by_origin", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.HotGraph == nil {
			return nil, errors.New("hot graph not initialised")
		}
		var req struct {
			OriginIP string `json:"origin_ip"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.OriginIP == "" {
			return nil, errors.New("origin_ip required")
		}
		nodes := fc.HotGraph.ByOriginIP(req.OriginIP)
		return map[string]any{"count": len(nodes), "nodes": nodes}, nil
	})
	srv.RegisterHandler("graph.by_cgroup", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.HotGraph == nil {
			return nil, errors.New("hot graph not initialised")
		}
		var req struct {
			CGroupID uint64 `json:"cgroup_id"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.CGroupID == 0 {
			return nil, errors.New("cgroup_id required")
		}
		nodes := fc.HotGraph.ByCgroup(req.CGroupID)
		return map[string]any{"count": len(nodes), "nodes": nodes}, nil
	})
	srv.RegisterHandler("graph.get", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.HotGraph == nil {
			return nil, errors.New("hot graph not initialised")
		}
		var req struct {
			PID        uint32 `json:"pid"`
			StartTicks uint64 `json:"start_ticks"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.PID == 0 {
			return nil, errors.New("pid required")
		}
		key := canonical.ProcKey{PID: req.PID, StartTicks: req.StartTicks}
		node, ok := fc.HotGraph.Get(key)
		if !ok {
			return map[string]any{"found": false}, nil
		}
		return map[string]any{"found": true, "node": node}, nil
	})
	srv.RegisterHandler("nonce.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Nonces == nil {
			return map[string]any{"enabled": false}, nil
		}
		return fc.Nonces.Stats(), nil
	})
	srv.RegisterHandler("nonce.issue", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Nonces == nil {
			return nil, errors.New("nonce store not initialised")
		}
		var req struct {
			Scope      string `json:"scope"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		n, err := fc.Nonces.Issue(req.Scope, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			return nil, err
		}
		return n, nil
	})
	srv.RegisterHandler("nonce.consume", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Nonces == nil {
			return nil, errors.New("nonce store not initialised")
		}
		var req struct {
			Nonce *nonce.Nonce `json:"nonce"`
			Scope string       `json:"scope"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.Nonce == nil || req.Scope == "" {
			return nil, errors.New("nonce and scope required")
		}
		result := fc.Nonces.Consume(req.Nonce, req.Scope)
		return map[string]any{
			"result":   result.String(),
			"ok":       result == nonce.ConsumeOK,
			"replayed": result == nonce.ConsumeReplayed,
		}, nil
	})
	srv.RegisterHandler("reqcontract.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.ReqContract == nil {
			return map[string]any{"enabled": false}, nil
		}
		return fc.ReqContract.Stats(), nil
	})
	srv.RegisterHandler("reqcontract.issue", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.ReqContract == nil {
			return nil, errors.New("reqcontract store not initialised")
		}
		var p reqcontract.IssueParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		c, err := fc.ReqContract.Issue(p)
		if err != nil {
			return nil, err
		}
		return c, nil
	})
	srv.RegisterHandler("policy.check", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Catalog == nil {
			return nil, errors.New("no catalog loaded")
		}
		var req struct {
			Route      string `json:"route"`
			ContractID string `json:"contract_id"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.Route == "" {
			return nil, errors.New("route required")
		}
		var c *reqcontract.Contract
		if req.ContractID != "" && fc.ReqContract != nil {
			if found, ok := fc.ReqContract.Lookup(req.ContractID); ok {
				c = found
			}
		}
		return policy.Check(fc.Catalog, req.Route, c), nil
	})
	srv.RegisterHandler("reqcontract.lookup", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.ReqContract == nil {
			return nil, errors.New("reqcontract store not initialised")
		}
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.ID == "" {
			return nil, errors.New("id required")
		}
		c, ok := fc.ReqContract.Lookup(req.ID)
		if !ok {
			return map[string]any{"found": false}, nil
		}
		return map[string]any{"found": true, "contract": c}, nil
	})
	srv.RegisterHandler("evidence.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Evidence == nil {
			return map[string]any{"enabled": false}, nil
		}
		return fc.Evidence.Stats(), nil
	})
	srv.RegisterHandler("evidence.list", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Evidence == nil {
			return map[string]any{"buckets": []any{}}, nil
		}
		var req struct {
			Limit int `json:"limit"`
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &req)
		}
		if req.Limit <= 0 {
			req.Limit = 50
		}
		all := fc.Evidence.Snapshot()
		if len(all) > req.Limit {
			all = all[:req.Limit]
		}
		return map[string]any{"count": len(all), "buckets": all}, nil
	})
	srv.RegisterHandler("evidence.promote", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Evidence == nil {
			return nil, errors.New("evidence aggregator not initialised")
		}
		var req struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.Key == "" {
			return nil, errors.New("key required")
		}
		ok := fc.Evidence.Promote(req.Key)
		return map[string]any{"promoted": ok}, nil
	})
	srv.RegisterHandler("coldstore.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.ColdStore == nil {
			return map[string]any{"enabled": false}, nil
		}
		return fc.ColdStore.Stats(), nil
	})
	srv.RegisterHandler("coldstore.query", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.ColdStore == nil {
			return nil, errors.New("cold store not initialised")
		}
		var f coldstore.EventFilter
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
		}
		// Default severity filter = -1 (any) when unset; JSON's
		// default zero is 0 which would only match SeverityNotice.
		// Accept absence of the field via a wrapper.
		var w struct {
			HasSeverity bool `json:"-"`
		}
		_ = w
		if f.Severity == 0 {
			f.Severity = -1
		}
		events, err := fc.ColdStore.Query(f)
		if err != nil {
			return nil, err
		}
		return map[string]any{"count": len(events), "events": events}, nil
	})
	srv.RegisterHandler("proccache.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.ProcCache == nil {
			return map[string]any{"enabled": false}, nil
		}
		return fc.ProcCache.Stats(), nil
	})
	srv.RegisterHandler("proccache.resolve", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.ProcCache == nil {
			return nil, errors.New("proc cache not initialised")
		}
		var req struct {
			PID uint32 `json:"pid"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.PID == 0 {
			return nil, errors.New("pid required")
		}
		pk, err := fc.ProcCache.Resolve(req.PID)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"pid":         pk.PID,
			"start_ticks": pk.StartTicks,
			"proc_key":    pk.String(),
		}, nil
	})
	srv.RegisterHandler("catalog.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Catalog == nil {
			return map[string]any{"loaded": false}, nil
		}
		st := fc.Catalog.Stats()
		// Wrap the whole Stats so future fields don't need a
		// hand-rolled mapping per addition.
		return map[string]any{
			"loaded":            true,
			"classes":           st.Classes,
			"tables":            st.Tables,
			"path_globs":        st.PathGlobs,
			"secret_patterns":   st.SecretPatterns,
			"routes":            st.Routes,
			"canary_uids":       st.CanaryUIDs,
			"canary_uid_ranges": st.CanaryRanges,
			"canary_routes":     st.CanaryRoutes,
			"source":            st.Source,
		}, nil
	})
	srv.RegisterHandler("catalog.reload", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Catalog == nil {
			return nil, errors.New("no catalog loaded — set up /etc/xhelix/dlcf/catalog.yaml first")
		}
		if err := fc.Catalog.Reload(); err != nil {
			return nil, err
		}
		st := fc.Catalog.Stats()
		return map[string]any{"reloaded": true, "stats": st}, nil
	})
	srv.RegisterHandler("catalog.is_canary", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Catalog == nil {
			return nil, errors.New("no catalog loaded")
		}
		var req struct {
			UID   uint64 `json:"uid,omitempty"`
			Route string `json:"route,omitempty"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		out := map[string]any{}
		if req.UID != 0 {
			out["uid_is_canary"] = fc.Catalog.IsCanaryUID(req.UID)
		}
		if req.Route != "" {
			out["route_is_canary"] = fc.Catalog.IsCanaryRoute(req.Route)
		}
		if len(out) == 0 {
			return nil, errors.New("catalog.is_canary: provide uid or route")
		}
		return out, nil
	})
	srv.RegisterHandler("catalog.lookup", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Catalog == nil {
			return nil, errors.New("no catalog loaded")
		}
		var req struct {
			Table  string `json:"table,omitempty"`
			Path   string `json:"path,omitempty"`
			Secret string `json:"secret,omitempty"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &req); err != nil {
				return nil, err
			}
		}
		out := map[string]any{}
		if req.Table != "" {
			out["table_classes"] = stringClasses(fc.Catalog.ClassesForTable(req.Table))
		}
		if req.Path != "" {
			out["path_classes"] = stringClasses(fc.Catalog.ClassesForPath(req.Path))
		}
		if req.Secret != "" {
			name, cls, ok := fc.Catalog.ClassesForSecret(req.Secret)
			if ok {
				out["secret_match"] = map[string]any{
					"name":    name,
					"classes": stringClasses(cls),
				}
			}
		}
		if len(out) == 0 {
			return nil, errors.New("catalog.lookup: provide at least one of table/path/secret")
		}
		return out, nil
	})
	srv.RegisterHandler("taint.snapshot", func(_ context.Context, _ json.RawMessage) (any, error) {
		entries := fc.Origins.TaintsSnapshot()
		rows := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			rows = append(rows, map[string]any{
				"lineage_id": e.ID,
				"classes":    fc.Classes.NamesOf(e.Taint),
				"bits":       uint64(e.Taint),
			})
		}
		return map[string]any{
			"tainted_lineages": len(rows),
			"entries":          rows,
		}, nil
	})
	srv.RegisterHandler("budget.usage", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Budgets == nil {
			return map[string]any{"tracked_keys": 0, "entries": []any{}}, nil
		}
		all := fc.Budgets.All()
		return map[string]any{
			"tracked_keys": len(all),
			"entries":      all,
		}, nil
	})
	srv.RegisterHandler("egress.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Egress == nil {
			return map[string]any{"loaded": false}, nil
		}
		return fc.Egress.Stats(), nil
	})
	srv.RegisterHandler("egress.reload", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Egress == nil {
			return nil, errors.New("egress policy not initialised")
		}
		if err := fc.Egress.Reload(); err != nil {
			return nil, err
		}
		return map[string]any{"reloaded": true, "stats": fc.Egress.Stats()}, nil
	})
	srv.RegisterHandler("adminguard.stats", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.AdminGuard == nil {
			return map[string]any{"loaded": false}, nil
		}
		return fc.AdminGuard.Stats(), nil
	})
	srv.RegisterHandler("adminguard.reload", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.AdminGuard == nil {
			return nil, errors.New("admin guard not initialised")
		}
		if err := fc.AdminGuard.Reload(); err != nil {
			return nil, err
		}
		return map[string]any{"reloaded": true, "stats": fc.AdminGuard.Stats()}, nil
	})
	srv.RegisterHandler("adminguard.check", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.AdminGuard == nil {
			return nil, errors.New("admin guard not initialised")
		}
		var req struct {
			Route    string `json:"route"`
			SourceIP string `json:"source_ip"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.Route == "" || req.SourceIP == "" {
			return nil, errors.New("route and source_ip are required")
		}
		return fc.AdminGuard.Check(req.Route, req.SourceIP), nil
	})
	srv.RegisterHandler("passport.issue", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Passports == nil {
			return nil, errors.New("passport store not initialised")
		}
		var p passport.IssueParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		signed, err := fc.Passports.Issue(p)
		if err != nil {
			return nil, err
		}
		return signed, nil
	})
	srv.RegisterHandler("passport.list", func(_ context.Context, _ json.RawMessage) (any, error) {
		if fc.Passports == nil {
			return map[string]any{"active": 0, "passports": []any{}}, nil
		}
		list := fc.Passports.List()
		return map[string]any{
			"active":    len(list),
			"passports": list,
			"stats":     fc.Passports.Stats(),
		}, nil
	})
	srv.RegisterHandler("passport.revoke", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Passports == nil {
			return nil, errors.New("passport store not initialised")
		}
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		if req.ID == "" {
			return nil, errors.New("passport.revoke: id required")
		}
		fc.Passports.Revoke(req.ID)
		return map[string]any{"revoked": req.ID}, nil
	})
	srv.RegisterHandler("egress.check", func(_ context.Context, raw json.RawMessage) (any, error) {
		if fc.Egress == nil {
			return nil, errors.New("egress policy not initialised")
		}
		var req struct {
			Classes  []string `json:"classes"`
			DestIP   string   `json:"dest_ip"`
			DestHost string   `json:"dest_host"`
			DestPort uint16   `json:"dest_port"`
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &req); err != nil {
				return nil, err
			}
		}
		ip := net.ParseIP(req.DestIP)
		if ip == nil {
			return nil, errors.New("egress.check: dest_ip is required and must parse")
		}
		ts, _ := fc.Classes.SetFromNames(req.Classes)
		return fc.Egress.Allow(ts, ip, req.DestHost, req.DestPort), nil
	})
}

// nonceBlock returns the nonce-store summary for health.snapshot.
func (fc *foundationContext) nonceBlock() healthNonceBlock {
	if fc.Nonces == nil {
		return healthNonceBlock{}
	}
	s := fc.Nonces.Stats()
	return healthNonceBlock{
		IssuedOutstanding: s.Issued,
		ConsumedInWindow:  s.Consumed,
		IssuedTotal:       s.IssuedTotal,
		OK:                s.OK,
		Replayed:          s.Replayed,
		Expired:           s.Expired,
		BadSig:            s.BadSig,
		NotIssued:         s.NotIssued,
		InvalidScope:      s.InvalidScope,
	}
}

// reqContractBlock returns the Request Contract store summary for health.snapshot.
func (fc *foundationContext) reqContractBlock() healthReqContractBlock {
	if fc.ReqContract == nil {
		return healthReqContractBlock{}
	}
	s := fc.ReqContract.Stats()
	return healthReqContractBlock{
		Size:     s.Size,
		MaxSize:  s.MaxSize,
		Issued:   s.Issued,
		Lookups:  s.Lookups,
		LookupOK: s.LookupOK,
		Expired:  s.Expired,
		Rejected: s.Rejected,
		Evicted:  s.Evicted,
	}
}

// evidenceBlock returns the evidence-aggregator summary for health.snapshot.
func (fc *foundationContext) evidenceBlock() healthEvidenceBlock {
	if fc.Evidence == nil {
		return healthEvidenceBlock{}
	}
	s := fc.Evidence.Stats()
	return healthEvidenceBlock{
		Buckets:    s.Buckets,
		MaxBuckets: s.MaxBuckets,
		Promoted:   s.Promoted,
		Observed:   s.Observed,
		Dropped:    s.Dropped,
		Swept:      s.Swept,
	}
}

// coldStoreBlock returns the cold-store summary for health.snapshot.
func (fc *foundationContext) coldStoreBlock() healthColdStoreBlock {
	if fc.ColdStore == nil {
		return healthColdStoreBlock{}
	}
	s := fc.ColdStore.Stats()
	return healthColdStoreBlock{
		Path:         s.Path,
		QueueSize:    s.QueueSize,
		QueueCap:     s.QueueCap,
		Submitted:    s.Submitted,
		Written:      s.Written,
		Dropped:      s.Dropped,
		Batches:      s.Batches,
		FlushErrs:    s.FlushErrs,
		CurrentTable: s.CurrentTable,
	}
}

// hotGraphBlock returns the hot graph summary for health.snapshot.
func (fc *foundationContext) hotGraphBlock() healthHotGraphBlock {
	if fc.HotGraph == nil {
		return healthHotGraphBlock{}
	}
	s := fc.HotGraph.Stats()
	return healthHotGraphBlock{
		Nodes:          s.Nodes,
		MaxNodes:       s.MaxNodes,
		Pins:           s.Pins,
		Inserts:        s.Inserts,
		Evicts:         s.Evicts,
		EvictsLRU:      s.EvictsLRU,
		EvictsExitTTL:  s.EvictsExitTTL,
		EvictsCapacity: s.EvictsCapacity,
	}
}

// procCacheBlock returns the ProcKey cache summary for health.snapshot.
func (fc *foundationContext) procCacheBlock() healthProcCacheBlock {
	if fc.ProcCache == nil {
		return healthProcCacheBlock{}
	}
	s := fc.ProcCache.Stats()
	return healthProcCacheBlock{
		Size:     s.Size,
		MaxSize:  s.MaxSize,
		TTLSecs:  s.TTLSecs,
		Hits:     s.Hits,
		Misses:   s.Misses,
		Evicts:   s.Evicts,
		HitRatio: fc.ProcCache.HitRatio(),
	}
}

// dlcfBlock returns the DLCF summary embedded in health.snapshot.
func (fc *foundationContext) dlcfBlock() healthDLCFBlock {
	b := healthDLCFBlock{}
	if fc.Budgets != nil {
		b.TrackedBudgets = fc.Budgets.Size()
	}
	if fc.Egress != nil {
		es := fc.Egress.Stats()
		if es.Source != "" {
			b.EgressLoaded = true
			b.EgressSource = es.Source
			b.EgressRules = es.RuleCount
		}
		b.EgressChecks = es.Checks
		b.EgressDenied = es.Denied
	}
	if fc.Passports != nil {
		ps := fc.Passports.Stats()
		b.PassportActive = ps.Active
		b.PassportKeyID = ps.KeyID
	}
	if fc.AdminGuard != nil {
		as := fc.AdminGuard.Stats()
		b.AdminGuardRules = as.RuleCount
		b.AdminGuardChecks = as.Checks
		b.AdminGuardDenied = as.Denied
		b.AdminGuardSource = as.Source
	}
	if fc.Catalog == nil {
		return b
	}
	st := fc.Catalog.Stats()
	b.CatalogLoaded = true
	b.CatalogSource = st.Source
	b.CatalogClasses = st.Classes
	b.CatalogTables = st.Tables
	b.CatalogRoutes = st.Routes
	return b
}

// stringClasses renders a slice of catalog.DataClass as plain strings
// so the JSON response is operator-friendly.
func stringClasses(cls []catalog.DataClass) []string {
	out := make([]string, len(cls))
	for i, c := range cls {
		out[i] = string(c)
	}
	return out
}

func (fc *foundationContext) snapshot() healthSnapshot {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	stats := fc.EAC.Stats()
	return healthSnapshot{
		Version:    "0.0.11-dev",
		StartedAt:  fc.StartedAt.UTC().Format(time.RFC3339),
		UptimeSecs: int64(time.Since(fc.StartedAt).Seconds()),
		Self: healthSelfBlock{
			PID:        fc.SelfProcKey.PID,
			StartTicks: fc.SelfProcKey.StartTicks,
			ProcKey:    fc.SelfProcKey.String(),
		},
		EAC: healthEACBlock{
			Admitted:      stats.Admitted,
			Drops:         stats.Drops,
			LossEvents:    stats.LossEvents,
			BufferSize:    stats.BufferSize,
			ReorderWindow: "100ms",
		},
		ProcCache: fc.procCacheBlock(),
		HotGraph:  fc.hotGraphBlock(),
		ColdStore: fc.coldStoreBlock(),
		Evidence:  fc.evidenceBlock(),
		ReqContract: fc.reqContractBlock(),
		Nonces:      fc.nonceBlock(),
		Lineage: healthLineageBlock{
			StoredOrigins:     fc.Origins.Size(),
			TaintedLineages:   fc.Origins.TaintedCount(),
			RegisteredClasses: fc.Classes.Names(),
		},
		DLCF: fc.dlcfBlock(),
		Runtime: healthRuntimeBlock{
			NumGoroutine: runtime.NumGoroutine(),
			MemAllocMB:   mem.Alloc / 1024 / 1024,
			NumCPU:       runtime.NumCPU(),
		},
	}
}
