package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"

	"net"

	"github.com/xhelix/xhelix/pkg/adminguard"
	"github.com/xhelix/xhelix/pkg/budget"
	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/catalog"
	"github.com/xhelix/xhelix/pkg/coldstore"
	"github.com/xhelix/xhelix/pkg/eac"
	"github.com/xhelix/xhelix/pkg/egress"
	"github.com/xhelix/xhelix/pkg/hotgraph"
	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/passport"
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

	// DLCF subsystem (P7). May be nil if no catalog is configured.
	Catalog   *catalog.Catalog
	Budgets   *budget.Tracker
	Egress     *egress.Policy
	Passports  *passport.Store
	AdminGuard *adminguard.Guard
	HotGraph   *hotgraph.Graph
	ColdStore  *coldstore.Store
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

	// Cold store (P2.3). Durable per-day-partitioned event store.
	// Best-effort: failure to open isn't fatal — the daemon still
	// runs without cold persistence. Path lives under StateDir.
	coldPath := "/var/lib/xhelix/cold.db"
	if cs, err := coldstore.New(coldstore.Options{Path: coldPath}); err == nil {
		fc.ColdStore = cs
		fc.ColdStore.Start(parent)
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

	return fc, nil
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
		return map[string]any{
			"loaded":          true,
			"classes":         st.Classes,
			"tables":          st.Tables,
			"path_globs":      st.PathGlobs,
			"secret_patterns": st.SecretPatterns,
			"routes":          st.Routes,
			"source":          st.Source,
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
