package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"time"

	"github.com/xhelix/xhelix/pkg/budget"
	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/catalog"
	"github.com/xhelix/xhelix/pkg/eac"
	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/localapi"
)

// defaultCatalogPaths lists candidate paths for the DLCF catalog,
// in priority order. The first one that loads cleanly wins; a
// missing file is not an error (DLCF is opt-in for v1).
var defaultCatalogPaths = []string{
	"/etc/xhelix/dlcf/catalog.yaml",
	"/usr/lib/xhelix/ruleset/dlcf/catalog.yaml",
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

	EAC      *eac.Controller
	Minter   *lineage.Minter
	Origins  *lineage.Store
	Classes  *lineage.ClassRegistry

	// DLCF subsystem (P7). May be nil if no catalog is configured.
	Catalog *catalog.Catalog
	Budgets *budget.Tracker
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
		Minter:  lineage.NewMinter(),
		Origins: lineage.NewStore(),
		Classes: lineage.NewClassRegistry(),
	}
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

	fc.EAC.Start(parent)

	// Sweep ancient origin metadata every minute. Keeps the store
	// bounded; sessions older than 24 h are forensic-only and live
	// in the audit chain.
	go fc.sweepOrigins(parent)

	return fc, nil
}

func (fc *foundationContext) Stop() {
	if fc == nil || fc.EAC == nil {
		return
	}
	fc.EAC.Stop()
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
}

// dlcfBlock returns the DLCF summary embedded in health.snapshot.
func (fc *foundationContext) dlcfBlock() healthDLCFBlock {
	b := healthDLCFBlock{}
	if fc.Budgets != nil {
		b.TrackedBudgets = fc.Budgets.Size()
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
