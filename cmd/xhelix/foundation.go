package main

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"time"

	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/eac"
	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/localapi"
)

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
	}
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
	Runtime    healthRuntimeBlock  `json:"runtime"`
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
	StoredOrigins int `json:"stored_origins"`
}

type healthRuntimeBlock struct {
	NumGoroutine int    `json:"num_goroutine"`
	MemAllocMB   uint64 `json:"mem_alloc_mb"`
	NumCPU       int    `json:"num_cpu"`
	Goroot       string `json:"goroot,omitempty"`
}

// registerFoundationHandlers wires health.snapshot into the LocalAPI.
func registerFoundationHandlers(srv *localapi.Server, fc *foundationContext) {
	if srv == nil || fc == nil {
		return
	}
	srv.RegisterHandler("health.snapshot", func(_ context.Context, _ json.RawMessage) (any, error) {
		return fc.snapshot(), nil
	})
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
			StoredOrigins: fc.Origins.Size(),
		},
		Runtime: healthRuntimeBlock{
			NumGoroutine: runtime.NumGoroutine(),
			MemAllocMB:   mem.Alloc / 1024 / 1024,
			NumCPU:       runtime.NumCPU(),
		},
	}
}
