// Package procscrape — see allowlist.go for the rationale.
//
// The Sensor type satisfies sensors.Sensor so the daemon can list
// procscrape alongside other observation sources, but it does not
// own a goroutine — the actual events are produced by the eBPF
// backend (XH_EV_PROC_SCRAPE). This package's runtime job is to
// enrich those events with the allowlist verdict via Enrich().
package procscrape

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Sensor exposes procscrape state to operators (Health, counters)
// without owning a goroutine. The actual event source is the
// eBPF backend; this sensor's Start/Stop are no-ops.
type Sensor struct {
	allow *Allowlist

	running atomic.Bool
	seen    atomic.Uint64
	allowed atomic.Uint64
	flagged atomic.Uint64
}

// NewSensor creates a procscrape sensor backed by allow.
func NewSensor(allow *Allowlist) *Sensor {
	if allow == nil {
		allow = Default()
	}
	return &Sensor{allow: allow}
}

// Allowlist exposes the active allowlist (e.g., for status surfaces).
func (s *Sensor) Allowlist() *Allowlist { return s.allow }

// Name implements sensors.Sensor.
func (s *Sensor) Name() string { return "procscrape" }

// Start is a no-op other than recording the running flag.
func (s *Sensor) Start(_ context.Context, _ chan<- model.Event) error {
	s.running.Store(true)
	return nil
}

// Stop clears the running flag.
func (s *Sensor) Stop(_ context.Context) error {
	s.running.Store(false)
	return nil
}

// Health implements sensors.Sensor.
func (s *Sensor) Health() sensors.Health {
	return sensors.Health{
		Healthy: s.running.Load(),
		Reason: fmt.Sprintf("allowlist_size=%d seen=%d allowed=%d flagged=%d",
			s.allow.Size(), s.seen.Load(), s.allowed.Load(), s.flagged.Load()),
	}
}

// Enrich annotates a proc_scrape event with the allowlist verdict.
//
// The event must already carry the kernel-supplied reader identity
// (ev.PID, ev.Comm, ev.Image) and the path/target_pid/scrape_kind
// tags set by sensors/ebpf decodeProcScrape.
//
// Tags added:
//   - cred_proc_scrape = "true" when the reader is NOT allowlisted
//     AND the target PID differs from the reader's own PID
//   - allowlisted_reader = "true" when the reader matched the
//     allowlist (suppresses the rule)
//
// Self-reads (reader_pid == target_pid) are always allowed —
// they're trivially benign and would otherwise produce noise from
// every program that reads its own /proc entries (e.g., glibc
// stack-randomisation probe).
func (s *Sensor) Enrich(ev *model.Event) {
	if ev == nil || ev.Tags == nil {
		return
	}
	if ev.Tags["kind"] != "proc_scrape" {
		return
	}
	s.seen.Add(1)

	targetPID := uint32(0)
	if v := ev.Tags["target_pid"]; v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil {
			targetPID = uint32(n)
		}
	}
	// Self-read: reader is inspecting its own /proc entry.
	if targetPID != 0 && targetPID == ev.PID {
		ev.Tags["allowlisted_reader"] = "true"
		ev.Tags["allowlist_reason"] = "self-read"
		s.allowed.Add(1)
		return
	}
	if s.allow.IsAllowed(ev.Comm, ev.Image) {
		ev.Tags["allowlisted_reader"] = "true"
		ev.Tags["allowlist_reason"] = "allowlisted"
		s.allowed.Add(1)
		return
	}
	ev.Tags["cred_proc_scrape"] = "true"
	s.flagged.Add(1)
	// Raise severity for the credential-bearing kinds. status/cmdline
	// are filtered kernel-side already; what reaches here is
	// environ/maps/mem/auxv.
	if ev.Severity < model.SeverityWarn {
		ev.Severity = model.SeverityWarn
	}
}

// Stats returns the live counter snapshot.
func (s *Sensor) Stats() (seen, allowed, flagged uint64) {
	return s.seen.Load(), s.allowed.Load(), s.flagged.Load()
}
