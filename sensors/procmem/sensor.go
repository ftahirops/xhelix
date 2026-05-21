// Package procmem implements the Sensor for periodic /proc-based
// memory-execution checks (deleted-binary + thread-outside-module).
// The heavy lifting lives in pkg/procmem; this file is the
// sensors.Sensor adapter.
package procmem

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	pmem "github.com/xhelix/xhelix/pkg/procmem"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Sensor periodically scans /proc and emits findings.
type Sensor struct {
	host     string
	interval time.Duration
	scanner  *pmem.Scanner

	running atomic.Bool
	healthy atomic.Bool
	reason  string
	cancel  context.CancelFunc

	lastFindings atomic.Uint64
}

// NewSensor creates a procmem sensor.
//
//	interval: how often to walk /proc. Default 60s. Lower values
//	          tighten the detection window but cost more CPU
//	          (~5-15ms per scan on a 100-PID host).
//	allow:    a runtimeallow.Set (or any Allowlister) — processes
//	          whose image/comm matches are exempted from the
//	          thread-outside-module check (JIT runtimes).
func NewSensor(host string, interval time.Duration, allow pmem.Allowlister) *Sensor {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &Sensor{
		host:     host,
		interval: interval,
		scanner:  pmem.New(allow),
	}
}

// Name implements sensors.Sensor.
func (s *Sensor) Name() string { return "procmem" }

// Start begins the scan loop.
func (s *Sensor) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("procmem: already started")
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.healthy.Store(true)
	s.reason = "running"
	go s.loop(ctx, out)
	return nil
}

// Stop cancels the scan loop.
func (s *Sensor) Stop(_ context.Context) error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

// Health implements sensors.Sensor.
func (s *Sensor) Health() sensors.Health {
	return sensors.Health{
		Healthy: s.healthy.Load(),
		Reason:  fmt.Sprintf("%s; last_scan_findings=%d", s.reason, s.lastFindings.Load()),
	}
}

func (s *Sensor) loop(ctx context.Context, out chan<- model.Event) {
	// First scan immediately so operators see results during the
	// first interval rather than waiting a minute.
	s.runOne(ctx, out)
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.runOne(ctx, out)
		}
	}
}

func (s *Sensor) runOne(ctx context.Context, out chan<- model.Event) {
	fs := s.scanner.Scan()
	s.lastFindings.Store(uint64(len(fs)))
	for _, f := range fs {
		ev := newEvent(s.host, f)
		select {
		case <-ctx.Done():
			return
		case out <- ev:
		default:
			// Drop on full channel — losing one procmem finding
			// is preferable to blocking the scanner.
		}
	}
}

// newEvent maps a Finding to a model.Event with the tag shape that
// the rule predicates consume.
func newEvent(host string, f pmem.Finding) model.Event {
	ev := model.NewEvent("procmem", model.SeverityHigh)
	ev.Time = time.Now().UTC()
	ev.Host = host
	ev.PID = f.PID
	ev.TID = f.TID
	ev.Comm = f.Comm
	ev.Image = f.Image
	ev.UID = f.UID
	ev.Tags["kind"] = f.Kind
	ev.Tags["reason"] = f.Reason
	ev.Tags["detail"] = f.Detail
	ev.Tags["realtime"] = "false" // periodic, not push-based
	return ev
}
