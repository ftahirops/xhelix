// Package memdiff is the sensors.Sensor adapter for pkg/memdiff —
// periodic /proc/*/maps diffing for new anonymous executable
// mappings.
package memdiff

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	mdiff "github.com/xhelix/xhelix/pkg/memdiff"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/procmem"
	"github.com/xhelix/xhelix/sensors"
)

// Sensor wraps a memdiff.Scanner and runs its Tick loop.
type Sensor struct {
	host     string
	interval time.Duration
	scanner  *mdiff.Scanner

	running atomic.Bool
	cancel  context.CancelFunc
	reason  string
}

// NewSensor constructs a memdiff sensor.
//
//	interval: default 60s. Lower tightens detection window at small
//	          CPU cost (~10-50ms per scan on a 200-pid host).
//	allow:    JIT runtime allowlist; nil = no exemptions (more noise).
func NewSensor(host string, interval time.Duration, allow procmem.Allowlister) *Sensor {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &Sensor{
		host:     host,
		interval: interval,
		scanner:  mdiff.New(allow),
	}
}

// Name implements sensors.Sensor.
func (s *Sensor) Name() string { return "memdiff" }

// Start kicks off the periodic Tick loop.
func (s *Sensor) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("memdiff: already started")
	}
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.reason = "running"
	go s.scanner.Run(ctx, s.interval, out, s.host)
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
	st := s.scanner.Stats()
	return sensors.Health{
		Healthy: s.running.Load(),
		Reason: fmt.Sprintf("%s; ticks=%d new_regions=%d allowlisted=%d",
			s.reason, st.Ticks, st.NewRegions, st.Allowlisted),
	}
}
