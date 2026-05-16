// Package fim implements the Sensor interface for file-integrity monitoring.
//
// It wraps pkg/fim baseline + periodic verify, emitting events when files
// change, are removed, or are added outside the baseline.
package fim

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/fim"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Sensor periodically verifies file integrity against a baseline.
type Sensor struct {
	dbPath     string
	watchPaths []string
	host       string
	interval   time.Duration

	mu       sync.Mutex
	out      chan<- model.Event
	cancel   context.CancelFunc
	running  atomic.Bool
	baseline *fim.Baseline
	healthy  atomic.Bool
	reason   string
}

// NewSensor creates a FIM sensor.
func NewSensor(dbPath string, watchPaths []string, host string, interval time.Duration) *Sensor {
	if interval == 0 {
		interval = 5 * time.Minute
	}
	return &Sensor{
		dbPath:     dbPath,
		watchPaths: watchPaths,
		host:       host,
		interval:   interval,
	}
}

// Name implements sensors.Sensor.
func (s *Sensor) Name() string { return "fim" }

// Start opens the baseline database, builds it if empty, and starts
// the periodic verify loop.
func (s *Sensor) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("fim: already started")
	}

	b, err := fim.Open(s.dbPath)
	if err != nil {
		s.running.Store(false)
		return fmt.Errorf("fim open: %w", err)
	}
	s.baseline = b

	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.out = out

	// Initial build if needed
	count, err := b.Build(ctx, s.watchPaths)
	if err != nil {
		s.reason = fmt.Sprintf("build failed: %v", err)
		s.healthy.Store(false)
	} else {
		s.reason = fmt.Sprintf("baseline %d entries", count)
		s.healthy.Store(true)
	}

	go s.loop(ctx)
	return nil
}

// Stop halts the verify loop and closes the baseline database.
func (s *Sensor) Stop(ctx context.Context) error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.baseline != nil {
		_ = s.baseline.Close()
	}
	return nil
}

// Health implements sensors.Sensor.
func (s *Sensor) Health() sensors.Health {
	return sensors.Health{
		Healthy: s.healthy.Load(),
		Reason:  s.reason,
	}
}

func (s *Sensor) loop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.verify(ctx)
		}
	}
}

func (s *Sensor) verify(ctx context.Context) {
	if s.baseline == nil {
		return
	}
	drifts, err := s.baseline.Verify(ctx, s.watchPaths)
	if err != nil {
		s.reason = fmt.Sprintf("verify error: %v", err)
		s.healthy.Store(false)
		return
	}

	s.healthy.Store(true)
	s.reason = fmt.Sprintf("verify ok, %d drifts", len(drifts))

	for _, d := range drifts {
		ev := model.NewEvent("fim.drift", model.SeverityHigh)
		ev.Time = time.Now().UTC()
		ev.Host = s.host
		ev.Tags["path"] = d.Path
		ev.Tags["reason"] = d.Reason
		if d.Got.SHA256 != "" {
			ev.Tags["sha256"] = d.Got.SHA256
		}
		if d.Want.SHA256 != "" {
			ev.Tags["expected_sha256"] = d.Want.SHA256
		}
		select {
		case <-ctx.Done():
			return
		case s.out <- ev:
		}
	}
}
