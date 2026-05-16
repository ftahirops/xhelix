package ebpf

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Sensor is the public Sensor implementation that wraps a platform
// backend. The backend produces events on an internal channel; the
// Sensor projects them into model.Event and writes to out.
type Sensor struct {
	cfg     Config
	backend Backend
	out     chan<- model.Event
	cancel  context.CancelFunc
	running atomic.Bool
	last    atomic.Int64
}

// New returns a Sensor with the platform-default backend.
func New(cfg Config) *Sensor {
	return &Sensor{cfg: cfg, backend: newPlatformBackend(cfg)}
}

// Name implements sensors.Sensor.
func (s *Sensor) Name() string { return "ebpf" }

// Start implements sensors.Sensor.
func (s *Sensor) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("ebpf: already started")
	}
	s.out = out
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	if err := s.backend.Start(ctx, out); err != nil {
		s.running.Store(false)
		cancel()
		return err
	}
	return nil
}

// Stop implements sensors.Sensor.
func (s *Sensor) Stop(ctx context.Context) error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	return s.backend.Stop(ctx)
}

// Health implements sensors.Sensor.
func (s *Sensor) Health() sensors.Health {
	return sensors.Health{
		Healthy:   s.backend.Healthy(),
		DropCount: s.backend.Drops(),
		LastEvent: time.Unix(0, s.last.Load()),
	}
}
