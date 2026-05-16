// Package heartbeat is the agent's reference Sensor, used to prove
// the daemon is alive in Phase 0 and to surface a liveness signal
// even after richer sensors come online.
package heartbeat

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Sensor emits one Info-severity event per Interval to confirm
// liveness. Operators can disable it once richer sensors are wired.
type Sensor struct {
	Interval time.Duration
	Host     string

	mu        sync.Mutex
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	emitted   atomic.Uint64
	lastEvent atomic.Int64
	running   atomic.Bool
}

// New returns a Sensor that emits at interval. interval <= 0 selects
// 1 second.
func New(interval time.Duration, host string) *Sensor {
	if interval <= 0 {
		interval = time.Second
	}
	return &Sensor{Interval: interval, Host: host}
}

// Name implements sensors.Sensor.
func (s *Sensor) Name() string { return "heartbeat" }

// Start implements sensors.Sensor.
func (s *Sensor) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return errors.New("heartbeat: already started")
	}
	s.mu.Lock()
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.mu.Unlock()

	s.wg.Add(1)
	go s.loop(ctx, out)
	return nil
}

// Stop implements sensors.Sensor.
func (s *Sensor) Stop(ctx context.Context) error {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.running.Store(false)
	return nil
}

// Health implements sensors.Sensor.
func (s *Sensor) Health() sensors.Health {
	return sensors.Health{
		Healthy:   s.running.Load(),
		LastEvent: time.Unix(0, s.lastEvent.Load()),
	}
}

// Emitted returns the number of events emitted since Start.
func (s *Sensor) Emitted() uint64 { return s.emitted.Load() }

func (s *Sensor) loop(ctx context.Context, out chan<- model.Event) {
	defer s.wg.Done()
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			ev := model.NewEvent("heartbeat", model.SeverityInfo)
			ev.Time = now.UTC()
			ev.Host = s.Host
			ev.Tags["msg"] = "agent alive"
			select {
			case out <- ev:
				s.emitted.Add(1)
				s.lastEvent.Store(now.UnixNano())
			case <-ctx.Done():
				return
			default:
				// Channel full; drop silently. The bus's drop
				// counter is the authoritative metric.
			}
		}
	}
}
