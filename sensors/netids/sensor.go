// Package netids implements the Sensor interface for network intrusion detection.
//
// It wraps the EveTailer (Suricata EVE JSON) and optionally starts the
// SuricataSupervisor. DGA, beacon, and NXDOMAIN detectors are applied
// to DNS and flow events in the dispatch loop rather than here.
package netids

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/sensors"
)

// Sensor tails Suricata EVE JSON and emits model.Events.
type Sensor struct {
	evePath     string
	suricataBin string
	iface       string
	host        string

	mu         sync.Mutex
	out        chan<- model.Event
	cancel     context.CancelFunc
	running    atomic.Bool
	healthy    atomic.Bool
	reason     string
	supervisor *SuricataSupervisor
	tailer     *EveTailer
}

// NewSensor creates a NetIDS sensor.
func NewSensor(evePath, suricataBin, iface, host string) *Sensor {
	return &Sensor{
		evePath:     evePath,
		suricataBin: suricataBin,
		iface:       iface,
		host:        host,
	}
}

// Name implements sensors.Sensor.
func (s *Sensor) Name() string { return "netids" }

// Start optionally launches Suricata and begins tailing EVE JSON.
func (s *Sensor) Start(parent context.Context, out chan<- model.Event) error {
	if !s.running.CompareAndSwap(false, true) {
		return fmt.Errorf("netids: already started")
	}

	s.out = out
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel

	// If we have a suricata binary and interface, start the supervisor.
	if s.suricataBin != "" && s.iface != "" {
		sup := &SuricataSupervisor{
			BinaryPath: s.suricataBin,
			Interface:  s.iface,
			EveOutPath: s.evePath,
			PIDFile:    "/run/xhelix/suricata.pid",
		}
		s.supervisor = sup
		if err := sup.Start(ctx); err != nil {
			s.reason = fmt.Sprintf("suricata start: %v", err)
			s.healthy.Store(false)
		} else {
			s.healthy.Store(true)
			s.reason = "suricata running"
		}
		// Give Suricata a moment to create the EVE file
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}

	// Start tailing EVE JSON
	if s.evePath != "" {
		s.tailer = NewEveTailer(s.evePath)
		go func() {
			err := s.tailer.Run(ctx, out)
			if err != nil && ctx.Err() == nil {
				s.mu.Lock()
				s.reason = fmt.Sprintf("eve tailer: %v", err)
				s.healthy.Store(false)
				s.mu.Unlock()
			}
		}()
	}

	if s.supervisor == nil && s.tailer == nil {
		s.reason = "no sources configured"
		s.healthy.Store(false)
	}

	return nil
}

// Stop halts Suricata and the tailer.
func (s *Sensor) Stop(ctx context.Context) error {
	if !s.running.CompareAndSwap(true, false) {
		return nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	if s.supervisor != nil {
		_ = s.supervisor.Stop(ctx)
	}
	return nil
}

// Health implements sensors.Sensor.
func (s *Sensor) Health() sensors.Health {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sensors.Health{
		Healthy:   s.healthy.Load(),
		Reason:    s.reason,
		DropCount: s.tailer.Dropped(),
	}
}
