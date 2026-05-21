package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/model"
)

// soakSink is a model.Sink that updates the enforce.Soak tracker on
// every alert. Without this, the Soak primitive that's existed in
// the codebase for months was a no-op — Track() was never being
// called, so every rule's ConsecutiveCleanDays counter stayed at 0
// forever.
//
// Subscribes via the alert bus alongside file/stdout/webhook sinks
// so the daemon's existing fan-out delivers to it for free.
type soakSink struct {
	soak *enforce.Soak
	// Background flusher writes Snapshot to disk so the counter
	// survives daemon restart. saveInterval defaults to 1 minute;
	// missing flushes lose at most one minute of tick data, which
	// is acceptable for a counter that operates on days.
	savePath string
	saveErrs atomic.Uint64
}

func newSoakSink(s *enforce.Soak, savePath string) *soakSink {
	return &soakSink{soak: s, savePath: savePath}
}

func (s *soakSink) Name() string { return "soak" }

func (s *soakSink) Send(_ context.Context, a model.Alert) error {
	if s.soak == nil || a.RuleID == "" {
		return nil
	}
	s.soak.Track(a.RuleID, time.Now().UTC())
	return nil
}

func (s *soakSink) Close() error {
	if s.soak == nil || s.savePath == "" {
		return nil
	}
	return s.soak.SaveTo(s.savePath)
}

// runFlusher writes the soak file every interval until ctx is done.
// Called as a goroutine from run.go after the bus is wired.
func (s *soakSink) runFlusher(ctx context.Context, interval time.Duration) {
	if s.soak == nil || s.savePath == "" {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.soak.SaveTo(s.savePath)
			return
		case <-t.C:
			if err := s.soak.SaveTo(s.savePath); err != nil {
				s.saveErrs.Add(1)
			}
		}
	}
}
