package heartbeat

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestHeartbeatEmits(t *testing.T) {
	s := New(20*time.Millisecond, "test-host")
	out := make(chan model.Event, 10)

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx, out); err != nil {
		t.Fatal(err)
	}

	// Collect a few events.
	deadline := time.After(200 * time.Millisecond)
	got := 0
loop:
	for {
		select {
		case ev := <-out:
			if ev.Sensor != "heartbeat" {
				t.Errorf("sensor = %q", ev.Sensor)
			}
			if ev.Host != "test-host" {
				t.Errorf("host = %q", ev.Host)
			}
			got++
			if got >= 3 {
				break loop
			}
		case <-deadline:
			t.Fatalf("only got %d events; expected at least 3", got)
		}
	}

	cancel()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := s.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if !s.Health().Healthy {
		// after Stop, running flips to false; this is fine.
	}
	if s.Emitted() < 3 {
		t.Errorf("emitted = %d, want >= 3", s.Emitted())
	}
}
