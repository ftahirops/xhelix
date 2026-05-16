package hub

import (
	"context"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/model"
)

func TestHubMultiHostCorrelation(t *testing.T) {
	var fires atomic.Uint64
	hub, err := NewServer("", func(model.Alert) { fires.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	rule := correlator.Rule{
		ID:          "fleet_lateral_move",
		Desc:        "ssh login on host-a then exec on host-b within 60s",
		SeverityRaw: "critical",
		Window:      time.Minute,
		GroupBy:     []string{"src_ip"},
		Steps: []correlator.Step{
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "success"`,
				Within: time.Minute},
			{Select: `event.sensor == "ebpf.proc" && event.tags["src_ip"] == group.src_ip`,
				Within: time.Minute},
		},
	}
	if err := hub.LoadCorrelations([]correlator.Rule{rule}); err != nil {
		t.Fatal(err)
	}

	// Spin up the hub on a random port.
	srv := httptest.NewServer(hub.srv.Handler)
	defer srv.Close()

	clientA := NewClient(srv.URL, "host-a")
	clientB := NewClient(srv.URL, "host-b")

	// host-a logs a successful ssh.
	ev1 := model.NewEvent("identity.sshd", model.SeverityInfo)
	ev1.Tags["outcome"] = "success"
	ev1.Tags["src_ip"] = "198.51.100.5"
	ev1.Time = time.Now()
	clientA.Push(ev1)
	if err := clientA.Flush(); err != nil {
		t.Fatal(err)
	}

	// host-b sees an exec from same src_ip a moment later.
	ev2 := model.NewEvent("ebpf.proc", model.SeverityInfo)
	ev2.Tags["src_ip"] = "198.51.100.5"
	ev2.Time = ev1.Time.Add(2 * time.Second)
	clientB.Push(ev2)
	if err := clientB.Flush(); err != nil {
		t.Fatal(err)
	}

	// Allow the correlator a moment to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fires.Load() >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if fires.Load() < 1 {
		t.Errorf("multi-host correlation did not fire; fires=%d", fires.Load())
	}

	stopCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = hub.Stop(stopCtx)
}
