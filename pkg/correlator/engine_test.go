package correlator

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestSequenceCorrelationFires(t *testing.T) {
	var fires atomic.Uint64
	eng, err := New(func(model.Alert) { fires.Add(1) })
	if err != nil {
		t.Fatal(err)
	}

	rule := Rule{
		ID:          "ssh_then_curl",
		Desc:        "ssh login then curl spawn within 60s",
		SeverityRaw: "high",
		Window:      time.Minute,
		GroupBy:     []string{"src_ip"},
		Steps: []Step{
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "success"`,
				Within: time.Minute},
			{Select: `event.sensor == "ebpf.proc" && event.comm == "curl"`,
				Within: time.Minute},
		},
	}
	if err := eng.Load([]Rule{rule}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	now := time.Now()

	// Step 0: ssh accepted
	ev1 := model.NewEvent("identity.sshd", model.SeverityInfo)
	ev1.Time = now
	ev1.Tags["outcome"] = "success"
	ev1.Tags["user"] = "alice"
	ev1.Tags["src_ip"] = "198.51.100.5"
	eng.Ingest(ctx, ev1)
	if fires.Load() != 0 {
		t.Fatal("fired prematurely")
	}

	// Step 1: curl runs
	ev2 := model.NewEvent("ebpf.proc", model.SeverityInfo)
	ev2.Time = now.Add(5 * time.Second)
	ev2.Comm = "curl"
	eng.Ingest(ctx, ev2)

	if fires.Load() != 1 {
		t.Errorf("expected 1 incident, got %d", fires.Load())
	}
}

func TestGroupKeyIsDeterministic(t *testing.T) {
	m := map[string]string{"b": "2", "a": "1", "c": "3"}
	got := groupKeyString(m)
	want := "a=1;b=2;c=3;"
	if got != want {
		t.Errorf("groupKeyString = %q, want %q", got, want)
	}
}

func TestCorrelationExpires(t *testing.T) {
	var fires atomic.Uint64
	eng, _ := New(func(model.Alert) { fires.Add(1) })

	rule := Rule{
		ID:          "expire",
		SeverityRaw: "warn",
		Window:      time.Minute,
		Steps: []Step{
			{Select: `event.sensor == "a"`, Within: time.Minute},
			{Select: `event.sensor == "b"`, Within: time.Minute},
		},
	}
	_ = eng.Load([]Rule{rule})

	ctx := context.Background()
	t0 := time.Now()

	a := model.NewEvent("a", model.SeverityInfo)
	a.Time = t0
	eng.Ingest(ctx, a)

	// Now elapsed time exceeds the window; an unrelated tick prunes.
	other := model.NewEvent("z", model.SeverityInfo)
	other.Time = t0.Add(2 * time.Minute)
	eng.Ingest(ctx, other)

	// Then the second step arrives — but the session already expired.
	b := model.NewEvent("b", model.SeverityInfo)
	b.Time = t0.Add(2 * time.Minute).Add(time.Second)
	eng.Ingest(ctx, b)

	if fires.Load() != 0 {
		t.Errorf("rule should not have fired after window; fires=%d", fires.Load())
	}
}
