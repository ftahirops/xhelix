package baseline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func mkEvent(sensor, comm, image string, t time.Time, tags map[string]string) model.Event {
	e := model.NewEvent(sensor, model.SeverityInfo)
	e.Comm = comm
	e.Image = image
	e.Time = t
	if tags != nil {
		for k, v := range tags {
			e.Tags[k] = v
		}
	}
	return e
}

func TestAggregatorBasicProjection(t *testing.T) {
	a := NewAggregator(Config{KeepHours: 4})
	t0 := time.Date(2026, 5, 4, 14, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		a.Observe(mkEvent("ebpf.spawn", "nginx", "/usr/sbin/nginx", t0,
			map[string]string{"dst_ip": "10.0.1.5", "dst_port": "443"}))
	}
	a.Observe(mkEvent("fim.drift", "nginx", "/usr/sbin/nginx", t0,
		map[string]string{"path": "/var/log/nginx/access.log"}))

	ws := a.FlushAll()
	if len(ws) != 1 {
		t.Fatalf("expected 1 window, got %d", len(ws))
	}
	w := ws[0]
	if w.Binary != "/usr/sbin/nginx" {
		t.Errorf("binary = %q", w.Binary)
	}
	if w.Events != 6 {
		t.Errorf("events = %d, want 6", w.Events)
	}
	if w.Syscalls["ebpf.spawn"] != 5 {
		t.Errorf("ebpf.spawn count = %d", w.Syscalls["ebpf.spawn"])
	}
	if w.Syscalls["fim.drift"] != 1 {
		t.Errorf("fim.drift count = %d", w.Syscalls["fim.drift"])
	}
	want := "10.0.0.0/16:443"
	if w.Endpoints[want] != 5 {
		t.Errorf("endpoint %s count = %d", want, w.Endpoints[want])
	}
	if _, ok := w.FileWrites["/var/log/nginx/access.log"]; !ok {
		t.Errorf("file write not captured: %v", w.FileWrites)
	}
}

func TestAggregatorChildAttribution(t *testing.T) {
	a := NewAggregator(Config{KeepHours: 4})
	t0 := time.Date(2026, 5, 4, 14, 0, 0, 0, time.UTC)
	// nginx spawns bash (anomalous in real world, but valid input)
	a.Observe(mkEvent("ebpf.spawn", "bash", "/bin/bash", t0,
		map[string]string{"parent_comm": "nginx"}))
	ws := a.FlushAll()
	// One window for /bin/bash + one window attributed to nginx for the child
	var saw bool
	for _, w := range ws {
		if w.Binary == "nginx" && w.Children["bash"] == 1 {
			saw = true
		}
	}
	if !saw {
		for _, w := range ws {
			t.Logf("window %+v", w)
		}
		t.Fatal("expected child attribution to nginx")
	}
}

func TestAggregatorIgnoreList(t *testing.T) {
	a := NewAggregator(Config{
		KeepHours:      4,
		IgnoreBinaries: map[string]bool{"/usr/local/bin/xhelix": true},
	})
	t0 := time.Now().UTC().Truncate(time.Hour)
	a.Observe(mkEvent("ebpf.spawn", "xhelix", "/usr/local/bin/xhelix", t0, nil))
	ws := a.FlushAll()
	if len(ws) != 0 {
		t.Errorf("ignored binary should not produce window: %d", len(ws))
	}
}

func TestAggregatorFlushOnHourBoundary(t *testing.T) {
	a := NewAggregator(Config{KeepHours: 1})
	now := time.Date(2026, 5, 4, 14, 30, 0, 0, time.UTC)
	a.Observe(mkEvent("ebpf.spawn", "nginx", "/usr/sbin/nginx", now, nil))
	// jump 3 hours forward — older window must be moved to flush queue
	later := now.Add(3 * time.Hour)
	a.Observe(mkEvent("ebpf.spawn", "nginx", "/usr/sbin/nginx", later, nil))
	ready := a.FlushReady(later)
	if len(ready) == 0 {
		t.Fatal("expected the 14:00 window to be flush-ready after 3h passed")
	}
}

func TestTopNTruncation(t *testing.T) {
	a := NewAggregator(Config{KeepHours: 1, MaxKeysPerWindow: 3})
	t0 := time.Date(2026, 5, 4, 14, 0, 0, 0, time.UTC)
	// 10 distinct destinations with varying counts
	for i := 0; i < 10; i++ {
		for j := 0; j < i+1; j++ {
			a.Observe(mkEvent("ebpf.net", "nginx", "/usr/sbin/nginx", t0, map[string]string{
				"dst_ip":   strings.Replace("10.0.0.0", "0.0", string(rune('0'+i))+".0", 1),
				"dst_port": "443",
			}))
		}
	}
	ws := a.FlushAll()
	if len(ws) == 0 {
		t.Fatal("no windows")
	}
	if got := len(ws[0].Endpoints); got > 3 {
		t.Errorf("topN truncation failed: %d endpoints kept", got)
	}
}

// TestAggregatorFallsBackToSensor verifies the projection rule that
// makes the aggregator useful against the current sensor zoo: when an
// event has no Comm and no Image (true for fim, posture, netids and
// many other sensors today), the sensor name itself becomes the
// "binary" identity. Without this, the aggregator silently drops 99%
// of events.
func TestAggregatorFallsBackToSensor(t *testing.T) {
	a := NewAggregator(Config{KeepHours: 4})
	t0 := time.Date(2026, 5, 5, 14, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ev := mkEvent("fim.drift", "", "", t0, map[string]string{
			"path": "/etc/passwd", "reason": "sha-mismatch",
		})
		a.Observe(ev)
	}
	ws := a.FlushAll()
	if len(ws) != 1 {
		t.Fatalf("expected 1 window keyed on sensor, got %d", len(ws))
	}
	if ws[0].Binary != "fim.drift" {
		t.Errorf("binary = %q, want fim.drift", ws[0].Binary)
	}
	if ws[0].FileWrites["/etc/passwd"] != 5 {
		t.Errorf("file_writes /etc/passwd = %d, want 5", ws[0].FileWrites["/etc/passwd"])
	}
}

func TestAggregatorIgnoreSensorByName(t *testing.T) {
	a := NewAggregator(Config{
		KeepHours:      1,
		IgnoreBinaries: map[string]bool{"heartbeat": true},
	})
	t0 := time.Now().UTC().Truncate(time.Hour)
	for i := 0; i < 100; i++ {
		ev := mkEvent("heartbeat", "", "", t0, nil)
		a.Observe(ev)
	}
	if got := len(a.FlushAll()); got != 0 {
		t.Errorf("heartbeat must be ignorable by sensor-name, got %d windows", got)
	}
}

func TestCidr16(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5":    "203.0.0.0/16",
		"10.1.2.3":       "10.1.0.0/16",
		"127.0.0.1":      "",
		"169.254.1.1":    "",
		"::1":            "",
		"not an ip":      "",
		"2001:db8::1":    "2001:db8::/48",
	}
	for in, want := range cases {
		if got := cidr16(in); got != want {
			t.Errorf("cidr16(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStoreWriteAndRotate(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)
	defer s.Stop()

	// Day 1 window
	w1 := newWindow("/usr/sbin/nginx", time.Date(2026, 5, 3, 14, 0, 0, 0, time.UTC))
	w1.Events = 7
	// Day 2 window — should trigger rotation
	w2 := newWindow("/usr/sbin/nginx", time.Date(2026, 5, 4, 9, 0, 0, 0, time.UTC))
	w2.Events = 3

	s.Push([]*Window{w1, w2})

	// Give the goroutine time to process
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st := s.Stats()
		if st.Written >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	st := s.Stats()
	if st.Written < 2 {
		t.Fatalf("expected ≥2 writes, got %+v", st)
	}

	// Stop, then verify files on disk.
	s.Stop()
	time.Sleep(100 * time.Millisecond)
	entries, _ := os.ReadDir(dir)
	if len(entries) < 1 {
		t.Fatalf("expected at least one baseline file in %s", dir)
	}
	// Check at least one record in any plain or gz file
	found := false
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		body, _ := os.ReadFile(path)
		var w Window
		for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
			if line == "" {
				continue
			}
			if err := json.Unmarshal([]byte(line), &w); err == nil {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no parseable record found in %s; entries=%v", dir, entries)
	}
}

func TestStorePushDropsWhenFull(t *testing.T) {
	s, err := NewStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Don't Start — channel won't be drained.
	w := newWindow("x", time.Now().UTC())
	for i := 0; i < 2000; i++ {
		s.Push([]*Window{w})
	}
	if s.Stats().Dropped == 0 {
		t.Errorf("expected drops on full queue, got 0")
	}
}
