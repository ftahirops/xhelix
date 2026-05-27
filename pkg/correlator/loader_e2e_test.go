package correlator

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/xhelix/xhelix/pkg/model"
)

// TestLoadFromDir_E2E_DroppedBinary loads the shipped cortex-c2 rule
// and feeds simulated events through, confirming end-to-end that
// loader + engine + CEL compile + ingest path together fire.
func TestLoadFromDir_E2E_DroppedBinary(t *testing.T) {
	// Read the actual shipped rule file.
	src, err := os.ReadFile("../../ruleset/correlator/cortex_c2.yaml")
	if err != nil {
		t.Skipf("rule file not present: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.yaml"), src, 0644); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("no rules loaded")
	}
	var fires int32
	eng, err := New(func(model.Alert) { atomic.AddInt32(&fires, 1) })
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Load(rules); err != nil {
		t.Fatalf("Load: %v", err)
	}
	now := time.Now()
	// Step 0: outbound net_connect
	step0 := model.Event{
		ID:     ulid.Make(),
		Time:   now,
		Sensor: "ebpf.net",
		Tags: map[string]string{
			"kind":               "net_connect",
			"outbound":           "true",
			"cgroup_id":          "12345",
			"pkg_install_window": "false", // Phase K.2 suppression key (CEL needs present key)
		},
	}
	eng.Ingest(context.Background(), step0)
	// Step 1: proc_spawn from /tmp/ in same cgroup
	step1 := model.Event{
		ID:     ulid.Make(),
		Time:   now.Add(time.Second),
		Sensor: "ebpf.proc",
		Tags: map[string]string{
			"kind":               "proc_spawn",
			"path":               "/tmp/.dropped/payload",
			"cgroup_id":          "12345",
			"pkg_install_window": "false",
		},
	}
	eng.Ingest(context.Background(), step1)
	// Allow goroutine scheduling
	time.Sleep(100 * time.Millisecond)
	if atomic.LoadInt32(&fires) == 0 {
		t.Errorf("expected chain to fire, got 0; sessions=%d", eng.SessionCount())
	}
}
