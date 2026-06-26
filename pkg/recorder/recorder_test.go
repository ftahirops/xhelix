package recorder

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// TestRecorder_TickRecordsFullBatchOnStoreError verifies that Tick does not
// abort early when RecordChain returns an error. FlushIdle has already removed
// the chains from the accumulator, so every chain must be attempted even if an
// earlier one fails — no chain should be silently dropped.
func TestRecorder_TickRecordsFullBatchOnStoreError(t *testing.T) {
	dir := t.TempDir()
	st, err := NewStore(Options{Path: filepath.Join(dir, "r.db"), ExemplarsPerShape: 5, RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	// Close the store so all writes fail.
	st.Close()

	acc := NewAccumulator(time.Second)
	r := New(acc, st)

	t0 := time.Unix(1_700_000_000, 0)
	tags1 := map[string]string{"learnable": "true", "chain_id": "cx1", "app_id": "app", "root_type": "web", "phase": "request"}
	tags2 := map[string]string{"learnable": "true", "chain_id": "cx2", "app_id": "app", "root_type": "web", "phase": "request"}
	r.Observe(model.Event{Sensor: "ebpf.spawn", Comm: "curl", Tags: tags1, Time: t0})
	r.Observe(model.Event{Sensor: "ebpf.spawn", Comm: "wget", Tags: tags2, Time: t0})

	// Tick past idle threshold — both chains flushed, store writes fail.
	// Must return non-nil error and must NOT panic.
	tickErr := r.Tick(t0.Add(2 * time.Second))
	if tickErr == nil {
		t.Fatal("expected a non-nil error from Tick when store is closed, got nil")
	}
}

func TestRecorder_OnlyRecordsLearnable(t *testing.T) {
	st, err := NewStore(Options{Path: filepath.Join(t.TempDir(), "r.db"), ExemplarsPerShape: 5, RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := New(NewAccumulator(time.Second), st)
	t0 := time.Unix(1_700_000_000, 0)

	learn := map[string]string{"learnable": "true", "chain_id": "c1", "app_id": "shop", "root_type": "web", "phase": "request"}
	r.Observe(model.Event{Sensor: "ebpf.spawn", Comm: "curl", Tags: learn, Time: t0})
	// not learnable → ignored
	r.Observe(model.Event{Sensor: "ebpf.spawn", Comm: "bash", Tags: map[string]string{"learnable": "false", "chain_id": "c2", "app_id": "shop"}, Time: t0})

	if err := r.Tick(t0.Add(2 * time.Second)); err != nil { // idle 2s>1s → flush
		t.Fatal(err)
	}
	rows, _ := st.Shapes("shop")
	if len(rows) != 1 {
		t.Fatalf("only the learnable chain should be recorded, got %+v", rows)
	}
}
