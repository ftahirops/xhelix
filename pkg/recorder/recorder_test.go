package recorder

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

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
