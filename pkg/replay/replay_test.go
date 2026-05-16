package replay

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestReplayMemorySource(t *testing.T) {
	events := []model.Event{
		model.NewEvent("a", model.SeverityInfo),
		model.NewEvent("b", model.SeverityNotice),
		model.NewEvent("c", model.SeverityWarn),
	}
	src := NewMemorySource(events)
	sink := &CountingSink{}

	var processed atomic.Uint64
	processFn := func(_ context.Context, _ model.Event) { processed.Add(1) }

	if err := Replay(context.Background(), src, sink, processFn); err != nil {
		t.Fatal(err)
	}
	if sink.Events != 3 {
		t.Errorf("sink.Events = %d, want 3", sink.Events)
	}
	if processed.Load() != 3 {
		t.Errorf("processed = %d, want 3", processed.Load())
	}
}

func TestReplayFileSource(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "01.jsonl")
	f2 := filepath.Join(dir, "02.jsonl")

	enc1, _ := os.Create(f1)
	for i := 0; i < 3; i++ {
		_ = json.NewEncoder(enc1).Encode(model.NewEvent("a", model.SeverityInfo))
	}
	enc1.Close()
	enc2, _ := os.Create(f2)
	for i := 0; i < 2; i++ {
		_ = json.NewEncoder(enc2).Encode(model.NewEvent("b", model.SeverityWarn))
	}
	enc2.Close()

	src, err := OpenDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	sink := &CountingSink{}
	if err := Replay(context.Background(), src, sink, nil); err != nil {
		t.Fatal(err)
	}
	if sink.Events != 5 {
		t.Errorf("events = %d, want 5", sink.Events)
	}
}
