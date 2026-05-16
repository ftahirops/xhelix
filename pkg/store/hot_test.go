package store

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestHotStoreInsertAndPrune(t *testing.T) {
	h, err := OpenHot(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	ctx := context.Background()

	// Insert two events
	e1 := model.NewEvent("test", model.SeverityInfo)
	e1.PID = 100
	e1.Time = time.Now().Add(-2 * time.Hour)
	e2 := model.NewEvent("test", model.SeverityWarn)
	e2.PID = 200
	e2.Time = time.Now()

	for _, e := range []model.Event{e1, e2} {
		if err := h.Insert(ctx, e); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	n, err := h.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("count = %d, want 2", n)
	}

	cutoff := time.Now().Add(-time.Hour).UnixNano()
	deleted, err := h.Prune(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Errorf("prune deleted %d, want 1", deleted)
	}
}
