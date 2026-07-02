package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/xhelix/xhelix/pkg/model"
)

// TestHotStoreSchemaVersionStamped verifies OpenHot stamps PRAGMA user_version
// to the current schema version, and that reopening is idempotent.
func TestHotStoreSchemaVersionStamped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.db")
	h, err := OpenHot(path)
	if err != nil {
		t.Fatal(err)
	}
	var v int
	if err := h.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != len(schemaMigrations) {
		t.Errorf("user_version = %d, want %d (current schema)", v, len(schemaMigrations))
	}
	_ = h.Close()

	// Reopen: migrations already applied, must be a clean no-op.
	h2, err := OpenHot(path)
	if err != nil {
		t.Fatalf("reopen after migration failed: %v", err)
	}
	defer h2.Close()
	if err := h2.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != len(schemaMigrations) {
		t.Errorf("user_version after reopen = %d, want %d", v, len(schemaMigrations))
	}
}

// TestHotStoreAsyncWriterPersists verifies that events Submitted via the async
// write-behind path are eventually persisted and that Close drains the queue.
func TestHotStoreAsyncWriterPersists(t *testing.T) {
	h, err := OpenHot(filepath.Join(t.TempDir(), "async.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.StartWriter(ctx, 0)

	const n = 2000
	for i := 0; i < n; i++ {
		e := model.NewEvent("test", model.SeverityInfo)
		e.PID = uint32(i)
		e.Time = time.Now()
		h.Submit(e)
	}

	// Close drains the queue synchronously before closing the DB.
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopen and count — everything submitted (within the queue cap) must be
	// durable after a clean drain.
	h2, err := OpenHot(h.path)
	if err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	got, err := h2.Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got != n {
		t.Errorf("persisted %d events, want %d", got, n)
	}
}

// TestHotStoreSubmitSnapshotsTags verifies Submit copies the Tags map so the
// caller mutating it after Submit cannot race the writer's json.Marshal
// (the concurrent-map crash observed live on vps-4). Run with -race.
func TestHotStoreSubmitSnapshotsTags(t *testing.T) {
	h, err := OpenHot(filepath.Join(t.TempDir(), "tags.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.StartWriter(ctx, 0)

	e := model.NewEvent("test", model.SeverityInfo)
	e.Tags["k"] = "original"
	h.Submit(e)
	// Caller keeps mutating the same map after Submit — must not affect the
	// snapshot the writer persists, and must not race under -race.
	for i := 0; i < 1000; i++ {
		e.Tags["k"] = "mutated"
		e.Tags[string(rune('a'+i%26))] = "x"
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestHotStoreAsyncWriterDropsOldestWhenFull verifies the drop-oldest overflow
// policy bounds the queue without blocking Submit. White-box: we mark the
// writer "on" but never launch the drain goroutine, so the queue stays full
// and every Submit past the cap drops the oldest entry.
func TestHotStoreAsyncWriterDropsOldestWhenFull(t *testing.T) {
	h, err := OpenHot(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer h.db.Close()

	const cap = 4
	h.writeCap = cap
	h.wake = make(chan struct{}, 1)
	h.writerOn.Store(true) // no runWriter goroutine → queue never drains

	const total = 10
	for i := 0; i < total; i++ {
		e := model.NewEvent("test", model.SeverityInfo)
		e.PID = uint32(i)
		h.Submit(e)
	}

	if len(h.writeQ) != cap {
		t.Errorf("queue len = %d, want cap %d", len(h.writeQ), cap)
	}
	if _, _, dropped := h.WriteStats(); dropped != total-cap {
		t.Errorf("dropped = %d, want %d", dropped, total-cap)
	}
	// The retained entries must be the NEWEST (drop-oldest): PIDs 6,7,8,9.
	for i, e := range h.writeQ {
		want := uint32(total - cap + i)
		if e.PID != want {
			t.Errorf("queue[%d].PID = %d, want %d (oldest should have been dropped)", i, e.PID, want)
		}
	}
	h.writerOn.Store(false)
}

// TestOpenHotConvertsLegacyAutoVacuum verifies that a database created before
// the auto_vacuum(incremental) DSN pragma is converted to INCREMENTAL (mode 2)
// on open, so PruneBySize's incremental_vacuum can reclaim disk in place.
func TestOpenHotConvertsLegacyAutoVacuum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Create a legacy file with the default auto_vacuum=NONE (mode 0).
	legacy, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE t (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	var mode int
	if err := legacy.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 0 {
		t.Skipf("expected legacy auto_vacuum=NONE, got mode %d", mode)
	}
	_ = legacy.Close()

	h, err := OpenHot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if err := h.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != 2 {
		t.Errorf("auto_vacuum after OpenHot = %d, want 2 (INCREMENTAL)", mode)
	}
}

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
