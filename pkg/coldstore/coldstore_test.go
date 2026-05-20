package coldstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/xhelix/xhelix/pkg/model"
)

func tmpStore(t *testing.T, opts Options) *Store {
	t.Helper()
	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), "cold.db")
	}
	if opts.FlushInterval == 0 {
		opts.FlushInterval = 50 * time.Millisecond
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makeEvent(t time.Time, sensor string, sev model.Severity) *model.Event {
	return &model.Event{
		ID:       ulid.MustNew(ulid.Timestamp(t), nil),
		Time:     t,
		Sensor:   sensor,
		Severity: sev,
		PID:      1234,
		Comm:     "tester",
		Tags:     map[string]string{"hello": "world"},
	}
}

func TestStore_SubmitFlushQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := tmpStore(t, Options{BatchSize: 10})
	s.Start(ctx)

	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 5; i++ {
		s.Submit(makeEvent(now.Add(time.Duration(i)*time.Millisecond), "test.sensor", model.SeverityNotice))
	}

	// Wait for flush.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().Written >= 5 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.Stats().Written < 5 {
		t.Fatalf("expected 5 written, got %d", s.Stats().Written)
	}

	got, err := s.Query(EventFilter{
		SinceUnixNS: now.Add(-time.Second).UnixNano(),
		UntilUnixNS: now.Add(time.Second).UnixNano(),
		Severity:    -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("query returned %d, want 5", len(got))
	}
	for _, e := range got {
		if e.Sensor != "test.sensor" {
			t.Errorf("unexpected sensor: %s", e.Sensor)
		}
		if e.Tags["hello"] != "world" {
			t.Errorf("tags not round-tripped: %v", e.Tags)
		}
	}
}

func TestStore_DropOldestOnOverflow(t *testing.T) {
	s := tmpStore(t, Options{QueueSize: 3, BatchSize: 100})
	// Don't Start — we want to inspect the queue without it draining.

	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		s.Submit(makeEvent(now.Add(time.Duration(i)*time.Millisecond), "t", model.SeverityNotice))
	}
	st := s.Stats()
	if st.QueueSize != 3 {
		t.Errorf("QueueSize = %d, want 3 (bounded)", st.QueueSize)
	}
	if st.Submitted != 10 {
		t.Errorf("Submitted = %d, want 10", st.Submitted)
	}
	if st.Dropped != 7 {
		t.Errorf("Dropped = %d, want 7", st.Dropped)
	}
}

func TestStore_QueryFiltersBySensorAndSeverity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := tmpStore(t, Options{BatchSize: 20})
	s.Start(ctx)

	now := time.Now().UTC()
	s.Submit(makeEvent(now, "fim", model.SeverityCritical))
	s.Submit(makeEvent(now.Add(time.Millisecond), "fim", model.SeverityNotice))
	s.Submit(makeEvent(now.Add(2*time.Millisecond), "exec", model.SeverityCritical))

	// Wait for flush.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().Written >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Filter to fim sensor only.
	got, err := s.Query(EventFilter{
		SinceUnixNS: now.Add(-time.Second).UnixNano(),
		UntilUnixNS: now.Add(time.Second).UnixNano(),
		Sensor:      "fim",
		Severity:    -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("fim filter returned %d, want 2", len(got))
	}

	// Filter to critical only.
	got, err = s.Query(EventFilter{
		SinceUnixNS: now.Add(-time.Second).UnixNano(),
		UntilUnixNS: now.Add(time.Second).UnixNano(),
		Severity:    int(model.SeverityCritical),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("critical filter returned %d, want 2", len(got))
	}
}

func TestStore_DayRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := tmpStore(t, Options{BatchSize: 5})
	s.Start(ctx)

	// Submit events on two distinct UTC days.
	day1 := time.Date(2026, 5, 19, 23, 50, 0, 0, time.UTC)
	day2 := time.Date(2026, 5, 20, 0, 10, 0, 0, time.UTC)
	s.Submit(makeEvent(day1, "x", model.SeverityNotice))
	s.Submit(makeEvent(day2, "x", model.SeverityNotice))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().Written >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.Stats().Written != 2 {
		t.Fatalf("written = %d, want 2", s.Stats().Written)
	}
	if s.Stats().DayRotations == 0 {
		t.Errorf("expected at least one day rotation")
	}

	// Both events queryable when range covers both days.
	got, err := s.Query(EventFilter{
		SinceUnixNS: day1.Add(-time.Hour).UnixNano(),
		UntilUnixNS: day2.Add(time.Hour).UnixNano(),
		Severity:    -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("cross-day query returned %d, want 2", len(got))
	}
}

func TestStore_FlushOnClose(t *testing.T) {
	s := tmpStore(t, Options{BatchSize: 100})
	// Don't Start — we want Close to do the final flush.

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		s.Submit(makeEvent(now.Add(time.Duration(i)*time.Millisecond), "t", model.SeverityNotice))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Re-open and confirm rows were durably written.
	s2, err := New(Options{Path: s.path, BatchSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Query(EventFilter{
		SinceUnixNS: now.Add(-time.Second).UnixNano(),
		UntilUnixNS: now.Add(time.Second).UnixNano(),
		Severity:    -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("after reopen got %d rows, want 5", len(got))
	}
}

func TestStore_Submit_AfterClose_IsNoOp(t *testing.T) {
	s := tmpStore(t, Options{})
	_ = s.Close()
	s.Submit(makeEvent(time.Now().UTC(), "x", model.SeverityNotice))
	// No panic, no counter bump.
	if s.Stats().Submitted != 0 {
		t.Errorf("post-close submit should be a no-op; submitted=%d", s.Stats().Submitted)
	}
}

func BenchmarkSubmit(b *testing.B) {
	s, err := New(Options{Path: filepath.Join(b.TempDir(), "bench.db")})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })

	e := makeEvent(time.Now().UTC(), "bench", model.SeverityNotice)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Submit(e)
	}
}

func BenchmarkFlush_1000Batch(b *testing.B) {
	s, err := New(Options{
		Path:      filepath.Join(b.TempDir(), "bench.db"),
		QueueSize: 1_000_000,
		BatchSize: 1000,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })

	now := time.Now().UTC()
	events := make([]*model.Event, 1000)
	for i := range events {
		events[i] = makeEvent(now.Add(time.Duration(i)*time.Microsecond), "bench", model.SeverityNotice)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, e := range events {
			s.Submit(e)
		}
		_ = s.flushOnce()
	}
}
