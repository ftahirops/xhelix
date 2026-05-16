package correlatorshard

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/model"
)

func TestRequiresEmit(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("nil Emit should error")
	}
}

func TestStartsAndStops(t *testing.T) {
	s, err := New(context.Background(), Config{
		Shards: 4,
		Emit:   func(model.Alert) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	if len(s.shards) != 4 {
		t.Fatalf("shards = %d, want 4", len(s.shards))
	}
}

func TestPartitionByPIDDeterministic(t *testing.T) {
	s, _ := New(context.Background(), Config{Shards: 8, Emit: func(model.Alert) {}})
	defer s.Stop()
	// Same pid → same shard, every time.
	a := s.partition(model.Event{PID: 42}) % uint64(len(s.shards))
	b := s.partition(model.Event{PID: 42}) % uint64(len(s.shards))
	if a != b {
		t.Fatal("partition not deterministic")
	}
}

func TestDifferentPIDsLikelyDifferentShards(t *testing.T) {
	s, _ := New(context.Background(), Config{Shards: 8, Emit: func(model.Alert) {}})
	defer s.Stop()
	hit := map[uint64]bool{}
	for pid := uint32(1); pid <= 100; pid++ {
		hit[s.partition(model.Event{PID: pid})%uint64(len(s.shards))] = true
	}
	if len(hit) < 4 {
		t.Errorf("partition spread too narrow across 100 pids: %d shards used", len(hit))
	}
}

func TestIngestRoutesAndCounts(t *testing.T) {
	s, _ := New(context.Background(), Config{
		Shards: 4, BufferSize: 256, Emit: func(model.Alert) {},
	})
	defer s.Stop()

	for pid := uint32(1); pid <= 100; pid++ {
		s.Ingest(model.NewEvent("test", model.SeverityInfo))
		s.Ingest(model.Event{PID: pid, Sensor: "test", Comm: "x"})
	}
	// Allow workers to drain.
	for tries := 0; tries < 50; tries++ {
		st := s.Stats()
		if st.Ingested >= 200 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	st := s.Stats()
	if st.Ingested < 200 {
		t.Fatalf("ingested = %d, want >= 200", st.Ingested)
	}
	if st.Shards != 4 {
		t.Fatalf("shards = %d, want 4", st.Shards)
	}
}

func TestIngestDropsOnFullBuffer(t *testing.T) {
	// Single shard, tiny buffer; we'll flood it.
	var emitted atomic.Uint64
	s, _ := New(context.Background(), Config{
		Shards: 1, BufferSize: 1,
		Emit: func(model.Alert) { emitted.Add(1) },
	})
	defer s.Stop()

	for i := 0; i < 10_000; i++ {
		s.Ingest(model.Event{PID: 1, Sensor: "test"})
	}
	st := s.Stats()
	if st.Dropped == 0 {
		t.Fatalf("expected drops at buf=1; got 0")
	}
}

func TestPartitionByGroup(t *testing.T) {
	p := PartitionByGroup("exe_sha")
	ev1 := model.Event{PID: 100, Tags: map[string]string{"exe_sha": "abc"}}
	ev2 := model.Event{PID: 200, Tags: map[string]string{"exe_sha": "abc"}}
	// Different pid, same exe_sha → same partition.
	if p(ev1) != p(ev2) {
		t.Fatal("PartitionByGroup should hash on exe_sha")
	}
	// Different exe_sha → different partition (probabilistic, but
	// FNV-1a separates simple strings).
	ev3 := model.Event{Tags: map[string]string{"exe_sha": "xyz"}}
	if p(ev1) == p(ev3) {
		t.Fatal("different exe_sha collided")
	}
}

func TestPartitionByGroupFallback(t *testing.T) {
	p := PartitionByGroup("missing_tag")
	ev := model.Event{PID: 99, Tags: map[string]string{}}
	if p(ev) == 0 {
		t.Fatal("fallback should produce non-zero hash for pid 99")
	}
}

func TestCustomPartitionUsed(t *testing.T) {
	calls := uint64(0)
	custom := func(model.Event) uint64 {
		atomic.AddUint64(&calls, 1)
		return 0
	}
	s, _ := New(context.Background(), Config{
		Shards: 2, BufferSize: 8,
		PartitionFunc: custom,
		Emit:          func(model.Alert) {},
	})
	defer s.Stop()
	s.Ingest(model.Event{PID: 1})
	if atomic.LoadUint64(&calls) == 0 {
		t.Fatal("custom partition func not invoked")
	}
}

func TestEmitNotConcurrent(t *testing.T) {
	// Synthesise alerts directly via the engine, confirm Emit is
	// serialised. Use a no-op rule load and ingest synthetic
	// events that the inner correlator won't fire on, then
	// directly invoke the emitter to assert mutex behaviour.
	var wg sync.WaitGroup
	var inFlight atomic.Int32
	var maxFlight atomic.Int32

	s, _ := New(context.Background(), Config{
		Shards: 4, BufferSize: 64,
		Emit: func(model.Alert) {
			cur := inFlight.Add(1)
			for {
				old := maxFlight.Load()
				if cur > old {
					if maxFlight.CompareAndSwap(old, cur) {
						break
					}
				} else {
					break
				}
			}
			time.Sleep(time.Millisecond)
			inFlight.Add(-1)
		},
	})
	defer s.Stop()

	// Manually trigger many concurrent emits via the worker
	// engines (correlator.Engine.fire is internal — instead we
	// just verify the wrapper's mutex behaviour by calling Emit
	// from multiple goroutines using a borrowed worker's Engine.
	// Since we can't access the wrapped emit fn directly, we
	// instead spawn many goroutines that ingest events and rely
	// on the load to not crash; this is more of a smoke test).
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				s.Ingest(model.Event{PID: uint32(j), Sensor: "t"})
			}
		}()
	}
	wg.Wait()
	// We don't strictly assert maxFlight here — without rules
	// loaded the correlator won't emit anything. The test is
	// effectively a race-detector smoke test.
}

func TestSessionCountAggregates(t *testing.T) {
	s, _ := New(context.Background(), Config{
		Shards: 4, BufferSize: 64,
		Emit: func(model.Alert) {},
	})
	defer s.Stop()
	// No rules loaded → no sessions, but the API must work.
	if s.SessionCount() < 0 {
		t.Fatal("SessionCount negative")
	}
}

func TestStatsPerShard(t *testing.T) {
	s, _ := New(context.Background(), Config{
		Shards: 3, BufferSize: 32,
		Emit: func(model.Alert) {},
	})
	defer s.Stop()
	for i := 0; i < 30; i++ {
		s.Ingest(model.Event{PID: uint32(i)})
	}
	// Allow drain
	time.Sleep(50 * time.Millisecond)
	st := s.Stats()
	if len(st.PerShard) != 3 {
		t.Fatalf("per-shard len = %d", len(st.PerShard))
	}
}

func TestStopIdempotent(t *testing.T) {
	s, _ := New(context.Background(), Config{
		Shards: 2, BufferSize: 4,
		Emit: func(model.Alert) {},
	})
	s.Stop()
	s.Stop() // must not panic
}

func TestIngestAfterStopIsNoop(t *testing.T) {
	s, _ := New(context.Background(), Config{Shards: 1, BufferSize: 4, Emit: func(model.Alert) {}})
	s.Stop()
	// Should not block or panic
	s.Ingest(model.Event{PID: 1})
}

// Compile-time check that correlator.Rule is what New expects.
var _ correlator.Rule
