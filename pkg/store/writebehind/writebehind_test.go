package writebehind

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recordingWriter collects batches for inspection.
type recordingWriter[T any] struct {
	mu      sync.Mutex
	batches [][]T
	err     error
	delay   time.Duration
}

func (w *recordingWriter[T]) WriteBatch(ctx context.Context, items []T) error {
	if w.delay > 0 {
		time.Sleep(w.delay)
	}
	if w.err != nil {
		return w.err
	}
	w.mu.Lock()
	cp := make([]T, len(items))
	copy(cp, items)
	w.batches = append(w.batches, cp)
	w.mu.Unlock()
	return nil
}

func (w *recordingWriter[T]) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, b := range w.batches {
		n += len(b)
	}
	return n
}

func (w *recordingWriter[T]) BatchCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.batches)
}

func TestRequiresWriter(t *testing.T) {
	_, err := NewRing[int](context.Background(), Config[int]{})
	if err == nil {
		t.Fatal("nil Writer should error")
	}
}

func TestSubmitsBatchedWithinInterval(t *testing.T) {
	w := &recordingWriter[int]{}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BatchInterval: 30 * time.Millisecond,
	})
	defer r.Stop()
	for i := 0; i < 10; i++ {
		r.Submit(context.Background(), i)
	}
	time.Sleep(100 * time.Millisecond)
	if w.Count() != 10 {
		t.Fatalf("written = %d, want 10", w.Count())
	}
}

func TestMaxBatchFlushesEarly(t *testing.T) {
	w := &recordingWriter[int]{}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, MaxBatch: 5, BatchInterval: time.Hour,
	})
	defer r.Stop()
	for i := 0; i < 12; i++ {
		r.Submit(context.Background(), i)
	}
	// Allow drain
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && w.Count() < 10 {
		time.Sleep(5 * time.Millisecond)
	}
	if w.Count() < 10 {
		t.Fatalf("written = %d, want ≥10", w.Count())
	}
	// Batches should be of size 5.
	w.mu.Lock()
	for _, b := range w.batches {
		if len(b) > 5 {
			t.Errorf("batch size = %d, expected ≤5", len(b))
		}
	}
	w.mu.Unlock()
}

func TestDropNewestOnFull(t *testing.T) {
	w := &recordingWriter[int]{delay: 100 * time.Millisecond}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BufferSize: 2, MaxBatch: 1,
		BatchInterval: 10 * time.Millisecond,
		DropPolicy:    DropNewest,
	})
	defer r.Stop()

	dropped := 0
	for i := 0; i < 100; i++ {
		ok, _ := r.Submit(context.Background(), i)
		if !ok {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("DropNewest at tiny buffer should drop something")
	}
}

func TestDropOldestEvicts(t *testing.T) {
	w := &recordingWriter[int]{delay: 50 * time.Millisecond}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BufferSize: 4, MaxBatch: 8,
		BatchInterval: 5 * time.Millisecond,
		DropPolicy:    DropOldest,
	})
	defer r.Stop()

	for i := 0; i < 100; i++ {
		ok, _ := r.Submit(context.Background(), i)
		if !ok {
			t.Fatalf("DropOldest should never report failure; got false at i=%d", i)
		}
	}
	// All submits accepted; some dropped silently from head.
	st := r.Stats()
	if st.Dropped == 0 {
		t.Errorf("expected some dropped via DropOldest; counters=%+v", st)
	}
}

func TestBlockWaitsForSpace(t *testing.T) {
	w := &recordingWriter[int]{delay: 20 * time.Millisecond}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BufferSize: 2, MaxBatch: 4,
		BatchInterval: 5 * time.Millisecond,
		DropPolicy:    Block,
	})
	defer r.Stop()

	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			accepted, _ := r.Submit(ctx, i)
			if accepted {
				ok.Add(1)
			}
		}(i)
	}
	wg.Wait()
	// Under Block, with ample timeout, virtually every submit
	// should land — but we can't guarantee no race conditions on
	// the timeout, so just check the bulk made it through.
	if ok.Load() < 40 {
		t.Fatalf("Block accepted = %d, want ≥ 40", ok.Load())
	}
}

func TestBlockRespectsContext(t *testing.T) {
	// Slow writer holds the drain goroutine in WriteBatch for the
	// short test window, keeping the buffer full and forcing
	// Submit to block. Delay is bounded so the deferred Stop()
	// can return.
	w := &recordingWriter[int]{delay: 500 * time.Millisecond}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BufferSize: 1, MaxBatch: 1,
		BatchInterval: 100 * time.Millisecond,
		DropPolicy:    Block,
	})
	defer r.Stop()

	r.Submit(context.Background(), 1) // fills buffer
	// Allow the drain to pick up item 1 and start its slow write.
	time.Sleep(10 * time.Millisecond)
	r.Submit(context.Background(), 2) // fills again

	// Next submit should block; cancel via ctx before the slow
	// writer finishes.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	ok, err := r.Submit(ctx, 3)
	if ok {
		t.Fatal("submit should not have succeeded")
	}
	if err == nil {
		t.Fatal("submit should report ctx error")
	}
}

func TestErrorCallbackInvoked(t *testing.T) {
	calls := atomic.Int64{}
	w := &recordingWriter[int]{err: errors.New("boom")}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BatchInterval: 10 * time.Millisecond,
		OnError: func(err error, n int) { calls.Add(1) },
	})
	defer r.Stop()
	r.Submit(context.Background(), 1)
	time.Sleep(50 * time.Millisecond)
	if calls.Load() == 0 {
		t.Fatal("OnError not invoked on writer failure")
	}
}

func TestStopFlushesPending(t *testing.T) {
	w := &recordingWriter[int]{}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BatchInterval: time.Hour, // never auto-flush
	})
	r.Submit(context.Background(), 1)
	r.Submit(context.Background(), 2)
	r.Submit(context.Background(), 3)
	r.Stop()
	if w.Count() != 3 {
		t.Fatalf("Stop did not flush pending; written = %d", w.Count())
	}
}

func TestSubmitAfterStopFails(t *testing.T) {
	w := &recordingWriter[int]{}
	r, _ := NewRing[int](context.Background(), Config[int]{Writer: w})
	r.Stop()
	ok, err := r.Submit(context.Background(), 1)
	if ok || err == nil {
		t.Fatalf("post-stop submit should fail; got ok=%v err=%v", ok, err)
	}
}

func TestStatsReportsCounters(t *testing.T) {
	w := &recordingWriter[int]{}
	r, _ := NewRing[int](context.Background(), Config[int]{
		Writer: w, BatchInterval: 5 * time.Millisecond,
	})
	defer r.Stop()
	for i := 0; i < 5; i++ {
		r.Submit(context.Background(), i)
	}
	time.Sleep(50 * time.Millisecond)
	st := r.Stats()
	if st.Inserted < 5 {
		t.Errorf("inserted = %d", st.Inserted)
	}
	if st.Written < 5 {
		t.Errorf("written = %d", st.Written)
	}
	if st.Batches < 1 {
		t.Errorf("batches = %d", st.Batches)
	}
}
