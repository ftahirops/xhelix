package recorder

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func evChain(sensor, comm, chainID, app string, tags map[string]string, ts time.Time) model.Event {
	m := map[string]string{"chain_id": chainID, "app_id": app, "root_type": "web", "phase": "request"}
	for k, v := range tags {
		m[k] = v
	}
	return model.Event{Sensor: sensor, Comm: comm, Tags: m, Time: ts}
}

func TestAccumulator_GroupsAndDedupsByChain(t *testing.T) {
	a := NewAccumulator(30 * time.Second)
	t0 := time.Unix(1_700_000_000, 0)
	a.Observe(evChain("ebpf.spawn", "curl", "c1", "shop", nil, t0))
	a.Observe(evChain("net_connect", "", "c1", "shop", map[string]string{"sni": "api.stripe.com", "dst_port": "443"}, t0.Add(time.Second)))
	a.Observe(evChain("ebpf.spawn", "curl", "c1", "shop", nil, t0.Add(2*time.Second))) // dup exec edge

	got := a.FlushAll()
	if len(got) != 1 {
		t.Fatalf("want 1 chain, got %d", len(got))
	}
	if got[0].AppID != "shop" || got[0].ChainID != "c1" {
		t.Errorf("chain identity wrong: %+v", got[0])
	}
	if len(got[0].Edges) != 2 {
		t.Errorf("want 2 deduped edges (exec curl + egress), got %d: %+v", len(got[0].Edges), got[0].Edges)
	}
	// Fix 2: assert timing fields are preserved correctly.
	if !got[0].FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen: want %v, got %v", t0, got[0].FirstSeen)
	}
	wantLast := t0.Add(2 * time.Second)
	if !got[0].LastSeen.Equal(wantLast) {
		t.Errorf("LastSeen: want %v, got %v", wantLast, got[0].LastSeen)
	}
}

func TestAccumulator_FlushIdleOnlyExpired(t *testing.T) {
	a := NewAccumulator(30 * time.Second)
	t0 := time.Unix(1_700_000_000, 0)
	a.Observe(evChain("ebpf.spawn", "curl", "old", "shop", nil, t0))
	a.Observe(evChain("ebpf.spawn", "wget", "fresh", "shop", nil, t0.Add(40*time.Second)))

	flushed := a.FlushIdle(t0.Add(45 * time.Second)) // "old" idle 45s>30s; "fresh" idle 5s
	if len(flushed) != 1 || flushed[0].ChainID != "old" {
		t.Fatalf("want only 'old' flushed, got %+v", flushed)
	}
	// "fresh" still resident.
	if rest := a.FlushAll(); len(rest) != 1 || rest[0].ChainID != "fresh" {
		t.Fatalf("want 'fresh' still resident, got %+v", rest)
	}
}

func TestAccumulator_SkipsEmptyChainID(t *testing.T) {
	a := NewAccumulator(time.Second)
	a.Observe(model.Event{Sensor: "ebpf.spawn", Comm: "curl", Tags: map[string]string{"app_id": "shop"}}) // no chain_id
	if got := a.FlushAll(); len(got) != 0 {
		t.Errorf("event with no chain_id must be skipped, got %+v", got)
	}
}

func TestAccumulator_SkipsNonEdgeEvents(t *testing.T) {
	a := NewAccumulator(time.Second)
	a.Observe(evChain("heartbeat", "", "c1", "shop", nil, time.Unix(1, 0)))
	if got := a.FlushAll(); len(got) != 0 {
		t.Errorf("non-edge event must not create a chain, got %+v", got)
	}
}

// Fix 3: chain idle EXACTLY equal to configured idle must be flushed (boundary is >=).
func TestAccumulator_IdleBoundaryExact(t *testing.T) {
	idle := 50 * time.Millisecond
	a := NewAccumulator(idle)
	t0 := time.Unix(1_700_000_000, 0)
	a.Observe(evChain("ebpf.spawn", "curl", "c1", "shop", nil, t0))

	// flush exactly at t0+idle — must be >=, so the chain should come out.
	flushed := a.FlushIdle(t0.Add(idle))
	if len(flushed) != 1 || flushed[0].ChainID != "c1" {
		t.Errorf("chain at exact idle boundary must be flushed, got %+v", flushed)
	}
	// Nothing left.
	if rest := a.FlushAll(); len(rest) != 0 {
		t.Errorf("accumulator must be empty after exact-boundary flush, got %+v", rest)
	}
}

// Fix 1: genuinely concurrent Observe + FlushIdle so go test -race can catch a
// dropped lock. Writers hammer varied chain IDs; flushers drain concurrently.
func TestAccumulator_ConcurrentObserveAndFlush(t *testing.T) {
	a := NewAccumulator(time.Millisecond)

	const writers = 8
	const observesPerWriter = 200
	var wg sync.WaitGroup

	// Track total chains seen across all FlushIdle calls.
	var (
		mu         sync.Mutex
		totalSeen  int
	)

	// Concurrent flushers: run until writers are all done.
	done := make(chan struct{})
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					chains := a.FlushIdle(time.Now())
					if len(chains) > 0 {
						mu.Lock()
						totalSeen += len(chains)
						mu.Unlock()
					}
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}

	// Writers: each goroutine observes events with distinct chain IDs.
	var writerWg sync.WaitGroup
	for g := 0; g < writers; g++ {
		writerWg.Add(1)
		g := g
		go func() {
			defer writerWg.Done()
			for i := 0; i < observesPerWriter; i++ {
				chainID := fmt.Sprintf("c%d-%d", g, i)
				a.Observe(evChain("ebpf.spawn", "curl", chainID, "shop",
					map[string]string{"chain_id": chainID, "app_id": "shop"},
					time.Now()))
			}
		}()
	}

	// Wait for all writers, then signal flushers to stop.
	writerWg.Wait()
	close(done)
	wg.Wait()

	// Drain remainder.
	final := a.FlushAll()
	mu.Lock()
	totalSeen += len(final)
	mu.Unlock()

	// Sanity: we must have seen at least some chains (not a count assertion,
	// just a liveness check — the race detector does the real work here).
	if totalSeen == 0 {
		t.Errorf("expected >0 chains flushed across all goroutines, got 0")
	}
}
