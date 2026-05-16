// Package correlatorshard wraps `pkg/correlator` in a sharded
// dispatcher that preserves within-shard determinism while
// scaling aggregate throughput linearly with shard count.
//
// Design constraints (preserved from the single-goroutine
// correlator):
//
//   - Within one shard, events are processed in arrival order.
//     This is the property that makes incident replay reproducible.
//   - Across shards, ordering is unspecified — but no correlation
//     rule's group_by partition ever crosses a shard, so two
//     events that *could* combine into one incident always land
//     on the same shard.
//
// Partitioning: by default, events are hashed on `ev.PID`. The
// kernel only emits one event-stream per pid, and almost every
// correlation rule's group_by is pid-or-narrower (proctree path,
// exe_sha, dst_ip), so pid-partitioning is sufficient. Callers
// with rules that group by something coarser (e.g. user uid)
// supply a custom PartitionFunc.
//
// Pure-Go, no new dependencies.
package correlatorshard

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"

	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/model"
)

// PartitionFunc maps an event to its shard index. The returned
// value is taken modulo the shard count.
type PartitionFunc func(ev model.Event) uint64

// DefaultPartition uses ev.PID. Stable across event types and
// matches the dominant group_by axis for xhelix's rule set.
func DefaultPartition(ev model.Event) uint64 {
	if ev.PID == 0 {
		// Fall back to ev.Comm hash so kernel-thread events
		// don't all pile onto shard 0.
		h := fnv.New64a()
		_, _ = h.Write([]byte(ev.Comm))
		return h.Sum64()
	}
	return uint64(ev.PID)
}

// PartitionByGroup returns a PartitionFunc that hashes the given
// event-tag value, falling back to DefaultPartition when the tag
// is absent. Useful for rule sets that group by exe_sha or unit.
func PartitionByGroup(tag string) PartitionFunc {
	return func(ev model.Event) uint64 {
		if v, ok := ev.Tags[tag]; ok && v != "" {
			h := fnv.New64a()
			_, _ = h.Write([]byte(v))
			return h.Sum64()
		}
		return DefaultPartition(ev)
	}
}

// Shard is the multi-shard dispatcher.
type Shard struct {
	shards     []*shardWorker
	partition  PartitionFunc
	dropped    atomic.Uint64
	stopped    atomic.Bool
	bufferSize int
}

type shardWorker struct {
	idx     int
	engine  *correlator.Engine
	in      chan model.Event
	done    chan struct{}
	dropped atomic.Uint64
	count   atomic.Uint64
}

// Config configures New.
type Config struct {
	// Shards is the worker count. <=0 selects 4.
	Shards int

	// BufferSize is the per-shard channel depth. <=0 selects 1024.
	BufferSize int

	// PartitionFunc maps events to shard indices. nil → DefaultPartition.
	PartitionFunc PartitionFunc

	// Rules are loaded into every shard's engine.
	Rules []correlator.Rule

	// Emit is the alert emitter; receives Alerts produced by any
	// shard. Must be safe for concurrent invocation.
	Emit correlator.IncidentFn
}

// New starts a sharded dispatcher. Returns the Shard. Caller
// invokes Stop() to terminate worker goroutines.
func New(ctx context.Context, cfg Config) (*Shard, error) {
	if cfg.Emit == nil {
		return nil, errors.New("correlatorshard: Emit required")
	}
	n := cfg.Shards
	if n <= 0 {
		n = 4
	}
	buf := cfg.BufferSize
	if buf <= 0 {
		buf = 1024
	}
	part := cfg.PartitionFunc
	if part == nil {
		part = DefaultPartition
	}

	s := &Shard{
		shards:     make([]*shardWorker, n),
		partition:  part,
		bufferSize: buf,
	}

	// Build the emit wrapper. We serialise alerts through a
	// single emit mutex so the user's IncidentFn doesn't need to
	// be thread-safe internally (we promise it isn't called
	// concurrently from our workers).
	var emitMu sync.Mutex
	safeEmit := func(a model.Alert) {
		emitMu.Lock()
		defer emitMu.Unlock()
		cfg.Emit(a)
	}

	for i := 0; i < n; i++ {
		e, err := correlator.New(safeEmit)
		if err != nil {
			return nil, err
		}
		if len(cfg.Rules) > 0 {
			if err := e.Load(cfg.Rules); err != nil {
				return nil, err
			}
		}
		w := &shardWorker{
			idx:    i,
			engine: e,
			in:     make(chan model.Event, buf),
			done:   make(chan struct{}),
		}
		s.shards[i] = w
		go w.run(ctx)
	}
	return s, nil
}

// Ingest routes ev to the appropriate shard. Non-blocking on
// full channels — drops with a counter increment instead of
// blocking the producer. The dispatch loop must not stall on
// correlator pressure.
func (s *Shard) Ingest(ev model.Event) {
	if s.stopped.Load() {
		return
	}
	idx := s.partition(ev) % uint64(len(s.shards))
	w := s.shards[idx]
	select {
	case w.in <- ev:
		w.count.Add(1)
	default:
		w.dropped.Add(1)
		s.dropped.Add(1)
	}
}

// Stop signals all workers to terminate and waits for them.
func (s *Shard) Stop() {
	if !s.stopped.CompareAndSwap(false, true) {
		return
	}
	for _, w := range s.shards {
		close(w.in)
	}
	for _, w := range s.shards {
		<-w.done
	}
}

// Stats is a brief inventory for status reporting.
type Stats struct {
	Shards      int
	Ingested    uint64
	Dropped     uint64
	PerShard    []ShardStat
}

// ShardStat is the per-shard breakdown.
type ShardStat struct {
	Index    int
	Count    uint64
	Dropped  uint64
	Sessions int
}

// Stats returns the current counters.
func (s *Shard) Stats() Stats {
	out := Stats{
		Shards:   len(s.shards),
		Dropped:  s.dropped.Load(),
		PerShard: make([]ShardStat, len(s.shards)),
	}
	for i, w := range s.shards {
		out.Ingested += w.count.Load()
		out.PerShard[i] = ShardStat{
			Index:    i,
			Count:    w.count.Load(),
			Dropped:  w.dropped.Load(),
			Sessions: w.engine.SessionCount(),
		}
	}
	return out
}

// SessionCount returns the total in-flight sessions across all
// shards. Convenience helper for parity with single-shard usage.
func (s *Shard) SessionCount() int {
	total := 0
	for _, w := range s.shards {
		total += w.engine.SessionCount()
	}
	return total
}

// ── worker ────────────────────────────────────────────────────

func (w *shardWorker) run(ctx context.Context) {
	defer close(w.done)
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.in:
			if !ok {
				return
			}
			w.engine.Ingest(ctx, ev)
		}
	}
}
