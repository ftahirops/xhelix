// Package writebehind is a generic async-writer ring for the
// SQLite-backed stores. The host's hot path enqueues; a single
// background goroutine drains and batches inserts. Producers
// never block on SQLite's single-writer constraint.
//
// Crash window: at most BatchInterval of in-memory events lost
// on hard kill. For xhelix this is acceptable — the eBPF ringbuf
// has the same guarantee, and the forensic chain is signed
// per-batch downstream so a missing batch is detectable.
//
// Drop policy is configurable:
//
//   - DropNewest: incoming Insert returns immediately, sample
//     dropped. Default. Best for "more samples is better but
//     producers must not stall."
//   - DropOldest: silently evict from the head when the ring
//     is full, then append new.
//   - Block: producer blocks until queue space appears. Used by
//     forensic-chain stores where loss is unacceptable but back-
//     pressure on the dispatch loop is.
//
// Generic over the item type via the Writer interface. No
// external dependencies.
package writebehind

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Writer is the destination for a batch of items.
type Writer[T any] interface {
	// WriteBatch persists items. Errors are logged by the
	// ring; production callers typically pass an idempotent
	// upsert so retries on transient errors are safe.
	WriteBatch(ctx context.Context, items []T) error
}

// DropPolicy controls behaviour when the ring is full.
type DropPolicy uint8

const (
	DropNewest DropPolicy = 0 // discard the incoming item
	DropOldest DropPolicy = 1 // evict from queue head, then append
	Block      DropPolicy = 2 // wait for space (with a Submit-level ctx cancel)
)

// Config configures NewRing.
type Config[T any] struct {
	// Writer receives WriteBatch calls. Required.
	Writer Writer[T]

	// BufferSize bounds the in-memory queue. <=0 selects 4096.
	BufferSize int

	// MaxBatch caps the size of one WriteBatch. <=0 selects 256.
	MaxBatch int

	// BatchInterval is how long the writer waits before flushing
	// a partial batch. <=0 selects 200ms.
	BatchInterval time.Duration

	// DropPolicy applies when the queue is full.
	DropPolicy DropPolicy

	// OnError is called for each WriteBatch failure. nil → silent.
	OnError func(err error, batchSize int)
}

// Ring is the write-behind queue + drain goroutine.
type Ring[T any] struct {
	cfg     Config[T]
	queue   chan T
	stopped atomic.Bool
	done    chan struct{}

	inserted atomic.Uint64
	dropped  atomic.Uint64
	written  atomic.Uint64
	batches  atomic.Uint64
	errors   atomic.Uint64

	// blockMu serialises Block-policy submitters so they can
	// share the queue's channel.
	blockMu sync.Mutex
}

// NewRing starts the drain goroutine and returns the Ring.
// Callers invoke Stop() to flush and shut down.
func NewRing[T any](ctx context.Context, cfg Config[T]) (*Ring[T], error) {
	if cfg.Writer == nil {
		return nil, errors.New("writebehind: Writer required")
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 4096
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 256
	}
	if cfg.BatchInterval <= 0 {
		cfg.BatchInterval = 200 * time.Millisecond
	}
	r := &Ring[T]{
		cfg:   cfg,
		queue: make(chan T, cfg.BufferSize),
		done:  make(chan struct{}),
	}
	go r.drain(ctx)
	return r, nil
}

// Submit enqueues item per the configured DropPolicy.
//
// Returns (true, nil) on accept. (false, nil) on drop. The
// per-policy semantics:
//
//   DropNewest: full queue → (false, nil), item discarded.
//   DropOldest: full queue → one head dropped, item enqueued,
//               returns (true, nil).
//   Block:      blocks until space or ctx.Done() → (false, ctx.Err()).
func (r *Ring[T]) Submit(ctx context.Context, item T) (bool, error) {
	if r.stopped.Load() {
		return false, errors.New("writebehind: stopped")
	}
	r.inserted.Add(1)
	switch r.cfg.DropPolicy {
	case Block:
		r.blockMu.Lock()
		defer r.blockMu.Unlock()
		select {
		case r.queue <- item:
			return true, nil
		case <-ctx.Done():
			r.dropped.Add(1)
			return false, ctx.Err()
		}
	case DropOldest:
		for {
			select {
			case r.queue <- item:
				return true, nil
			default:
				// Pop one head to make room.
				select {
				case <-r.queue:
					r.dropped.Add(1)
				default:
					// Channel drained between checks; loop.
				}
			}
		}
	default: // DropNewest
		select {
		case r.queue <- item:
			return true, nil
		default:
			r.dropped.Add(1)
			return false, nil
		}
	}
}

// Stop closes the queue, drains the remaining buffer through the
// Writer, and waits for the drain goroutine to exit.
func (r *Ring[T]) Stop() {
	if !r.stopped.CompareAndSwap(false, true) {
		return
	}
	close(r.queue)
	<-r.done
}

// Stats reports operational counters.
type Stats struct {
	Inserted uint64
	Dropped  uint64
	Written  uint64
	Batches  uint64
	Errors   uint64
	QueueLen int
}

// Stats returns the current counters.
func (r *Ring[T]) Stats() Stats {
	return Stats{
		Inserted: r.inserted.Load(),
		Dropped:  r.dropped.Load(),
		Written:  r.written.Load(),
		Batches:  r.batches.Load(),
		Errors:   r.errors.Load(),
		QueueLen: len(r.queue),
	}
}

// ── drain goroutine ──────────────────────────────────────────

func (r *Ring[T]) drain(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.cfg.BatchInterval)
	defer ticker.Stop()

	batch := make([]T, 0, r.cfg.MaxBatch)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		err := r.cfg.Writer.WriteBatch(ctx, batch)
		r.batches.Add(1)
		if err != nil {
			r.errors.Add(1)
			if r.cfg.OnError != nil {
				r.cfg.OnError(err, len(batch))
			}
		} else {
			r.written.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			// Drain whatever's in the queue best-effort, then exit.
			for {
				select {
				case item, ok := <-r.queue:
					if !ok {
						flush()
						return
					}
					batch = append(batch, item)
					if len(batch) >= r.cfg.MaxBatch {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case item, ok := <-r.queue:
			if !ok {
				flush()
				return
			}
			batch = append(batch, item)
			if len(batch) >= r.cfg.MaxBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}
