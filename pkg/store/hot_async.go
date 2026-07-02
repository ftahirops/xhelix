package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Default async-writer tuning. The hot store is a recent-events cache, so the
// queue is smaller than the coldstore's; batching keeps SQLite transaction
// overhead off the per-event path.
const (
	hotWriteCapDefault    = 65536
	hotWriteBatchDefault  = 512
	hotWriteFlushInterval = 250 * time.Millisecond
)

// StartWriter enables the async write-behind path and launches the writer
// goroutine. Callers then use Submit instead of Insert. Safe to call once;
// subsequent calls are no-ops. The writer runs until ctx is cancelled or Close
// is called, whichever comes first.
//
// bufCap is the in-memory queue capacity; <= 0 selects the default.
func (h *HotStore) StartWriter(ctx context.Context, bufCap int) {
	if !h.writerOn.CompareAndSwap(false, true) {
		return
	}
	if bufCap <= 0 {
		bufCap = hotWriteCapDefault
	}
	h.writeCap = bufCap
	h.wake = make(chan struct{}, 1)
	h.writeDone = make(chan struct{})
	h.writeQ = make([]model.Event, 0, bufCap)
	go h.runWriter(ctx)
}

// Submit enqueues an event for asynchronous persistence. It never blocks: if
// the queue is full it drops the OLDEST queued event and bumps the drop
// counter. When the writer is not running, Submit falls back to a synchronous
// Insert so behaviour is correct even if StartWriter was never called.
func (h *HotStore) Submit(e model.Event) {
	if !h.writerOn.Load() {
		_ = h.Insert(context.Background(), e)
		return
	}
	h.submitted.Add(1)
	h.writeMu.Lock()
	if len(h.writeQ) >= h.writeCap {
		h.writeQ = h.writeQ[1:] // drop oldest
		h.dropped.Add(1)
	}
	h.writeQ = append(h.writeQ, e)
	full := len(h.writeQ) >= hotWriteBatchDefault
	h.writeMu.Unlock()
	if full {
		h.nudge()
	}
}

// nudge wakes the writer without blocking (buffered-1 channel, coalesced).
func (h *HotStore) nudge() {
	if h.wake == nil {
		return
	}
	select {
	case h.wake <- struct{}{}:
	default:
	}
}

// WriteStats reports async-writer counters for health/observability.
func (h *HotStore) WriteStats() (submitted, written, dropped uint64) {
	return h.submitted.Load(), h.written.Load(), h.dropped.Load()
}

func (h *HotStore) runWriter(ctx context.Context) {
	defer close(h.writeDone)
	t := time.NewTicker(hotWriteFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			h.drainAll()
			return
		case <-h.wake:
			h.drainAll()
			if !h.writerOn.Load() {
				return // Close() drained us
			}
		case <-t.C:
			h.drainAll()
			if !h.writerOn.Load() {
				h.drainAll()
				return
			}
		}
	}
}

// drainAll flushes the entire queue in batches until it is empty.
func (h *HotStore) drainAll() {
	for h.flushOnce() > 0 {
	}
}

// flushOnce pulls up to one batch off the queue and writes it in a single
// transaction. Returns the number of rows written.
func (h *HotStore) flushOnce() int {
	h.writeMu.Lock()
	if len(h.writeQ) == 0 {
		h.writeMu.Unlock()
		return 0
	}
	n := hotWriteBatchDefault
	if n > len(h.writeQ) {
		n = len(h.writeQ)
	}
	batch := make([]model.Event, n)
	copy(batch, h.writeQ[:n])
	h.writeQ = h.writeQ[n:]
	h.writeMu.Unlock()

	if err := h.writeBatch(batch); err != nil {
		// Persistence is best-effort here: the cold store and forensic chain
		// hold the durable copy. Count the loss rather than blocking or
		// crashing the writer goroutine.
		h.dropped.Add(uint64(len(batch)))
		return len(batch) // still made progress on the queue
	}
	h.written.Add(uint64(len(batch)))
	return len(batch)
}

// writeBatch inserts all rows in a single transaction.
func (h *HotStore) writeBatch(rows []model.Event) error {
	tx, err := h.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO events (id, ts, sensor, severity, host, pid, comm, image, rule, tags)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, e := range rows {
		tagJSON, _ := json.Marshal(e.Tags)
		if _, err := stmt.Exec(
			e.ID.String(), e.Time.UnixNano(), e.Sensor, e.Severity.String(),
			e.Host, e.PID, e.Comm, e.Image, e.Rule, string(tagJSON),
		); err != nil {
			_ = stmt.Close()
			_ = tx.Rollback()
			return err
		}
	}
	_ = stmt.Close()
	return tx.Commit()
}
