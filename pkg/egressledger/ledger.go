package egressledger

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Ledger is the public handle. All public methods are nil-safe.
type Ledger struct {
	opts Options

	hot    *hotRing
	warm   *warmStore
	cold   *coldStore
	recent *recentRing

	mu            sync.Mutex
	lastTickAt    time.Time
	lastCompactAt time.Time
	lastWarmFlush time.Time
	lastColdRoll  time.Time
	closed        bool

	observeCount uint64
	dropEmpty    uint64
}

// stateFile persists timestamps across restarts.
type stateFile struct {
	LastCompactionAt time.Time `json:"last_compaction_at"`
	RetentionDays    int       `json:"retention_days"`
}

// New creates a Ledger rooted at opts.Dir. The directory tree is created
// on demand.
func New(opts Options) (*Ledger, error) {
	opts.defaults()
	if opts.Dir == "" {
		return nil, errors.New("egressledger: Dir is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o755); err != nil {
		return nil, err
	}
	warmDir := filepath.Join(opts.Dir, "badger")
	if err := os.MkdirAll(warmDir, 0o755); err != nil {
		return nil, err
	}
	w, err := newWarmStore(warmDir, opts.WarmBucket)
	if err != nil {
		return nil, err
	}
	c, err := newColdStore(opts.Dir)
	if err != nil {
		_ = w.close()
		return nil, err
	}
	l := &Ledger{
		opts:   opts,
		hot:    newHotRing(opts.HotBucket, opts.HotWindow),
		warm:   w,
		cold:   c,
		recent: newRecentRing(opts.RecentRingCap),
	}
	l.loadState()
	// Restore persisted recent-ring entries (last 24h). Drops events
	// older than that so a long-stopped daemon doesn't surface stale
	// PID rows for processes that long since exited.
	l.loadRecent(24 * time.Hour)
	// Start the host-wide listening-port refresher so inferRole can
	// authoritatively classify Server vs Client even for apps on
	// non-standard ports.
	startListenSetRefresher(context.Background(), 15*time.Second)
	return l, nil
}

func (l *Ledger) loadState() {
	if l == nil {
		return
	}
	path := filepath.Join(l.opts.Dir, "state.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil {
		return
	}
	l.mu.Lock()
	l.lastCompactAt = s.LastCompactionAt
	l.mu.Unlock()
}

func (l *Ledger) saveState() {
	if l == nil {
		return
	}
	path := filepath.Join(l.opts.Dir, "state.json")
	l.mu.Lock()
	s := stateFile{LastCompactionAt: l.lastCompactAt, RetentionDays: l.opts.RetentionDays}
	l.mu.Unlock()
	b, err := json.MarshalIndent(&s, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o644)
}

// Observe records a single event. It is safe for concurrent use and avoids
// holding the lock during key construction.
func (l *Ledger) Observe(ev Event) {
	if l == nil {
		return
	}
	atomic.AddUint64(&l.observeCount, 1)
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	// Drop self-loopback noise: kernel routes traffic from the host to
	// its own public IP back through the loopback path, and the eBPF
	// accept-side socket records the remote peer (which is us) as the
	// destination. These rows pollute the dashboard.
	if len(l.opts.OwnIPs) > 0 && ev.DestIP != nil && l.opts.OwnIPs[ev.DestIP.String()] {
		atomic.AddUint64(&l.dropEmpty, 1)
		return
	}
	// Smart per-class bucketing: ev.DestClass (set at the write site
	// by the pipeline) selects /16 for CDN/cloud vs exact IP for raw/
	// unknown/intel_bad. Empty class falls back to legacy /16 OR to the
	// Options.DestClassifier callback if one is configured.
	class := ev.DestClass
	if class == "" && l.opts.DestClassifier != nil {
		class = l.opts.DestClassifier(ev.DestIP, ev.SNI)
	}
	cidr := flowKeyForIP(ev.DestIP, class)
	if cidr == "" && ev.Binary == "" {
		atomic.AddUint64(&l.dropEmpty, 1)
		return
	}
	if l.opts.ExcludePrivate && !IsPublicDestClass(class) {
		// Also check CIDR fallback if class is empty.
		if class != "" || !IsPublicCIDR(cidr) {
			atomic.AddUint64(&l.dropEmpty, 1)
			return
		}
	}
	if ev.Role == "" {
		ev.Role = inferRole(ev.SrcPort, ev.DestPort)
	}
	key := FlowKey{
		Binary:    ev.Binary,
		ExeSHA:    ev.ExeSHA,
		UID:       ev.UID,
		CGroupID:  ev.CGroupID,
		DestCIDR:  cidr,
		DestPort:  ev.DestPort,
		Protocol:  ev.Protocol,
		SNI:       ev.SNI,
		DNSName:   ev.DNSName,
		DestClass: class,
		Role:      ev.Role,
	}
	l.hot.observe(ev.Time, key, &ev)
	l.observeRecent(ev, cidr)
}

// Tick performs scheduled maintenance: slide hot, periodic warm flush, and
// hourly cold roll-up + prune. Idempotent and safe to call from a single
// goroutine.
func (l *Ledger) Tick(ctx context.Context) error {
	if l == nil {
		return nil
	}
	now := time.Now()

	// 0) Persist recent-events ring so it survives daemon restart.
	l.flushRecent()

	// 1) Slide hot ring; anything older than HotWindow becomes warm.
	evicted := l.hot.slide(now)
	if len(evicted) > 0 {
		if err := l.warm.putRecords(evicted); err != nil {
			return err
		}
	}

	// 2) Every 5 minutes also flush near-edge buckets so warm is fresh.
	l.mu.Lock()
	doWarmFlush := now.Sub(l.lastWarmFlush) >= 5*time.Minute
	doColdRoll := now.Sub(l.lastColdRoll) >= time.Hour
	l.lastTickAt = now
	if doWarmFlush {
		l.lastWarmFlush = now
	}
	if doColdRoll {
		l.lastColdRoll = now
	}
	l.mu.Unlock()

	if doWarmFlush {
		// Force-flush hot buckets older than HotBucket so the warm tier sees
		// fresh data even if HotWindow has not elapsed.
		cutoff := now.Add(-l.opts.HotBucket)
		extra := l.snapshotAndDropBefore(cutoff)
		if len(extra) > 0 {
			if err := l.warm.putRecords(extra); err != nil {
				return err
			}
		}
	}

	if doColdRoll {
		// Move warm records older than 1h into cold parquet.
		warmCut := now.Add(-time.Hour)
		drained, err := l.warm.drainOlderThan(warmCut)
		if err != nil {
			return err
		}
		if len(drained) > 0 {
			// Re-bucket to cold granularity.
			rebucketed := make([]FlowRecord, len(drained))
			for i, r := range drained {
				r.Bucket = r.Bucket.Truncate(l.opts.ColdBucket)
				rebucketed[i] = r
			}
			if err := l.cold.appendRecords(rebucketed); err != nil {
				return err
			}
		}
		// Prune cold dirs older than retention.
		cutoff := now.Add(-time.Duration(l.opts.RetentionDays) * 24 * time.Hour)
		if err := l.cold.pruneOlderThan(cutoff); err != nil {
			return err
		}
		// Prune warm older than WarmRetention as a safety net.
		if err := l.warm.pruneOlderThan(now.Add(-l.opts.WarmRetention)); err != nil {
			return err
		}
		l.mu.Lock()
		l.lastCompactAt = now
		l.mu.Unlock()
		l.saveState()
	}

	_ = ctx
	return nil
}

// snapshotAndDropBefore removes hot rows older than cutoff and returns them.
func (l *Ledger) snapshotAndDropBefore(cutoff time.Time) []FlowRecord {
	l.hot.mu.Lock()
	defer l.hot.mu.Unlock()
	var out []FlowRecord
	cn := cutoff.UnixNano()
	for b, m := range l.hot.rows {
		if b < cn {
			bt := time.Unix(0, b)
			for k, v := range m {
				out = append(out, FlowRecord{Key: k, Metrics: *v, Bucket: bt})
			}
			delete(l.hot.rows, b)
		}
	}
	return out
}

// Close flushes hot+warm and releases storage handles.
func (l *Ledger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	// Drain everything in hot to warm.
	rem := l.hot.snapshot()
	if len(rem) > 0 {
		_ = l.warm.putRecords(rem)
	}
	l.saveState()
	return l.warm.close()
}

// Stats returns a snapshot of current ledger health.
func (l *Ledger) Stats() Stats {
	if l == nil {
		return Stats{}
	}
	l.mu.Lock()
	s := Stats{
		LastTickAt:    l.lastTickAt,
		LastCompactAt: l.lastCompactAt,
		RetentionDays: l.opts.RetentionDays,
	}
	l.mu.Unlock()
	s.HotRows = l.hot.rowsCount()
	s.WarmKeys = l.warm.keyCount()
	s.ColdDays = l.cold.dayCount()
	s.ColdBytes = l.cold.totalBytes()
	s.ObserveCount = atomic.LoadUint64(&l.observeCount)
	s.DropEmptyCount = atomic.LoadUint64(&l.dropEmpty)
	return s
}
