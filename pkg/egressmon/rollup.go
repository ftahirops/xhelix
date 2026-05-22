package egressmon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Rollup writes periodic snapshots of the Observer to a daily JSONL
// file under a configured directory. The file is rotated at UTC
// midnight; each line is one PerLineageStats record stamped with the
// snapshot time. Operators (and the analytics CLI) can replay the
// file to reconstruct activity for any given day.
//
// Honest scope: this is observability storage, not durable runtime
// state. Lineage state is process-tree-scoped and doesn't survive a
// daemon restart — only the *history* survives, which is what
// "analytics" actually needs.
type Rollup struct {
	obs     *Observer
	dir     string
	period  time.Duration
	host    string

	mu      sync.Mutex
	curFile *os.File
	curDate string // YYYY-MM-DD of curFile
}

// RollupRecord is one line in the daily JSONL.
type RollupRecord struct {
	At    time.Time         `json:"at"`
	Host  string            `json:"host,omitempty"`
	Stats PerLineageStats   `json:"stats"`
}

// NewRollup constructs a Rollup writer.
//   dir    : where to write YYYY-MM-DD.jsonl (created if missing).
//   period : how often to write a snapshot (zero = 60s default).
//   host   : optional host identifier baked into each record.
func NewRollup(obs *Observer, dir string, period time.Duration, host string) *Rollup {
	if period <= 0 {
		period = 60 * time.Second
	}
	return &Rollup{obs: obs, dir: dir, period: period, host: host}
}

// Start runs the rollup loop until ctx is cancelled. Writes one
// snapshot per period; rotates on UTC date change.
func (r *Rollup) Start(ctx context.Context) error {
	if err := os.MkdirAll(r.dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", r.dir, err)
	}
	go func() {
		t := time.NewTicker(r.period)
		defer t.Stop()
		// Immediate first write so analytics CLI has data even right
		// after daemon start.
		_ = r.writeOnce()
		for {
			select {
			case <-ctx.Done():
				r.close()
				return
			case <-t.C:
				_ = r.writeOnce()
			}
		}
	}()
	return nil
}

func (r *Rollup) writeOnce() error {
	now := time.Now().UTC()
	date := now.Format("2006-01-02")
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.curDate != date {
		if r.curFile != nil {
			_ = r.curFile.Close()
		}
		path := filepath.Join(r.dir, date+".jsonl")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		r.curFile = f
		r.curDate = date
	}
	snaps := r.obs.Snapshot(0)
	enc := json.NewEncoder(r.curFile)
	for _, s := range snaps {
		_ = enc.Encode(RollupRecord{At: now, Host: r.host, Stats: s})
	}
	return r.curFile.Sync()
}

func (r *Rollup) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.curFile != nil {
		_ = r.curFile.Close()
		r.curFile = nil
	}
}

// LoadDay reads a single day's JSONL records from dir. Missing file
// returns (nil, nil). Used by xhelixctl egress analytics --date.
func LoadDay(dir, date string) ([]RollupRecord, error) {
	path := filepath.Join(dir, date+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []RollupRecord
	dec := json.NewDecoder(f)
	for dec.More() {
		var rec RollupRecord
		if err := dec.Decode(&rec); err != nil {
			return out, err
		}
		out = append(out, rec)
	}
	return out, nil
}
