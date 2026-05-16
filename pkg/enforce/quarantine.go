package enforce

import (
	"os"
	"sync"
	"time"
)

// SignalFn is the abstraction over signal delivery so tests can
// substitute a fake without touching real pids. Production wires
// this to syscall.Kill on Linux and a no-op elsewhere.
type SignalFn func(pid int, sig os.Signal) error

// Quarantine pauses pids on rule fire and tracks them so an operator
// can resume or kill via the CLI.
//
// Phase 7 implements the userspace half: SIGSTOP / SIGCONT / SIGKILL.
// Forensic snapshot capture (memory dump, /proc/<pid>/maps) is the
// caller's responsibility — the snapshot path should be set on the
// QuarantineRecord before Stop is called so the record links to the
// captured artefacts.
type Quarantine struct {
	send SignalFn

	mu       sync.Mutex
	records  map[uint32]*QuarantineRecord
}

// QuarantineRecord describes one stopped pid.
type QuarantineRecord struct {
	PID         uint32
	Comm        string
	Image       string
	StoppedAt   time.Time
	ResumedAt   time.Time
	KilledAt    time.Time
	RuleID      string
	SnapshotID  string // populated by the caller after capture
	State       string // "stopped" | "resumed" | "killed"
}

// NewQuarantine builds a tracker. send may be nil; in that case
// signal delivery is a no-op (useful for unit tests).
func NewQuarantine(send SignalFn) *Quarantine {
	return &Quarantine{send: send, records: map[uint32]*QuarantineRecord{}}
}

// Stop SIGSTOPs pid. It is idempotent — stopping an already-stopped
// pid returns the existing record without re-signalling.
func (q *Quarantine) Stop(pid uint32, comm, image, ruleID string) (*QuarantineRecord, error) {
	if pid == 0 || pid == 1 {
		return nil, errInvalidPID
	}
	q.mu.Lock()
	defer q.mu.Unlock()

	if r, ok := q.records[pid]; ok && r.State == "stopped" {
		return r, nil
	}
	r := &QuarantineRecord{
		PID:       pid,
		Comm:      comm,
		Image:     image,
		StoppedAt: time.Now().UTC(),
		RuleID:    ruleID,
		State:     "stopped",
	}
	if q.send != nil {
		if err := q.send(int(pid), sigSTOP); err != nil {
			return nil, err
		}
	}
	q.records[pid] = r
	return r, nil
}

// Resume sends SIGCONT to pid.
func (q *Quarantine) Resume(pid uint32) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, ok := q.records[pid]
	if !ok {
		return errNotQuarantined
	}
	if q.send != nil {
		if err := q.send(int(pid), sigCONT); err != nil {
			return err
		}
	}
	r.ResumedAt = time.Now().UTC()
	r.State = "resumed"
	return nil
}

// Kill terminates pid with SIGKILL.
func (q *Quarantine) Kill(pid uint32) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	r, ok := q.records[pid]
	if !ok {
		return errNotQuarantined
	}
	if q.send != nil {
		if err := q.send(int(pid), sigKILL); err != nil {
			return err
		}
	}
	r.KilledAt = time.Now().UTC()
	r.State = "killed"
	return nil
}

// Snapshot returns a copy of the active record set.
func (q *Quarantine) Snapshot() []QuarantineRecord {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]QuarantineRecord, 0, len(q.records))
	for _, r := range q.records {
		out = append(out, *r)
	}
	return out
}
