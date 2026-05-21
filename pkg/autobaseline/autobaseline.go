// Package autobaseline implements a self-configuring detection
// baseline so xhelix can be installed on an arbitrary Linux host
// (Plesk, cPanel, DirectAdmin, raw nginx, Kubernetes worker, …)
// without a human walking the path tree.
//
// State machine
//
//	┌──────────┐  observation_period elapsed  ┌───────────┐
//	│ OBSERVE  │ ────────────────────────────►│  DETECT   │
//	│ (silent) │                              │ (alerting)│
//	└──────────┘                              └───────────┘
//
// In OBSERVE mode every event passing through pkg/pipeline is
// recorded against the binary that produced it — what syscall
// sensors fired, what capabilities were gained, what files were
// written, what outbound endpoints. Nothing alerts. The agent
// emits one heartbeat alert per hour so the operator knows it's
// still in baseline mode.
//
// At the end of the observation window the recorded behaviour
// is sealed into a per-binary profile. Day-1+ traffic flows
// through IsKnown(image, behavior): if the action exactly matches
// what that binary was already seen doing, the event is tagged
// `baseline_known=true` and any rule that opted into
// baseline-suppression treats it as benign.
//
// This is the "noise" axis. It does NOT prove the binary is
// trustworthy — only that the action falls inside its observed
// envelope. Genuinely-novel behaviour from a known-good binary
// still reaches the rules. Tier-1 deterministic facts (canary
// touch, signed-rule shellcode, sudo to root from a www-data
// shell) always alert regardless of baseline state.
//
// This package supersedes hand-curated runtimeallow entries on a
// per-host basis. runtimeallow is still the seed allowlist for
// the OBSERVE window itself (so we don't accidentally treat sudo
// as anomalous before baseline closes).
//
// Honest limits:
//   - An attacker active during OBSERVE poisons the baseline.
//     Mitigation: a) keep the window short (24h default), b) the
//     sealed profile is signed and operator-reviewable via
//     `xhelixctl posture baseline show`.
//   - A binary that does X once on day 0 has X in its profile
//     forever unless the operator re-baselines. We accept this
//     because the alternative (continuous learning) creates a
//     trivial poisoning vector — an attacker patient enough to
//     repeat their action under threshold trains the system to
//     ignore them.
//   - Profile granularity is coarse (per-image, not per-argv).
//     Fine-grained matching is the rules' job.
package autobaseline

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"

	_ "modernc.org/sqlite"
)

// Mode is the current state of the autobaseline.
type Mode string

const (
	ModeObserve Mode = "observe" // recording, suppressing rules
	ModeDetect  Mode = "detect"  // sealed, querying
	ModeOff     Mode = "off"     // feature disabled
)

// Options configures Manager. Zero values pick reasonable
// defaults (24h observation, /var/lib/xhelix/autobaseline.db).
type Options struct {
	// DBPath is the SQLite file. Empty disables persistence
	// (in-memory only — useful for tests).
	DBPath string
	// Observation is how long OBSERVE mode runs from first
	// startup. Default 24h. Operators on volatile or workload-
	// rotating hosts should set this longer.
	Observation time.Duration
	// SealedAt, if non-zero, forces the manager into DETECT mode
	// using this as the seal timestamp. Loaded from the DB at
	// startup.
	SealedAt time.Time
}

// Behavior is the dimension of an event we record + query
// against. Keep small and discriminating; fine-grained payloads
// belong on the event, not in the profile.
type Behavior struct {
	// Action is the dominant verb: "syscall", "cap_gained",
	// "file_write", "outbound", "memfd_run", "child_spawn".
	Action string
	// Detail is the action-specific payload, normalised:
	//   syscall      → syscall name ("execve", "ptrace")
	//   cap_gained   → capability name ("CAP_SYS_ADMIN")
	//   file_write   → directory of target ("/etc/cron.d")
	//   outbound     → "cidr16:port" ("203.0.113.0/16:443")
	//   memfd_run    → "" (presence alone is the signal)
	//   child_spawn  → child comm
	Detail string
}

// Manager owns the autobaseline state.
type Manager struct {
	mu       sync.RWMutex
	mode     Mode
	startAt  time.Time
	sealAt   time.Time
	obsWin   time.Duration
	db       *sql.DB
	memCache map[string]map[Behavior]uint64 // image → behavior → count
	dirty    bool
}

// New constructs a Manager. If opts.DBPath exists and contains a
// sealed profile, the manager starts in DETECT mode; otherwise
// it starts in OBSERVE.
func New(opts Options) (*Manager, error) {
	if opts.Observation == 0 {
		opts.Observation = 24 * time.Hour
	}
	m := &Manager{
		obsWin:   opts.Observation,
		memCache: map[string]map[Behavior]uint64{},
		startAt:  time.Now(),
	}
	if opts.DBPath == "" {
		m.mode = ModeObserve
		return m, nil
	}
	db, err := sql.Open("sqlite", opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open autobaseline db: %w", err)
	}
	if err := initSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	m.db = db

	// Reload prior state.
	sealedAt, started, err := loadState(db)
	if err != nil {
		return nil, err
	}
	if !started.IsZero() {
		m.startAt = started
	} else {
		if err := saveState(db, "start_at", m.startAt); err != nil {
			return nil, err
		}
	}
	if !sealedAt.IsZero() {
		m.sealAt = sealedAt
		m.mode = ModeDetect
		if err := m.loadProfileIntoCache(); err != nil {
			return nil, err
		}
	} else {
		m.mode = ModeObserve
	}
	return m, nil
}

// Mode returns the current mode. Safe for concurrent callers.
func (m *Manager) Mode() Mode {
	if m == nil {
		return ModeOff
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mode
}

// Status returns a human-readable summary for xhelixctl.
type Status struct {
	Mode             Mode
	StartedAt        time.Time
	SealAt           time.Time
	ObservationLeft  time.Duration
	BinariesObserved int
	BehaviorsTotal   int
}

// Status returns the current snapshot.
func (m *Manager) Status() Status {
	if m == nil {
		return Status{Mode: ModeOff}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := Status{
		Mode:             m.mode,
		StartedAt:        m.startAt,
		SealAt:           m.sealAt,
		BinariesObserved: len(m.memCache),
	}
	for _, bs := range m.memCache {
		s.BehaviorsTotal += len(bs)
	}
	if m.mode == ModeObserve {
		elapsed := time.Since(m.startAt)
		if elapsed < m.obsWin {
			s.ObservationLeft = m.obsWin - elapsed
		}
	}
	return s
}

// Observe records one (image, behavior) pair. Cheap and lock-
// guarded — safe to call from the hot pipeline path. No-op when
// image is empty or mode is DETECT/OFF.
func (m *Manager) Observe(image string, b Behavior) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode != ModeObserve {
		return
	}
	if image == "" {
		return
	}
	// Strip argv that sometimes sneaks in via Image.
	image = strings.Fields(image)[0]
	bs, ok := m.memCache[image]
	if !ok {
		bs = map[Behavior]uint64{}
		m.memCache[image] = bs
	}
	bs[b]++
	m.dirty = true
}

// IsKnown returns true if (image, behavior) is in the sealed
// profile. Always false in OBSERVE or OFF mode — callers must
// gate on Mode() == ModeDetect when using this for suppression.
func (m *Manager) IsKnown(image string, b Behavior) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.mode != ModeDetect {
		return false
	}
	bs, ok := m.memCache[image]
	if !ok {
		return false
	}
	_, ok = bs[b]
	return ok
}

// Tick is called periodically by the daemon. It seals the
// observation window when the elapsed time exceeds Observation,
// and flushes dirty cache rows to disk regardless of mode.
func (m *Manager) Tick(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Persist any pending observations.
	if m.dirty && m.db != nil {
		if err := m.flushLocked(ctx); err != nil {
			return err
		}
		m.dirty = false
	}

	// Auto-seal if the window has elapsed.
	if m.mode == ModeObserve && time.Since(m.startAt) >= m.obsWin {
		m.sealAt = time.Now()
		m.mode = ModeDetect
		if m.db != nil {
			if err := saveState(m.db, "sealed_at", m.sealAt); err != nil {
				return err
			}
		}
	}
	return nil
}

// ForceSeal closes the observation window immediately. Used by
// `xhelixctl posture baseline seal` for operators who want to
// shorten the window after a clean observation period.
func (m *Manager) ForceSeal(ctx context.Context) error {
	if m == nil {
		return errors.New("autobaseline: nil manager")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == ModeDetect {
		return errors.New("autobaseline: already sealed")
	}
	if m.dirty && m.db != nil {
		if err := m.flushLocked(ctx); err != nil {
			return err
		}
		m.dirty = false
	}
	m.sealAt = time.Now()
	m.mode = ModeDetect
	if m.db != nil {
		return saveState(m.db, "sealed_at", m.sealAt)
	}
	return nil
}

// Close persists and releases the DB.
func (m *Manager) Close() error {
	if m == nil || m.db == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dirty {
		if err := m.flushLocked(context.Background()); err != nil {
			return err
		}
	}
	return m.db.Close()
}

// EventToBehavior projects a model.Event onto a Behavior, or
// returns ok=false if the event isn't baseline-relevant.
//
// Kept here (not in pipeline) so the rule for "what counts as
// behaviour" lives next to the storage.
func EventToBehavior(e model.Event) (Behavior, bool) {
	tags := e.Tags
	switch {
	case tags["action"] == "cap_gained" || strings.Contains(e.Sensor, "cap"):
		if cap := tags["capability"]; cap != "" {
			return Behavior{Action: "cap_gained", Detail: cap}, true
		}
	case e.Sensor == "fim" || tags["action"] == "file_write":
		if path := tags["path"]; path != "" {
			return Behavior{Action: "file_write", Detail: filepath.Dir(path)}, true
		}
	case e.Sensor == "netids" || tags["action"] == "outbound":
		if ep := tags["endpoint"]; ep != "" {
			return Behavior{Action: "outbound", Detail: ep}, true
		}
	case tags["action"] == "memfd_run" || strings.Contains(e.Sensor, "memfd"):
		return Behavior{Action: "memfd_run"}, true
	case tags["action"] == "child_spawn":
		if c := tags["child_comm"]; c != "" {
			return Behavior{Action: "child_spawn", Detail: c}, true
		}
	case e.Sensor == "ebpf" && tags["syscall"] != "":
		return Behavior{Action: "syscall", Detail: tags["syscall"]}, true
	}
	return Behavior{}, false
}

// ─────────────────────────── persistence ───────────────────────────

func initSchema(db *sql.DB) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS state (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS profile (
  image   TEXT NOT NULL,
  action  TEXT NOT NULL,
  detail  TEXT NOT NULL,
  hits    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (image, action, detail)
);
CREATE INDEX IF NOT EXISTS profile_image_idx ON profile(image);
`
	_, err := db.Exec(ddl)
	return err
}

func saveState(db *sql.DB, key string, t time.Time) error {
	_, err := db.Exec(
		`INSERT INTO state(key,value) VALUES(?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, t.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func loadState(db *sql.DB) (sealedAt, startedAt time.Time, err error) {
	rows, err := db.Query(`SELECT key, value FROM state`)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return time.Time{}, time.Time{}, err
		}
		t, perr := time.Parse(time.RFC3339Nano, v)
		if perr != nil {
			continue
		}
		switch k {
		case "sealed_at":
			sealedAt = t
		case "start_at":
			startedAt = t
		}
	}
	return sealedAt, startedAt, rows.Err()
}

func (m *Manager) flushLocked(ctx context.Context) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO profile(image, action, detail, hits) VALUES(?,?,?,?)
		ON CONFLICT(image, action, detail) DO UPDATE SET hits = hits + excluded.hits`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for img, bs := range m.memCache {
		for b, n := range bs {
			if n == 0 {
				continue
			}
			if _, err := stmt.ExecContext(ctx, img, b.Action, b.Detail, n); err != nil {
				_ = tx.Rollback()
				return err
			}
			// Reset the in-mem delta — sealed profile lives in DB +
			// is reloaded into cache for fast IsKnown lookups.
			bs[b] = 0
		}
	}
	return tx.Commit()
}

func (m *Manager) loadProfileIntoCache() error {
	rows, err := m.db.Query(`SELECT image, action, detail FROM profile`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var img, action, detail string
		if err := rows.Scan(&img, &action, &detail); err != nil {
			return err
		}
		bs, ok := m.memCache[img]
		if !ok {
			bs = map[Behavior]uint64{}
			m.memCache[img] = bs
		}
		bs[Behavior{Action: action, Detail: detail}] = 1
	}
	return rows.Err()
}
