// Package session correlates SSH login events with subsequent
// process activity to produce a per-session "who did what" timeline.
//
// Operating model:
//   1. identity.sshd "Accepted" → open a Session record keyed by
//      (user, src_ip, login_time). Capture session_id when sshd
//      provides one (most distros do via PAM env).
//   2. ebpf.proc spawn → walk parent chain to find the originating
//      sshd login session via process tree. Tag the event.
//   3. identity.sshd "disconnect" → close the session.
//
// Output: per-session timeline of {commands, file accesses, net
// connections, alerts}. Investigators query by user / src_ip / time.
package session

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Session is one ssh login from open to close.
type Session struct {
	ID        string    // synthetic if sshd doesn't provide one
	User      string
	SrcIP     string
	SrcGeo    string
	SrcASN    string
	LoginAt   time.Time
	LogoutAt  time.Time
	Method    string // publickey | password | keyboard-interactive
	KeyFP     string // ssh key fingerprint when known
	Active    bool
	RootPID   uint32 // sshd child pid that owns this session

	mu       sync.Mutex
	events   []model.Event // bounded; newest-first eviction at cap
	alerts   []model.Alert
	commands []string
}

// Tracker is the public API.
type Tracker struct {
	mu       sync.RWMutex
	byID     map[string]*Session     // session_id → session
	byUser   map[string][]*Session   // user → sessions (newest last)
	bySrc    map[string][]*Session   // src_ip → sessions
	byPID    map[uint32]*Session     // ancestor pid → session
	maxEvents int

	totalIngested atomic.Uint64
}

// New returns a tracker with sensible defaults.
func New(maxEventsPerSession int) *Tracker {
	if maxEventsPerSession <= 0 {
		maxEventsPerSession = 1024
	}
	return &Tracker{
		byID:      map[string]*Session{},
		byUser:    map[string][]*Session{},
		bySrc:     map[string][]*Session{},
		byPID:     map[uint32]*Session{},
		maxEvents: maxEventsPerSession,
	}
}

// Ingest accepts every event from the bus. Identity events open /
// close sessions; ebpf events get attributed.
func (t *Tracker) Ingest(ev model.Event) {
	t.totalIngested.Add(1)
	switch ev.Sensor {
	case "identity.sshd":
		t.handleSSHD(ev)
	case "identity.sudo", "identity.su":
		t.handleElevation(ev)
	default:
		t.attribute(ev)
	}
}

// IngestAlert records an alert against the matching session.
func (t *Tracker) IngestAlert(a model.Alert) {
	t.mu.RLock()
	s := t.byPID[a.Event.PID]
	t.mu.RUnlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	s.alerts = append(s.alerts, a)
	s.mu.Unlock()
}

func (t *Tracker) handleSSHD(ev model.Event) {
	user := ev.Tags["user"]
	src := ev.Tags["src_ip"]
	outcome := ev.Tags["outcome"]
	if user == "" || src == "" {
		return
	}
	switch outcome {
	case "success":
		s := &Session{
			ID:      newSessionID(user, src, ev.Time),
			User:    user,
			SrcIP:   src,
			LoginAt: ev.Time,
			Method:  ev.Tags["method"],
			KeyFP:   ev.Tags["key_fp"],
			SrcGeo:  ev.Tags["src_geo"],
			SrcASN:  ev.Tags["src_asn"],
			Active:  true,
		}
		t.mu.Lock()
		t.byID[s.ID] = s
		t.byUser[user] = append(t.byUser[user], s)
		t.bySrc[src] = append(t.bySrc[src], s)
		// pid attribution: sshd's child pid (when we have it)
		if ev.PID > 0 {
			t.byPID[ev.PID] = s
			s.RootPID = ev.PID
		}
		t.mu.Unlock()
	case "disconnect":
		t.mu.Lock()
		// Best-effort: close the most recent active session for
		// this (user, src).
		for _, s := range t.bySrc[src] {
			if s.User == user && s.Active {
				s.Active = false
				s.LogoutAt = ev.Time
				if s.RootPID != 0 {
					delete(t.byPID, s.RootPID)
				}
				break
			}
		}
		t.mu.Unlock()
	}
}

func (t *Tracker) handleElevation(ev model.Event) {
	// sudo / su events land in the session that issued them.
	t.attribute(ev)
}

// attribute walks the pid → ancestor map to find a session.
// We accept Event.ParentPID as the ancestor probe; full process-tree
// walk happens at the engine level via SetTreeFn.
func (t *Tracker) attribute(ev model.Event) {
	if ev.PID == 0 {
		return
	}
	t.mu.RLock()
	s := t.byPID[ev.PID]
	if s == nil {
		s = t.byPID[ev.ParentPID]
	}
	t.mu.RUnlock()
	if s == nil {
		return
	}
	// Inherit attribution: child pid joins the session.
	t.mu.Lock()
	t.byPID[ev.PID] = s
	t.mu.Unlock()
	s.mu.Lock()
	if len(s.events) >= t.maxEvents {
		s.events = s.events[1:]
	}
	s.events = append(s.events, ev)
	if ev.Sensor == "ebpf.proc" {
		if cmd := ev.Tags["argv"]; cmd != "" {
			s.commands = append(s.commands, cmd)
		}
	}
	s.mu.Unlock()
}

// List returns active sessions ordered newest-first.
func (t *Tracker) List() []*Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Session, 0, len(t.byID))
	for _, s := range t.byID {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LoginAt.After(out[j].LoginAt)
	})
	return out
}

// Get returns the session for a given id.
func (t *Tracker) Get(id string) *Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byID[id]
}

// SessionMeta is the value-typed (mutex-free) projection of Session
// suitable for embedding in Snapshot and other return values. The
// previous design embedded Session itself; that copied a sync.Mutex
// by value (caught by go vet) and gave the caller a struct whose
// mutex was unrelated to the live tracker's mutex — a subtle
// concurrency bug if any caller ever called methods on the copy.
type SessionMeta struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	SrcIP    string    `json:"src_ip"`
	SrcGeo   string    `json:"src_geo,omitempty"`
	SrcASN   string    `json:"src_asn,omitempty"`
	LoginAt  time.Time `json:"login_at"`
	LogoutAt time.Time `json:"logout_at,omitempty"`
	Method   string    `json:"method,omitempty"`
	KeyFP    string    `json:"key_fp,omitempty"`
	Active   bool      `json:"active"`
	RootPID  uint32    `json:"root_pid,omitempty"`
}

// Snapshot returns a deep copy of one session's events + commands +
// alerts. Suitable for serialising to JSON.
type Snapshot struct {
	Session  SessionMeta   `json:"session"`
	Events   []model.Event `json:"events"`
	Alerts   []model.Alert `json:"alerts"`
	Commands []string      `json:"commands"`
}

// Snapshot freezes a session for export. The returned Snapshot is
// safe to mutate / serialise; it shares no state with the live
// tracker (in particular it has no copy of the session's mutex).
func (s *Session) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Snapshot{
		Session: SessionMeta{
			ID:       s.ID,
			User:     s.User,
			SrcIP:    s.SrcIP,
			SrcGeo:   s.SrcGeo,
			SrcASN:   s.SrcASN,
			LoginAt:  s.LoginAt,
			LogoutAt: s.LogoutAt,
			Method:   s.Method,
			KeyFP:    s.KeyFP,
			Active:   s.Active,
			RootPID:  s.RootPID,
		},
		Events:   append([]model.Event{}, s.events...),
		Alerts:   append([]model.Alert{}, s.alerts...),
		Commands: append([]string{}, s.commands...),
	}
}

// Total events ever ingested by the tracker.
func (t *Tracker) Total() uint64 { return t.totalIngested.Load() }

func newSessionID(user, src string, at time.Time) string {
	return user + "@" + src + "/" + at.UTC().Format("20060102T150405.000")
}
