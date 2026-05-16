package model

import (
	"time"

	"github.com/oklog/ulid/v2"
)

// ProcNode summarises a single process in an ancestry chain.
//
// Used to populate Event.ProcTree for tree-walking rule predicates.
type ProcNode struct {
	PID         uint32    `json:"pid"`
	Comm        string    `json:"comm,omitempty"`
	Argv        []string  `json:"argv,omitempty"`
	UID         uint32    `json:"uid"`
	StartNs     uint64    `json:"start_ns,omitempty"`
	Image       string    `json:"image,omitempty"`
	FirstAction time.Time `json:"first_action,omitempty"`
}

// Event is the canonical record produced by every sensor.
//
// Fields are normalised across sensor types so the rule engine can
// evaluate uniformly. Sensor-specific payloads live in Raw.
type Event struct {
	ID        ulid.ULID         `json:"id"`
	Time      time.Time         `json:"time"`
	Sensor    string            `json:"sensor"`
	Severity  Severity          `json:"severity"`
	Verdict   Verdict           `json:"verdict"`
	Host      string            `json:"host,omitempty"`
	PID       uint32            `json:"pid,omitempty"`
	TID       uint32            `json:"tid,omitempty"`
	Comm      string            `json:"comm,omitempty"`
	UID       uint32            `json:"uid"`
	GID       uint32            `json:"gid"`
	CGroupID  uint64            `json:"cgroup_id,omitempty"`
	Container string            `json:"container,omitempty"`
	Image     string            `json:"image,omitempty"`
	ParentPID uint32            `json:"parent_pid,omitempty"`
	ProcTree  []ProcNode        `json:"proc_tree,omitempty"`
	Rule      string            `json:"rule,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Raw       any               `json:"raw,omitempty"`
}

// NewEvent returns an Event with a fresh ULID and the current time.
func NewEvent(sensor string, sev Severity) Event {
	return Event{
		ID:       ulid.Make(),
		Time:     time.Now().UTC(),
		Sensor:   sensor,
		Severity: sev,
		Tags:     map[string]string{},
	}
}
