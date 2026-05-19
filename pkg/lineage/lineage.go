// Package lineage manages the causal chain of identifiers that every
// event in xhelix carries. A lineage chain answers the question
// "what authentication or scheduling event ultimately caused this?"
//
// Lineage is nested. An SSH login mints a lineage_id. A sudo inside
// that session mints a second one preserving the outer. A
// process spawned by either has the chain [ssh_id, sudo_id]. Queries
// can match at any level.
package lineage

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

// LineageID uniquely identifies a causal root. Process-local minter
// guarantees monotonic IDs within a daemon lifetime; the value space
// is large enough that collisions across reboots are not a practical
// concern for audit-chain purposes.
type LineageID uint64

// RootType classifies what kind of root created this lineage. The
// type determines which Origin metadata fields are meaningful.
type RootType uint8

const (
	RootUnknown   RootType = 0
	RootSSH       RootType = 1
	RootPAM       RootType = 2
	RootCron      RootType = 3
	RootSystemd   RootType = 4
	RootContainer RootType = 5
	RootSudo      RootType = 6
	RootWeb       RootType = 7
	RootLocal     RootType = 8
	RootKernel    RootType = 9
)

// String returns a stable short token used in audit-chain output.
func (r RootType) String() string {
	switch r {
	case RootSSH:
		return "ssh"
	case RootPAM:
		return "pam"
	case RootCron:
		return "cron"
	case RootSystemd:
		return "systemd"
	case RootContainer:
		return "container"
	case RootSudo:
		return "sudo"
	case RootWeb:
		return "web"
	case RootLocal:
		return "local"
	case RootKernel:
		return "kernel"
	}
	return "unknown"
}

// Chain is the nested causal chain: outermost lineage first,
// innermost last. A direct SSH session has length 1; an SSH session
// where the user ran sudo has length 2.
type Chain []LineageID

// Extend returns a new chain with newID appended. The parent chain
// is not modified — chains are append-only and shared safely.
func (c Chain) Extend(newID LineageID) Chain {
	out := make(Chain, len(c)+1)
	copy(out, c)
	out[len(c)] = newID
	return out
}

// Innermost returns the most-recently-appended ID, or 0 if empty.
func (c Chain) Innermost() LineageID {
	if len(c) == 0 {
		return 0
	}
	return c[len(c)-1]
}

// Outermost returns the root ID, or 0 if empty.
func (c Chain) Outermost() LineageID {
	if len(c) == 0 {
		return 0
	}
	return c[0]
}

// Contains returns true if id appears anywhere in the chain.
func (c Chain) Contains(id LineageID) bool {
	for _, x := range c {
		if x == id {
			return true
		}
	}
	return false
}

// Equal returns true if two chains have identical IDs in identical order.
func (c Chain) Equal(other Chain) bool {
	if len(c) != len(other) {
		return false
	}
	for i, id := range c {
		if id != other[i] {
			return false
		}
	}
	return true
}

// String renders as "id1>id2>id3" for human-readable logs.
func (c Chain) String() string {
	if len(c) == 0 {
		return "(none)"
	}
	out := ""
	for i, id := range c {
		if i > 0 {
			out += ">"
		}
		out += fmt.Sprintf("%d", id)
	}
	return out
}

// Marshal serialises a chain into a compact little-endian byte
// string for event payloads. Use with UnmarshalChain to round-trip.
func (c Chain) Marshal() []byte {
	if len(c) == 0 {
		return nil
	}
	out := make([]byte, 8*len(c))
	for i, id := range c {
		binary.LittleEndian.PutUint64(out[i*8:], uint64(id))
	}
	return out
}

// UnmarshalChain reads a chain produced by Marshal.
func UnmarshalChain(b []byte) (Chain, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if len(b)%8 != 0 {
		return nil, fmt.Errorf("lineage: chain bytes not multiple of 8 (got %d)", len(b))
	}
	out := make(Chain, len(b)/8)
	for i := range out {
		out[i] = LineageID(binary.LittleEndian.Uint64(b[i*8:]))
	}
	return out, nil
}

// Origin describes the root that minted a lineage_id. Only the
// fields relevant to Type are populated.
type Origin struct {
	ID        LineageID
	Type      RootType
	CreatedAt time.Time

	// Common: which user is associated with this lineage, if any.
	UserName  string
	UID       uint32
	LoginUID  uint32

	// Network roots (SSH, web)
	SourceIP   string
	SourcePort uint16

	// SSH only
	SSHKeyHash string // sha256 of the authorized key used

	// PAM only
	PAMSessionID uint32

	// Cron only
	CronEntry string // job name + fire time

	// Systemd only
	SystemdUnit string

	// Container only
	ContainerID string
	PodID       string

	// Web only
	HTTPRequestID string
	Method        string
	Path          string

	// Sudo only — preserves the lineage being escalated FROM
	EscalatedFromUID uint32
	EscalatedFromName string
}

// Minter generates unique LineageIDs within a daemon lifetime. Safe
// for concurrent use by multiple goroutines.
type Minter struct {
	counter atomic.Uint64
}

// NewMinter constructs a Minter seeded with a startup-time component
// so IDs are roughly comparable in magnitude to the daemon's start
// time but remain monotonic within the process.
func NewMinter() *Minter {
	m := &Minter{}
	// Seed with current unix-nano so two daemons started at different
	// times don't immediately overlap their ID spaces in human
	// observation; this is not a uniqueness guarantee across daemons.
	m.counter.Store(uint64(time.Now().UnixNano()))
	return m
}

// New mints a fresh LineageID.
func (m *Minter) New() LineageID {
	return LineageID(m.counter.Add(1))
}

// Store keeps Origin metadata for lineages we've seen. It is
// process-local and bounded; ancient lineages are evicted by a
// caller-driven sweep.
type Store struct {
	origins map[LineageID]Origin
}

// NewStore constructs an empty Store.
func NewStore() *Store {
	return &Store{origins: make(map[LineageID]Origin)}
}

// Put records or replaces an Origin entry.
func (s *Store) Put(o Origin) {
	if o.ID == 0 {
		return
	}
	if o.CreatedAt.IsZero() {
		o.CreatedAt = time.Now()
	}
	s.origins[o.ID] = o
}

// Get returns the Origin for an ID, plus whether it was found.
func (s *Store) Get(id LineageID) (Origin, bool) {
	o, ok := s.origins[id]
	return o, ok
}

// Resolve walks a chain and returns the Origins in order. Missing
// origins are skipped silently — caller decides whether that matters.
func (s *Store) Resolve(c Chain) []Origin {
	out := make([]Origin, 0, len(c))
	for _, id := range c {
		if o, ok := s.origins[id]; ok {
			out = append(out, o)
		}
	}
	return out
}

// SweepOlderThan removes origins whose CreatedAt is before cutoff.
// Returns the number removed.
func (s *Store) SweepOlderThan(cutoff time.Time) int {
	removed := 0
	for id, o := range s.origins {
		if o.CreatedAt.Before(cutoff) {
			delete(s.origins, id)
			removed++
		}
	}
	return removed
}

// Size returns the number of stored origins.
func (s *Store) Size() int {
	return len(s.origins)
}
