// Package kparamdrift snapshots and diffs Linux kernel hardening
// parameters under /proc/sys. The signal is asymmetric: when a
// hardening parameter moves from a stricter value to a looser one
// (e.g. `kernel.yama.ptrace_scope` goes 2 → 0), an active attacker
// is preparing the host for the next stage.
//
// Pure-Go. Snapshot reads files; Compare is a deterministic diff.
// Each watched parameter declares its "hardened direction" so the
// diff can label drift as Looser/Stricter/Equivalent.
package kparamdrift

import (
	"os"
	"sort"
	"strconv"
	"strings"
)

// Direction encodes whether a higher numeric value means tighter
// security (Up) or looser (Down). Some kernel knobs are
// bidirectional (e.g. text strings); marked Unknown.
type Direction uint8

const (
	DirectionUnknown Direction = 0
	DirectionUp      Direction = 1 // higher = stricter
	DirectionDown    Direction = 2 // lower = stricter
)

// Param is one watched kernel-sysctl knob.
type Param struct {
	// Path under /proc/sys/. Stored without the prefix.
	Key string
	// HardenedDirection — Up means higher numeric values are more
	// secure (e.g. ptrace_scope, kptr_restrict). Down means lower
	// is more secure (e.g. tcp.timestamps for fingerprinting
	// resistance is debatable; we mark it Up here).
	Direction Direction
	// HardenedFloor is the operator-recommended minimum value. A
	// snapshot value below this floor (for Direction=Up) or above
	// (for Direction=Down) is flagged as "below baseline."
	HardenedFloor int64
	// Notes for the operator UI.
	Notes string
}

// DefaultParams is the curated hardening watch list. The values
// represent reasonable defaults for hardened Debian/Ubuntu hosts;
// operators can override via WatchConfig.Params.
var DefaultParams = []Param{
	{Key: "kernel/yama/ptrace_scope", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "1 restricts ptrace to children; 2 admin-only; 3 disabled"},
	{Key: "kernel/kptr_restrict", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "1 hides kernel pointers from non-root; 2 hides from all"},
	{Key: "kernel/dmesg_restrict", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "1 prevents non-root from reading dmesg"},
	{Key: "kernel/randomize_va_space", Direction: DirectionUp, HardenedFloor: 2,
		Notes: "2 = full ASLR"},
	{Key: "kernel/unprivileged_bpf_disabled", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "1 disables non-root bpf()"},
	{Key: "kernel/unprivileged_userns_clone", Direction: DirectionDown, HardenedFloor: 0,
		Notes: "0 disables non-root user namespaces (smaller attack surface)"},
	{Key: "fs/protected_hardlinks", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "1 blocks classic hardlink attacks on world-writable dirs"},
	{Key: "fs/protected_symlinks", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "1 blocks classic symlink attacks"},
	{Key: "fs/protected_fifos", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "Newer hardening: protect named pipes in world-writable dirs"},
	{Key: "fs/protected_regular", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "Newer hardening: protect regular files in world-writable dirs"},
	{Key: "net/ipv4/tcp_syncookies", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "Mitigates SYN-flood DoS"},
	{Key: "net/ipv4/conf/all/rp_filter", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "Reverse-path filtering blocks spoofed source IPs"},
	{Key: "net/ipv4/conf/all/accept_redirects", Direction: DirectionDown, HardenedFloor: 0,
		Notes: "Reject ICMP redirects (router-spoofing defence)"},
	{Key: "net/ipv4/conf/all/accept_source_route", Direction: DirectionDown, HardenedFloor: 0,
		Notes: "Reject source-routed packets"},
	{Key: "net/ipv4/conf/all/log_martians", Direction: DirectionUp, HardenedFloor: 1,
		Notes: "Log packets with impossible source addrs"},
}

// Value is the observed value for one Param.
type Value struct {
	Key     string
	Raw     string // exact file content
	Numeric int64  // parsed first integer; 0 if not numeric
}

// Snapshot is a set of Values keyed by Param.Key.
type Snapshot struct {
	Values map[string]Value
}

// DriftKind classifies how a value changed.
type DriftKind uint8

const (
	DriftUnchanged DriftKind = 0
	DriftLooser    DriftKind = 1 // weaker security
	DriftStricter  DriftKind = 2 // stronger security
	DriftSideways  DriftKind = 3 // value changed but Direction unknown
)

func (d DriftKind) String() string {
	switch d {
	case DriftLooser:
		return "looser"
	case DriftStricter:
		return "stricter"
	case DriftSideways:
		return "sideways"
	}
	return "unchanged"
}

// Drift reports one param's change.
type Drift struct {
	Key      string
	OldValue Value
	NewValue Value
	Kind     DriftKind
	// BelowFloor is true when New is below the param's
	// HardenedFloor in the security-tightening direction.
	BelowFloor bool
	Notes      string
}

// Diff is the full set of drifts between two snapshots.
type Diff struct {
	Drifts []Drift
}

// IsEmpty reports whether nothing changed.
func (d Diff) IsEmpty() bool { return len(d.Drifts) == 0 }

// HasLooser reports whether any param moved toward weaker security.
func (d Diff) HasLooser() bool {
	for _, x := range d.Drifts {
		if x.Kind == DriftLooser {
			return true
		}
	}
	return false
}

// Snap reads all watched params under root.
// root defaults to "/proc/sys" when "".
func Snap(root string, params []Param) Snapshot {
	if root == "" {
		root = "/proc/sys"
	}
	if len(params) == 0 {
		params = DefaultParams
	}
	out := Snapshot{Values: make(map[string]Value, len(params))}
	for _, p := range params {
		b, err := os.ReadFile(root + "/" + p.Key)
		if err != nil {
			continue
		}
		raw := strings.TrimSpace(string(b))
		v := Value{Key: p.Key, Raw: raw}
		// First whitespace-separated token, parsed as int64.
		f := strings.Fields(raw)
		if len(f) > 0 {
			if n, err := strconv.ParseInt(f[0], 10, 64); err == nil {
				v.Numeric = n
			}
		}
		out.Values[p.Key] = v
	}
	return out
}

// Compare returns the diff between two snapshots, evaluated
// against the same Param list.
func Compare(base, cur Snapshot, params []Param) Diff {
	if len(params) == 0 {
		params = DefaultParams
	}
	var out Diff
	for _, p := range params {
		b, hasB := base.Values[p.Key]
		c, hasC := cur.Values[p.Key]
		if !hasB || !hasC {
			continue
		}
		if b.Raw == c.Raw {
			continue
		}
		kind := DriftSideways
		switch p.Direction {
		case DirectionUp:
			if c.Numeric < b.Numeric {
				kind = DriftLooser
			} else if c.Numeric > b.Numeric {
				kind = DriftStricter
			}
		case DirectionDown:
			if c.Numeric > b.Numeric {
				kind = DriftLooser
			} else if c.Numeric < b.Numeric {
				kind = DriftStricter
			}
		}
		below := false
		switch p.Direction {
		case DirectionUp:
			below = c.Numeric < p.HardenedFloor
		case DirectionDown:
			below = c.Numeric > p.HardenedFloor
		}
		out.Drifts = append(out.Drifts, Drift{
			Key: p.Key, OldValue: b, NewValue: c,
			Kind: kind, BelowFloor: below, Notes: p.Notes,
		})
	}
	sort.Slice(out.Drifts, func(i, j int) bool { return out.Drifts[i].Key < out.Drifts[j].Key })
	return out
}

// FloorAudit reports every param currently below its HardenedFloor
// in cur. Useful for the doctor / posture views — independent of
// any baseline.
func FloorAudit(cur Snapshot, params []Param) []Drift {
	if len(params) == 0 {
		params = DefaultParams
	}
	var out []Drift
	for _, p := range params {
		v, ok := cur.Values[p.Key]
		if !ok {
			continue
		}
		below := false
		switch p.Direction {
		case DirectionUp:
			below = v.Numeric < p.HardenedFloor
		case DirectionDown:
			below = v.Numeric > p.HardenedFloor
		}
		if below {
			out = append(out, Drift{
				Key: p.Key, NewValue: v, Kind: DriftLooser,
				BelowFloor: true, Notes: p.Notes,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
