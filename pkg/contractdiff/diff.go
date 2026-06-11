// Package contractdiff computes a human-readable behavioral diff between
// two compiled contract versions (P7). It powers the "what changed since
// the last signed version" review: when the current compiled contract
// drifts from the last-approved one, the operator sees exactly which
// behaviors were added or removed before approving (re-signing).
package contractdiff

import (
	"sort"

	"github.com/xhelix/xhelix/pkg/contractcompiler"
)

// ChangeKind names the dimension a change occurred in.
type ChangeKind string

const (
	KindService      ChangeKind = "service"       // a whole service added/removed
	KindExecAllow    ChangeKind = "exec_allow"    // allowed binary added/removed
	KindExecDeny     ChangeKind = "exec_deny"     // red-zone exec floor change
	KindDenySyscalls ChangeKind = "deny_syscalls" // denied syscall added/removed
	KindWriteDeny    ChangeKind = "write_deny"    // write-deny zone added/removed
)

// Op is the direction of a change.
type Op string

const (
	OpAdded   Op = "added"
	OpRemoved Op = "removed"
)

// Change is one added/removed behavior.
type Change struct {
	Kind  ChangeKind `json:"kind"`
	Unit  string     `json:"unit,omitempty"` // service unit ("" for app-level)
	Op    Op         `json:"op"`
	Value string     `json:"value"`
}

// Diff is the full set of changes from one contract version to another,
// plus a count of unchanged behaviors for context.
type Diff struct {
	App       string   `json:"app"`
	FromSHA   string   `json:"from_sha"`
	ToSHA     string   `json:"to_sha"`
	Changes   []Change `json:"changes"`
	Unchanged int      `json:"unchanged"`
}

// Empty reports whether the two versions are behaviorally identical.
func (d Diff) Empty() bool { return len(d.Changes) == 0 }

// Compute returns the behavioral diff transforming `from` into `to`.
// A nil `from` means "no prior version" — every behavior in `to` reads as
// added. Services are matched by Unit; within a service, each policy set
// is diffed as a set (order-independent).
func Compute(from, to *contractcompiler.CompiledContract) Diff {
	d := Diff{}
	if to != nil {
		d.App = to.App
		d.ToSHA = to.ArtifactSHA
	}
	if from != nil {
		d.App = from.App
		d.FromSHA = from.ArtifactSHA
	}

	fromSvc := indexServices(from)
	toSvc := indexServices(to)

	// Service-level add/remove.
	for unit := range toSvc {
		if _, ok := fromSvc[unit]; !ok {
			d.Changes = append(d.Changes, Change{Kind: KindService, Unit: unit, Op: OpAdded, Value: unit})
		}
	}
	for unit := range fromSvc {
		if _, ok := toSvc[unit]; !ok {
			d.Changes = append(d.Changes, Change{Kind: KindService, Unit: unit, Op: OpRemoved, Value: unit})
		}
	}

	// Per-service set diffs for services present in BOTH versions.
	for unit, ts := range toSvc {
		fs, ok := fromSvc[unit]
		if !ok {
			// New service: count its behaviors as added.
			d.diffSets(unit, nil, ts)
			continue
		}
		d.diffSets(unit, fs, ts)
	}
	// Removed services contribute their behaviors as removed.
	for unit, fs := range fromSvc {
		if _, ok := toSvc[unit]; !ok {
			d.diffSets(unit, fs, nil)
		}
	}

	sortChanges(d.Changes)
	return d
}

// diffSets appends added/removed changes for each policy set of a service
// and tallies unchanged entries.
func (d *Diff) diffSets(unit string, from, to *contractcompiler.CompiledService) {
	type setpair struct {
		kind     ChangeKind
		from, to []string
	}
	pairs := []setpair{
		{KindExecAllow, fieldOr(from, func(s *contractcompiler.CompiledService) []string { return s.ExecAllow }),
			fieldOr(to, func(s *contractcompiler.CompiledService) []string { return s.ExecAllow })},
		{KindExecDeny, fieldOr(from, func(s *contractcompiler.CompiledService) []string { return s.ExecDeny }),
			fieldOr(to, func(s *contractcompiler.CompiledService) []string { return s.ExecDeny })},
		{KindDenySyscalls, fieldOr(from, func(s *contractcompiler.CompiledService) []string { return s.DenySyscalls }),
			fieldOr(to, func(s *contractcompiler.CompiledService) []string { return s.DenySyscalls })},
		{KindWriteDeny, fieldOr(from, func(s *contractcompiler.CompiledService) []string { return s.WriteDeny }),
			fieldOr(to, func(s *contractcompiler.CompiledService) []string { return s.WriteDeny })},
	}
	for _, p := range pairs {
		added, removed, same := diffStringSets(p.from, p.to)
		d.Unchanged += same
		for _, v := range added {
			d.Changes = append(d.Changes, Change{Kind: p.kind, Unit: unit, Op: OpAdded, Value: v})
		}
		for _, v := range removed {
			d.Changes = append(d.Changes, Change{Kind: p.kind, Unit: unit, Op: OpRemoved, Value: v})
		}
	}
}

func indexServices(cc *contractcompiler.CompiledContract) map[string]*contractcompiler.CompiledService {
	out := map[string]*contractcompiler.CompiledService{}
	if cc == nil {
		return out
	}
	for i := range cc.Services {
		out[cc.Services[i].Unit] = &cc.Services[i]
	}
	return out
}

func fieldOr(s *contractcompiler.CompiledService, get func(*contractcompiler.CompiledService) []string) []string {
	if s == nil {
		return nil
	}
	return get(s)
}

// diffStringSets returns (added, removed, sameCount) treating inputs as sets.
func diffStringSets(from, to []string) (added, removed []string, same int) {
	fs := map[string]bool{}
	for _, v := range from {
		fs[v] = true
	}
	ts := map[string]bool{}
	for _, v := range to {
		ts[v] = true
	}
	for v := range ts {
		if fs[v] {
			same++
		} else {
			added = append(added, v)
		}
	}
	for v := range fs {
		if !ts[v] {
			removed = append(removed, v)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed, same
}

func sortChanges(c []Change) {
	sort.Slice(c, func(i, j int) bool {
		if c[i].Unit != c[j].Unit {
			return c[i].Unit < c[j].Unit
		}
		if c[i].Kind != c[j].Kind {
			return c[i].Kind < c[j].Kind
		}
		if c[i].Op != c[j].Op {
			return c[i].Op < c[j].Op
		}
		return c[i].Value < c[j].Value
	})
}
