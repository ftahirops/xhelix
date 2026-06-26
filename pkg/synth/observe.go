// Package synth turns recorded workflow shapes into a candidate BRP profile
// proposal. It ranks and proposes; it never enforces, signs, or auto-loads.
// SP-4 Cycle 2 (Synthesizer).
package synth

import (
	"sort"

	"github.com/xhelix/xhelix/pkg/recorder"
)

// ShapeReader is the slice of *recorder.Store the synthesizer needs. An
// interface so synth is testable without a live DB.
type ShapeReader interface {
	Shapes(appID string) ([]recorder.ShapeRow, error)
	ExemplarsByKey(appID, shapeHash string, kind recorder.EdgeKind) (map[string][]string, error)
}

// Observed is the unioned behavior of one app across all its recorded shapes.
type Observed struct {
	App         string
	SampleCount int
	ExecRaws    []string            // distinct exec exemplar raws (image paths)
	EgressKeys  []string            // distinct egress keys (host:port)
	WriteDirs   map[string][]string // dir -> distinct leaf paths
}

// Gather unions every recorded shape for appID into one Observed.
func Gather(r ShapeReader, appID string) (Observed, error) {
	shapes, err := r.Shapes(appID)
	if err != nil {
		return Observed{}, err
	}
	execSet := map[string]struct{}{}
	egressSet := map[string]struct{}{}
	writeDirs := map[string]map[string]struct{}{}
	total := 0
	for _, sh := range shapes {
		total += int(sh.Count)
		ex, err := r.ExemplarsByKey(appID, sh.ShapeHash, recorder.EdgeExec)
		if err != nil {
			return Observed{}, err
		}
		for _, raws := range ex {
			for _, raw := range raws {
				if raw != "" {
					execSet[raw] = struct{}{}
				}
			}
		}
		eg, err := r.ExemplarsByKey(appID, sh.ShapeHash, recorder.EdgeEgress)
		if err != nil {
			return Observed{}, err
		}
		for key := range eg {
			egressSet[key] = struct{}{}
		}
		wr, err := r.ExemplarsByKey(appID, sh.ShapeHash, recorder.EdgeWrite)
		if err != nil {
			return Observed{}, err
		}
		for dir, raws := range wr {
			if writeDirs[dir] == nil {
				writeDirs[dir] = map[string]struct{}{}
			}
			for _, raw := range raws {
				writeDirs[dir][raw] = struct{}{}
			}
		}
	}
	o := Observed{App: appID, SampleCount: total, WriteDirs: map[string][]string{}}
	o.ExecRaws = sortedKeys(execSet)
	o.EgressKeys = sortedKeys(egressSet)
	for dir, set := range writeDirs {
		o.WriteDirs[dir] = sortedKeys(set)
	}
	return o, nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
