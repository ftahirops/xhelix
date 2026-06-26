package synth

import "sort"

// GeneralizeWriteRoots converts observed per-dir write samples into candidate
// WriteRoots. A dir with at least globThreshold distinct observed leaves is
// generalized to "<dir>/**"; a dir with fewer keeps its exact observed paths
// (under-generalize rather than over-claim). Returns sorted distinct roots.
//
// HEURISTIC (R&D): globThreshold default is uncalibrated — see plan Global
// Constraints. Isolated here so it can be retuned independently.
func GeneralizeWriteRoots(o Observed, globThreshold int) []string {
	if globThreshold < 1 {
		globThreshold = 1
	}
	set := map[string]struct{}{}
	for dir, leaves := range o.WriteDirs {
		if len(leaves) >= globThreshold {
			set[dir+"/**"] = struct{}{}
		} else {
			for _, leaf := range leaves {
				set[leaf] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
