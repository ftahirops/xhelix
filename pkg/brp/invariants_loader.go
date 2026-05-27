package brp

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// T09 — operator-extensible hard-deny invariant list.
//
// DefaultInvariants() returns the canonical baked-in v2 set. This
// loader merges an operator YAML file on top so site-specific
// additions don't require a rebuild.
//
// Merge rules (intentionally additive only — operators can EXTEND
// the hard-deny set but cannot weaken it via YAML; weakening a baked-
// in invariant must be a deliberate code change with review):
//   * AlwaysSuspicious  — union
//   * DeniedExecsByRole — per-role union; new roles added
//
// Missing file is NOT an error — daemon falls back to defaults.

// InvariantsFile is the on-disk YAML shape.
type InvariantsFile struct {
	AlwaysSuspicious  []string            `yaml:"always_suspicious"`
	DeniedExecsByRole map[string][]string `yaml:"denied_execs_by_role"`
}

// LoadInvariantsFile reads path and returns the parsed InvariantsFile.
// Missing file → empty struct + nil error. Parse error → nil + error.
func LoadInvariantsFile(path string) (*InvariantsFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &InvariantsFile{}, nil
		}
		return nil, fmt.Errorf("brp invariants %s: %w", path, err)
	}
	var f InvariantsFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("brp invariants %s: parse: %w", path, err)
	}
	return &f, nil
}

// Merge returns base augmented with overlay. Pure — neither input
// is mutated. Duplicates are deduped.
func (base Invariants) Merge(overlay InvariantsFile) Invariants {
	out := Invariants{
		AlwaysSuspicious:  append([]string{}, base.AlwaysSuspicious...),
		DeniedExecsByRole: map[string][]string{},
	}
	out.AlwaysSuspicious = mergeUniqueStrings(out.AlwaysSuspicious, overlay.AlwaysSuspicious)
	for k, v := range base.DeniedExecsByRole {
		out.DeniedExecsByRole[k] = append([]string{}, v...)
	}
	for role, denies := range overlay.DeniedExecsByRole {
		out.DeniedExecsByRole[role] = mergeUniqueStrings(out.DeniedExecsByRole[role], denies)
	}
	return out
}

// LoadInvariantsWithOverlay returns DefaultInvariants merged with
// the file at path. Missing file = defaults only.
func LoadInvariantsWithOverlay(path string) (Invariants, error) {
	f, err := LoadInvariantsFile(path)
	if err != nil {
		return DefaultInvariants(), err
	}
	return DefaultInvariants().Merge(*f), nil
}

func mergeUniqueStrings(base, add []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(base)+len(add))
	for _, s := range append(append([]string{}, base...), add...) {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
