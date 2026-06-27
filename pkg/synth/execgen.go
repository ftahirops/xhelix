package synth

import (
	"regexp"
	"sort"
)

// Volatile exec-path patterns observed in real recorded data. These change
// every run, so without generalization the learned ExecAllowed envelope
// over-specifies and never matches the next execution.
var (
	// Go build cache exe dirs: /tmp/go-build<digits>/b001/exe/foo
	goBuildExecRE = regexp.MustCompile(`^/tmp/go-build[0-9]+/`)
	// Version-pinned path segments: name@v1.2.3-... → name@* (Go module cache,
	// toolchain pins, etc.). Stops at the next path separator.
	versionSegRE = regexp.MustCompile(`@[^/]+`)
)

// GeneralizeExecPaths canonicalizes transient/volatile exec paths so a learned
// ExecAllowed envelope doesn't over-specify on paths that change every run.
// Conservative — only known volatile patterns are rewritten; every other path
// passes through verbatim (under-generalize rather than over-claim, matching
// GeneralizeWriteRoots). Returns sorted distinct paths. R&D heuristic; the
// operator-review gate is the safety net.
func GeneralizeExecPaths(paths []string) []string {
	set := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		set[canonExecPath(p)] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func canonExecPath(p string) string {
	// Whole ephemeral Go build tree collapses to one glob.
	if goBuildExecRE.MatchString(p) {
		return "/tmp/go-build*/**"
	}
	// Collapse every version-pinned segment (handles multiple @ segments).
	return versionSegRE.ReplaceAllString(p, "@*")
}
