// Package main — xhelix-replay re-processes a captured alerts.jsonl log
// under a configurable (resolver + alert-mode) policy and reports per-rule
// before/after counts. It reuses pkg/rulecat so the offline verdict is
// identical to the live alert-bus gate. This is the canonical FP
// measurement tool — every detection change must include its output.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/xhelix/xhelix/pkg/rulecat"
)

// ReplayOpts controls a replay run.
type ReplayOpts struct {
	AlertMode       string            // "visibility" | "detection"
	Resolver        *rulecat.Resolver // rule_id -> Category
	TruePositiveIDs map[string]bool   // rule ids that MUST keep emitting
}

// ReplayResult is the structured output of a replay.
type ReplayResult struct {
	TotalLines           int            `json:"total_lines"`
	Parsed               int            `json:"parsed"`
	Emitted              int            `json:"emitted"`
	Suppressed           int            `json:"suppressed"`
	EmittedByRule        map[string]int `json:"emitted_by_rule"`
	SuppressedByRule     map[string]int `json:"suppressed_by_rule"`
	SuppressedByCategory map[string]int `json:"suppressed_by_category"`
	Unclassified         map[string]int `json:"unclassified"` // rule ids not in resolver
	TPRegressions        []string       `json:"tp_regressions"`
}

func newResult() *ReplayResult {
	return &ReplayResult{
		EmittedByRule:        map[string]int{},
		SuppressedByRule:     map[string]int{},
		SuppressedByCategory: map[string]int{},
		Unclassified:         map[string]int{},
	}
}

type lineEnvelope struct {
	RuleID string `json:"rule_id"`
}

// ReplayFile streams a JSONL alerts log through the (resolver, mode)
// policy and returns the aggregate result.
func ReplayFile(path string, opts ReplayOpts) (*ReplayResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	return replayReader(f, opts)
}

func replayReader(r io.Reader, opts ReplayOpts) (*ReplayResult, error) {
	res := newResult()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		res.TotalLines++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var env lineEnvelope
		if err := json.Unmarshal(line, &env); err != nil {
			continue // skip malformed
		}
		if env.RuleID == "" {
			continue
		}
		res.Parsed++

		// Track unclassified BEFORE resolving (Category() returns the
		// weak_signal default for unknowns, so we check membership via
		// the resolver's own knowledge).
		cat := opts.Resolver.Category(env.RuleID)
		if !opts.Resolver.Known(env.RuleID) {
			res.Unclassified[env.RuleID]++
		}

		if rulecat.ShouldEmit(cat, opts.AlertMode) {
			res.Emitted++
			res.EmittedByRule[env.RuleID]++
		} else {
			res.Suppressed++
			res.SuppressedByRule[env.RuleID]++
			res.SuppressedByCategory[cat.String()]++
			if opts.TruePositiveIDs[env.RuleID] {
				res.TPRegressions = append(res.TPRegressions,
					fmt.Sprintf("TP REGRESSION: rule %q (category %s) suppressed under mode %s",
						env.RuleID, cat.String(), opts.AlertMode))
			}
		}
	}
	return res, sc.Err()
}
