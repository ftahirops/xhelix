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
	"time"

	"github.com/xhelix/xhelix/pkg/lineagescore"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rulecat"
)

// ReplayOpts controls a replay run.
type ReplayOpts struct {
	AlertMode       string            // "visibility" | "detection"
	Resolver        *rulecat.Resolver // rule_id -> Category
	TruePositiveIDs map[string]bool   // rule ids that MUST keep emitting
	Verdict         bool              // route incident/weak_signal through pkg/lineagescore
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
	VerdictsEmitted      int            `json:"verdicts_emitted"`
	CollapsedByRule      map[string]int `json:"collapsed_by_rule"` // incident/weak raw fires that did NOT individually emit under verdict mode
}

func newResult() *ReplayResult {
	return &ReplayResult{
		EmittedByRule:        map[string]int{},
		SuppressedByRule:     map[string]int{},
		SuppressedByCategory: map[string]int{},
		Unclassified:         map[string]int{},
		CollapsedByRule:      map[string]int{},
	}
}

type lineEnvelope struct {
	RuleID string `json:"rule_id"`
	Event  struct {
		PID  uint32 `json:"pid"`
		Time string `json:"time"`
	} `json:"event"`
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

	// Verdict-mode score engine. LineageOf defaults to identity (each PID
	// is its own lineage root) — see honest limitation below.
	var eng *lineagescore.Engine
	if opts.Verdict {
		eng = lineagescore.New(lineagescore.Opts{
			Threshold: 80,
			Window:    time.Hour,
		})
	}
	// Synthetic clock for lines whose event.time is missing/unparseable,
	// so windowing stays deterministic. Each such line advances 1ms.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

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

		// Verdict mode: incident/weak_signal are routed through the
		// per-lineage score engine instead of emitting raw. Facts and
		// hard_deny keep their non-verdict behaviour. Detection mode
		// always emits everything (verdict has no effect there).
		if opts.Verdict && opts.AlertMode != "detection" &&
			(cat == model.CategoryIncident || cat == model.CategoryWeakSignal) {

			at, ok := parseEventTime(env.Event.Time)
			if !ok {
				at = base.Add(time.Duration(res.TotalLines) * time.Millisecond)
			}
			v := eng.Observe(lineagescore.Signal{
				PID:    env.Event.PID,
				RuleID: env.RuleID,
				Weight: opts.Resolver.Weight(env.RuleID),
				At:     at,
			})
			if v != nil {
				res.VerdictsEmitted++
				res.Emitted++
				res.EmittedByRule[env.RuleID]++
			} else {
				res.Suppressed++
				res.SuppressedByRule[env.RuleID]++
				res.SuppressedByCategory[cat.String()]++
				res.CollapsedByRule[env.RuleID]++
			}
			// TP rules are hard_deny (handled below), but keep the guard
			// honest: a TP rule that landed here would be a misclassify.
			if opts.TruePositiveIDs[env.RuleID] && v == nil {
				res.TPRegressions = append(res.TPRegressions,
					fmt.Sprintf("TP REGRESSION: rule %q (category %s) collapsed under verdict mode (no threshold crossing)",
						env.RuleID, cat.String()))
			}
			continue
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

// parseEventTime parses an event timestamp as RFC3339. Returns ok=false
// when empty or unparseable, signalling the caller to use a synthetic
// monotonic clock so verdict windowing stays deterministic.
func parseEventTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
