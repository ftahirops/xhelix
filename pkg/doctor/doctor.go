// Package doctor is xhelix's built-in security audit + remediation
// tool. Run via `xhelix doctor` to scan the host for hardening gaps,
// then optionally apply fixes interactively.
//
// Design:
//   - Each Check is a self-contained unit: it knows what to look for,
//     why it matters, the recommended fix, and (optionally) how to
//     apply that fix in code.
//   - Checks are pure with respect to the host: they read state but
//     never mutate it. Mutation only happens through Fix(), which the
//     CLI invokes after asking the operator.
//   - Categories group checks for filtering and reporting.
//   - Severity drives the score and the recommended order of fixes.
//
// What this is NOT:
//   - A CVE scanner. Trivy / Grype / Vulners do that better. We hook
//     into apt/dnf for "pending security updates" but don't ship a
//     CVE database.
//   - A compliance auditor for a specific framework. The check IDs
//     are loosely aligned with CIS, but we don't claim compliance.
//   - A magic fix-everything button. Some fixes are risky (kernel
//     hardening that breaks containers, AppArmor enforce that breaks
//     custom apps); those are flagged and require explicit confirm.
package doctor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity orders findings by their "fix this first" priority.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

// Status is the outcome of running a check.
type Status int

const (
	// Pass: the host is configured the way we recommend.
	Pass Status = iota
	// Warn: not strictly broken, but a non-default-secure setting.
	Warn
	// Fail: the host is configured the way attackers exploit.
	Fail
	// Skip: not applicable here (e.g. SELinux check on Debian).
	Skip
	// Errored: the check itself broke; cannot judge.
	Errored
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	case Skip:
		return "SKIP"
	default:
		return "ERROR"
	}
}

// Result is what a check returns.
type Result struct {
	Status   Status
	Evidence string // observed value(s) — e.g. "kernel.kptr_restrict=0"
	Detail   string // optional extra context
	Err      error  // populated only when Status == Errored
}

// Pass-fast helpers used heavily in checks.
func PassResult(evidence string) Result    { return Result{Status: Pass, Evidence: evidence} }
func WarnResult(evidence string) Result    { return Result{Status: Warn, Evidence: evidence} }
func FailResult(evidence string) Result    { return Result{Status: Fail, Evidence: evidence} }
func SkipResult(reason string) Result      { return Result{Status: Skip, Evidence: reason} }
func ErrorResult(err error) Result         { return Result{Status: Errored, Err: err} }

// Check is one auditable hardening item.
type Check struct {
	// ID is stable, dotted, and unique. Used by --check filter and
	// JSON output. Example: "kernel.kptr_restrict".
	ID string
	// Title is one short line describing what's being checked.
	Title string
	// Category groups related checks (e.g. "kernel", "ssh", "fs").
	Category string
	// Severity drives ordering and the security score.
	Severity Severity
	// Description explains, in operator language, what this check
	// looks at and why we look at it.
	Description string
	// Impact describes the risk of leaving this unfixed — the answer
	// to "what does an attacker do if I ignore this?".
	Impact string
	// Recommendation is human-readable fix guidance, regardless of
	// whether Apply is set.
	Recommendation string
	// FixCommand is a shell-friendly representation of the change,
	// shown to the operator. Set even when Apply is implemented so
	// the operator can copy-paste outside our tool.
	FixCommand string
	// Risky marks fixes that could disrupt service if applied
	// blindly (e.g. SSH config changes that lock you out, AppArmor
	// enforce that breaks an app). Even with --yes, we ask first.
	Risky bool
	// Run reads host state and returns a Result. Must not mutate.
	Run func(ctx context.Context) Result
	// Apply mutates host state to fix the issue. Optional — if nil,
	// the check is informational and the operator must fix manually.
	Apply func(ctx context.Context) error
}

// Finding pairs a check with its result, for reports.
type Finding struct {
	Check  Check
	Result Result
	RanAt  time.Time
}

// Score is a 0..100 composite. Higher is better.
//
// Algorithm: each non-skipped check contributes weight=1<<severity
// when it would have full credit. Pass = full credit, Warn = half,
// Fail = none. Errored does not count (we don't penalise for things
// we couldn't measure). The composite is the percentage of total
// credit earned.
type Score struct {
	Composite int
	Total     int
	Passed    int
	Warned    int
	Failed    int
	Skipped   int
	Errored   int
}

// Report is the result of a Runner.Run.
type Report struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Hostname   string
	Findings   []Finding
	Score      Score
}

// Runner orchestrates the checks.
type Runner struct {
	Checks      []Check
	Concurrency int // 0 = GOMAXPROCS-aware default
}

// NewRunner builds a runner with the given checks. The checks slice
// is copied so callers can safely mutate the source.
func NewRunner(checks []Check) *Runner {
	out := make([]Check, len(checks))
	copy(out, checks)
	// Stable sort by severity desc then category then ID so the
	// report has a predictable shape.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	return &Runner{Checks: out, Concurrency: 8}
}

// Filter returns a new runner containing only checks that match the
// predicate. category=="" matches all. id substring "" matches all.
func (r *Runner) Filter(category, idSubstr string) *Runner {
	if category == "" && idSubstr == "" {
		return r
	}
	var keep []Check
	for _, c := range r.Checks {
		if category != "" && c.Category != category {
			continue
		}
		if idSubstr != "" && !strings.Contains(c.ID, idSubstr) {
			continue
		}
		keep = append(keep, c)
	}
	return &Runner{Checks: keep, Concurrency: r.Concurrency}
}

// Run executes every check and returns a Report. ctx is propagated
// to every check; the Runner does not impose a per-check timeout —
// individual checks should bound themselves with exec.CommandContext.
func (r *Runner) Run(ctx context.Context) Report {
	rep := Report{
		StartedAt: time.Now(),
		Findings:  make([]Finding, len(r.Checks)),
	}

	conc := r.Concurrency
	if conc <= 0 {
		conc = 8
	}
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, c := range r.Checks {
		i, c := i, c
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					rep.Findings[i] = Finding{
						Check:  c,
						Result: Result{Status: Errored, Err: fmt.Errorf("panic: %v", rec)},
						RanAt:  time.Now(),
					}
				}
			}()
			res := c.Run(ctx)
			rep.Findings[i] = Finding{Check: c, Result: res, RanAt: time.Now()}
		}()
	}
	wg.Wait()
	rep.FinishedAt = time.Now()
	rep.Score = computeScore(rep.Findings)
	return rep
}

// computeScore turns findings into a 0..100 composite.
//
// Weights: 1, 2, 4, 8, 16 for Info..Critical. A failed Critical hurts
// 16x more than a failed Info — which is the right shape for a "fix
// these in order" prompt.
func computeScore(findings []Finding) Score {
	s := Score{}
	weight := func(sev Severity) int {
		return 1 << uint(sev)
	}
	earned, total := 0, 0
	for _, f := range findings {
		switch f.Result.Status {
		case Pass:
			s.Passed++
			w := weight(f.Check.Severity)
			earned += w
			total += w
		case Warn:
			s.Warned++
			w := weight(f.Check.Severity)
			earned += w / 2
			total += w
		case Fail:
			s.Failed++
			w := weight(f.Check.Severity)
			total += w
		case Skip:
			s.Skipped++
		case Errored:
			s.Errored++
		}
	}
	if total == 0 {
		s.Composite = 100
	} else {
		s.Composite = int(float64(earned) / float64(total) * 100)
	}
	s.Total = len(findings)
	return s
}

// Counts for top-level report headers.
func (r Report) FailedCritical() int  { return r.countFor(Fail, SeverityCritical) }
func (r Report) FailedHigh() int      { return r.countFor(Fail, SeverityHigh) }
func (r Report) FailedMedium() int    { return r.countFor(Fail, SeverityMedium) }
func (r Report) FailedLow() int       { return r.countFor(Fail, SeverityLow) }

func (r Report) countFor(st Status, sev Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Result.Status == st && f.Check.Severity == sev {
			n++
		}
	}
	return n
}

// FailedFindings returns only the failures and warnings, sorted by
// severity desc then category. Useful for the interactive CLI.
func (r Report) FailedFindings() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Result.Status == Fail || f.Result.Status == Warn {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Check.Severity != out[j].Check.Severity {
			return out[i].Check.Severity > out[j].Check.Severity
		}
		if out[i].Result.Status != out[j].Result.Status {
			// Fail before Warn within the same severity.
			return out[i].Result.Status == Fail
		}
		if out[i].Check.Category != out[j].Check.Category {
			return out[i].Check.Category < out[j].Check.Category
		}
		return out[i].Check.ID < out[j].Check.ID
	})
	return out
}
