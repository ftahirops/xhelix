package takeover

import "time"

// Scorer turns a list of Signals into a 0-100 composite score plus a
// per-kind contribution breakdown for explainability.
//
// Algorithm (matches FULL_TAKEOVER_DETECTION.md §4.2):
//
//  score = clamp(Σ effective_weight(signal) + Σ cooccur_bonus, 0, 100)
//
//  effective_weight(s) = s.Weight if s.Weight > 0 else Weights[s.Kind]
//
// Same-kind signals diminish: the 1st gets full weight, the 2nd
// gets 50%, the 3rd gets 25%, the rest 10% each. Prevents one noisy
// sensor from saturating the score on its own — composition rule
// from BEHAVIORAL_DEFENSE.md §5.
//
// Co-occurrence bonuses (P-PS.22, borrowed from IDE Shepherd's
// two-signal-in-same-source idea): when N specific SignalKinds
// co-occur within Window in the lineage, an additive bonus
// applies. Catches malicious COMPOSITIONS that individual signals
// don't capture (e.g. base64_decode alone is noisy; base64_decode
// + chmod_exec + shell_attempt is a dropper chain).
type Scorer struct {
	W       Weights
	CoRules []ScorerCoRule
}

// ScorerCoRule defines a dynamic co-occurrence bonus.
type ScorerCoRule struct {
	// ID identifies the rule in contribution breakdowns.
	ID string
	// Need is the set of SignalKinds that must ALL be present in
	// the snapshot for the bonus to apply.
	Need []SignalKind
	// Window — max age delta between earliest and latest matching
	// signal. Zero = unbounded.
	Window time.Duration
	// Bonus is added once per evaluation (not per signal). Capped
	// at 100 by the overall score clamp.
	Bonus int
}

// NewScorer returns a Scorer with the given weight table. Pass nil
// for DefaultWeights(). Co-occurrence rules default to DefaultCoRules().
func NewScorer(w Weights) *Scorer {
	if w == nil {
		w = DefaultWeights()
	}
	return &Scorer{W: w, CoRules: DefaultCoRules()}
}

// DefaultCoRules — adapted from the IDE Shepherd two-signal idea
// for our dynamic per-lineage signal stream (P-PS.22). Each rule
// fires once per scoring evaluation; bonuses stack additively
// before the final clamp to 100.
func DefaultCoRules() []ScorerCoRule {
	return []ScorerCoRule{
		{
			ID:     "cooccur.dropper_chain",
			Need:   []SignalKind{SignalBase64Decode, SignalChmodExec},
			Window: 60 * time.Second,
			Bonus:  30,
		},
		{
			ID:     "cooccur.beacon_then_shell",
			Need:   []SignalKind{SignalC2Beacon, SignalShellAttempt},
			Window: 90 * time.Second,
			Bonus:  35,
		},
		{
			ID:     "cooccur.exfil_chain",
			Need:   []SignalKind{SignalDecoyTouch, SignalForbiddenConnect},
			Window: 5 * time.Minute,
			Bonus:  30,
		},
		{
			ID:     "cooccur.recon_then_persist",
			Need:   []SignalKind{SignalReconTool, SignalPersistence},
			Window: 5 * time.Minute,
			Bonus:  25,
		},
		{
			ID:     "cooccur.delete_after_shell",
			Need:   []SignalKind{SignalShellAttempt, SignalRecursiveDelete},
			Window: 2 * time.Minute,
			Bonus:  20,
		},
		{
			ID:     "cooccur.identity_then_attack",
			Need:   []SignalKind{SignalIdentityMismatch, SignalShellAttempt},
			Window: 5 * time.Minute,
			Bonus:  40,
		},
	}
}

// Result is the scorer's output: a composite score plus the
// per-kind contributions and any co-occurrence bonuses that fired.
type Result struct {
	Score         int
	Contributions []KindContribution
	CoBonuses     []CoBonus
}

// CoBonus is one fired co-occurrence rule, included in Result for
// explainability.
type CoBonus struct {
	RuleID string
	Bonus  int
}

// KindContribution is one row in Result.Contributions.
type KindContribution struct {
	Kind  SignalKind
	Count int
	Score int // post-diminishing-returns contribution
}

// Score computes the Result for a snapshot of signals.
func (s *Scorer) Score(sigs []Signal) Result {
	if len(sigs) == 0 {
		return Result{}
	}
	// Group by kind to apply diminishing returns.
	byKind := map[SignalKind][]Signal{}
	for _, sig := range sigs {
		byKind[sig.Kind] = append(byKind[sig.Kind], sig)
	}

	total := 0
	contribs := make([]KindContribution, 0, len(byKind))
	for kind, ksigs := range byKind {
		kc := KindContribution{Kind: kind, Count: len(ksigs)}
		for i, sig := range ksigs {
			w := sig.Weight
			if w <= 0 {
				w = s.W[kind]
			}
			factor := dimFactor(i)
			kc.Score += scaleInt(w, factor)
		}
		total += kc.Score
		contribs = append(contribs, kc)
	}

	// P-PS.22: apply co-occurrence bonuses BEFORE the final clamp.
	var bonuses []CoBonus
	for _, r := range s.CoRules {
		if b, ok := s.evalCoRule(r, byKind); ok {
			total += b
			bonuses = append(bonuses, CoBonus{RuleID: r.ID, Bonus: b})
		}
	}

	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}
	return Result{Score: total, Contributions: contribs, CoBonuses: bonuses}
}

// evalCoRule returns (bonus, true) if every kind in r.Need has at
// least one signal and the time delta between the earliest and
// latest contributing signal is within r.Window.
func (s *Scorer) evalCoRule(r ScorerCoRule, byKind map[SignalKind][]Signal) (int, bool) {
	var youngest, oldest time.Time
	for i, k := range r.Need {
		group := byKind[k]
		if len(group) == 0 {
			return 0, false
		}
		// Use the most-recent observation for this kind as the
		// rule's contributing timestamp.
		newest := group[0].At
		earliest := group[0].At
		for _, sig := range group[1:] {
			if sig.At.After(newest) {
				newest = sig.At
			}
			if sig.At.Before(earliest) {
				earliest = sig.At
			}
		}
		if i == 0 {
			youngest = newest
			oldest = earliest
			continue
		}
		if newest.After(youngest) {
			youngest = newest
		}
		if earliest.Before(oldest) {
			oldest = earliest
		}
	}
	if r.Window > 0 && youngest.Sub(oldest) > r.Window {
		return 0, false
	}
	return r.Bonus, true
}

// dimFactor returns the diminishing-returns multiplier (0..1)
// expressed as percent-times-100 so we can do integer math.
//
//	idx 0 → 100  (full weight)
//	idx 1 → 50
//	idx 2 → 25
//	idx ≥ 3 → 10
func dimFactor(idx int) int {
	switch idx {
	case 0:
		return 100
	case 1:
		return 50
	case 2:
		return 25
	}
	return 10
}

// scaleInt computes weight × factorPct / 100, rounding to nearest.
func scaleInt(weight, factorPct int) int {
	return (weight*factorPct + 50) / 100
}
