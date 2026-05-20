package takeover

// Scorer turns a list of Signals into a 0-100 composite score plus a
// per-kind contribution breakdown for explainability.
//
// Algorithm (matches FULL_TAKEOVER_DETECTION.md §4.2):
//
//  score = clamp(Σ effective_weight(signal), 0, 100)
//
//  effective_weight(s) = s.Weight if s.Weight > 0 else Weights[s.Kind]
//
// Same-kind signals diminish: the 1st gets full weight, the 2nd
// gets 50%, the 3rd gets 25%, the rest 10% each. Prevents one noisy
// sensor from saturating the score on its own — composition rule
// from BEHAVIORAL_DEFENSE.md §5.
type Scorer struct {
	W Weights
}

// NewScorer returns a Scorer with the given weight table. Pass nil
// for DefaultWeights().
func NewScorer(w Weights) *Scorer {
	if w == nil {
		w = DefaultWeights()
	}
	return &Scorer{W: w}
}

// Result is the scorer's output: a composite score plus the
// per-kind contributions that produced it.
type Result struct {
	Score         int
	Contributions []KindContribution
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

	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}
	return Result{Score: total, Contributions: contribs}
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
