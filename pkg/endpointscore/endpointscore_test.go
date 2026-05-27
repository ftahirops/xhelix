package endpointscore

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/sourcescore"
)

func TestScore_EmptyTokensIsZero(t *testing.T) {
	s := Score(DefaultChains(), nil, time.Now())
	if s.Score != 0 {
		t.Errorf("empty=%d want 0", s.Score)
	}
	if s.Chain != "" {
		t.Errorf("chain=%q want empty", s.Chain)
	}
}

func TestScore_FullChainHits(t *testing.T) {
	// Ransomware: discovery + encryption_burst → MaxBase=90
	s := Score(DefaultChains(),
		[]sourcescore.Token{"asset_discovery", "encryption_burst"},
		time.Now())
	if s.Chain != "ransomware" {
		t.Errorf("chain=%q want ransomware", s.Chain)
	}
	if s.Score != 90 {
		t.Errorf("score=%d want 90", s.Score)
	}
}

func TestScore_OptionalBonusApplied(t *testing.T) {
	// Ransomware + data_destruction optional (+5) → 95
	s := Score(DefaultChains(),
		[]sourcescore.Token{"asset_discovery", "encryption_burst", "data_destruction"},
		time.Now())
	if s.Score != 95 {
		t.Errorf("score=%d want 95 (base 90 + 5 optional)", s.Score)
	}
}

func TestScore_PartialChainCredit(t *testing.T) {
	// Only one of two ransomware requireds → 30% of 90 = 27
	s := Score(DefaultChains(),
		[]sourcescore.Token{"asset_discovery"},
		time.Now())
	// One of the chains should show partial; max should be > 0.
	if s.Score == 0 {
		t.Errorf("partial credit should be > 0")
	}
	if s.Score > 50 {
		t.Errorf("partial credit should not exceed 30%%; got %d", s.Score)
	}
}

func TestScore_PicksMaxChain(t *testing.T) {
	// Tokens hit two chains: c2_lateral (3 reqs) and persistence (2 reqs).
	// c2_lateral MaxBase=80, persistence MaxBase=65. Max should win.
	s := Score(DefaultChains(), []sourcescore.Token{
		"c2_beacon", "cred_access", "lateral_attempt",
		"shell_spawn", "persistence",
	}, time.Now())
	if s.Chain != "c2_lateral" {
		t.Errorf("chain=%q want c2_lateral", s.Chain)
	}
}

func TestScore_CapsAt100(t *testing.T) {
	// Ransomware + every optional → would exceed 100 without cap.
	toks := []sourcescore.Token{
		"asset_discovery", "encryption_burst",
		"data_destruction", "shadow_read",
	}
	s := Score(DefaultChains(), toks, time.Now())
	if s.Score > 100 {
		t.Errorf("score not capped: %d", s.Score)
	}
}

func TestEngine_PullsFromTracker(t *testing.T) {
	tr := sourcescore.NewTracker()
	tr.Add("src-1", "asset_discovery")
	tr.Add("src-2", "encryption_burst")
	e := NewEngine(tr, nil)
	es := e.Evaluate(time.Now())
	if es.Chain != "ransomware" {
		t.Errorf("chain=%q want ransomware (cross-source union)", es.Chain)
	}
}

func TestEngine_NilSafe(t *testing.T) {
	var e *Engine
	es := e.Evaluate(time.Now())
	if es.Score != 0 {
		t.Errorf("nil engine score=%d want 0", es.Score)
	}
}

func TestScore_SeverityBands(t *testing.T) {
	// Persistence partial (one of two reqs): score ~30% of 65 = 19.5 → 19
	// → Severity Info (below 20)
	s := Score(DefaultChains(), []sourcescore.Token{"shell_spawn"}, time.Now())
	if s.Severity != sourcescore.SeverityInfo && s.Severity != sourcescore.SeverityWarn {
		t.Errorf("severity=%q for score %d", s.Severity, s.Score)
	}
	// Full ransomware → critical
	s2 := Score(DefaultChains(),
		[]sourcescore.Token{"asset_discovery", "encryption_burst"},
		time.Now())
	if s2.Severity != sourcescore.SeverityCritical {
		t.Errorf("ransomware full severity=%q want critical", s2.Severity)
	}
}
