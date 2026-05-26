package verify

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/brp"
)

func TestPhaseCorrelation_AllPhases(t *testing.T) {
	pc := PhaseCorrelation{}
	cases := map[string]float64{
		"bootstrap": -1.5,
		"reload":    -1.0,
		"steady":    0,
		"degraded":  2.0,
		"":          0,
		"unknown":   0,
	}
	for phase, want := range cases {
		got, _ := pc.Score(Input{Phase: phase})
		if got != want {
			t.Errorf("PhaseCorrelation(%q) = %.1f, want %.1f", phase, got, want)
		}
	}
}

func TestSourceLineage_OperatorAnchorLenient(t *testing.T) {
	sl := SourceLineage{}
	for _, kind := range []string{"pam", "sudo", "su", "ssh", "sshd"} {
		got, _ := sl.Score(Input{SourceAnchorID: 42, AnchorKind: kind})
		if got != -2.0 {
			t.Errorf("operator anchor %q: got %.1f, want -2.0", kind, got)
		}
	}
}

func TestSourceLineage_HostAnchored(t *testing.T) {
	got, _ := SourceLineage{}.Score(Input{SourceAnchorID: 1, AnchorKind: "host"})
	if got != 1.0 {
		t.Errorf("host anchor: got %.1f, want 1.0", got)
	}
}

func TestSourceLineage_NoAnchor(t *testing.T) {
	got, _ := SourceLineage{}.Score(Input{})
	if got != 0 {
		t.Errorf("no anchor: got %.1f, want 0", got)
	}
}

func TestIntegrityHash_AuthenticReducesScore(t *testing.T) {
	got, _ := IntegrityHash{}.Score(Input{IntegrityAuthentic: true})
	if got != -3.0 {
		t.Errorf("authentic: got %.1f, want -3", got)
	}
}

func TestBehaviorHistory_KnownReducesScore(t *testing.T) {
	got, _ := BehaviorHistory{}.Score(Input{BaselineKnown: true})
	if got != -2.0 {
		t.Errorf("known: got %.1f, want -2", got)
	}
}

func TestNetworkNovelty_OnlyFiresOnNetConnect(t *testing.T) {
	got, _ := NetworkNovelty{}.Score(Input{
		Facts:     brp.EventFacts{Action: "file_write"},
		DestClass: "novel_external",
	})
	if got != 0 {
		t.Errorf("file_write should not score: got %.1f", got)
	}
}

func TestNetworkNovelty_NovelExternal(t *testing.T) {
	got, _ := NetworkNovelty{}.Score(Input{
		Facts:     brp.EventFacts{Action: "net_connect"},
		DestClass: "novel_external",
	})
	if got != 2.0 {
		t.Errorf("novel_external: got %.1f, want 2", got)
	}
}

func TestJITAttenuation_Allowlisted(t *testing.T) {
	got, _ := JITAttenuation{}.Score(Input{JITAllowlisted: true})
	if got != -1.0 {
		t.Errorf("JIT allowlisted: got %.1f, want -1", got)
	}
}

func TestCrossApp_KnownGoodEdge(t *testing.T) {
	got, _ := CrossApp{}.Score(Input{ActorApp: "nginx", TargetApp: "php-fpm"})
	if got != -1.5 {
		t.Errorf("nginx→php-fpm: got %.2f, want -1.5", got)
	}
}

func TestCrossApp_WebTierShellOut(t *testing.T) {
	got, reason := CrossApp{}.Score(Input{ActorApp: "nginx", TargetApp: "sh"})
	if got != 3.0 {
		t.Errorf("nginx→sh: got %.2f, want 3.0 (reason: %s)", got, reason)
	}
}

func TestCrossApp_DBTierShellOut(t *testing.T) {
	got, _ := CrossApp{}.Score(Input{ActorApp: "mysql", TargetApp: "bash"})
	if got != 3.0 {
		t.Errorf("mysql→bash: got %.2f, want 3.0", got)
	}
}

func TestCrossApp_UnknownEdgeFromKnownActor(t *testing.T) {
	got, _ := CrossApp{}.Score(Input{ActorApp: "nginx", TargetApp: "weirdservice"})
	if got != 0.5 {
		t.Errorf("nginx→weirdservice: got %.2f, want 0.5", got)
	}
}

func TestCrossApp_BothUnknownNoSignal(t *testing.T) {
	got, _ := CrossApp{}.Score(Input{ActorApp: "unknown", TargetApp: "alsounknown"})
	if got != 0 {
		t.Errorf("unknown→unknown: got %.2f, want 0", got)
	}
}

func TestCrossApp_MissingFieldNoSignal(t *testing.T) {
	got, _ := CrossApp{}.Score(Input{ActorApp: "nginx"}) // no target
	if got != 0 {
		t.Errorf("missing target: got %.2f, want 0", got)
	}
}

// Integration: full engine with all 8 domains
func TestEngine_FullStack_AuthenticUpgradeOfShadow(t *testing.T) {
	// dpkg writing /etc/shadow as part of an authentic upgrade:
	//   path_classifier: +5 (credential backbone)
	//   integrity_hash: -3 (authentic upgrade)
	//   behavior_history: -2 (known baseline)
	//   total: 0 → benign
	e := NewEngine()
	r := e.Evaluate(Input{
		Facts:              brp.EventFacts{Action: "file_write", Path: "/etc/shadow"},
		IntegrityAuthentic: true,
		BaselineKnown:      true,
	})
	if r.Outcome != OutcomeBenign {
		t.Errorf("authentic dpkg of /etc/shadow: outcome=%s score=%.2f, want benign",
			r.Outcome, r.Score)
	}
}

func TestEngine_FullStack_UnattributedShadowStillPromotes(t *testing.T) {
	// Unattributed write to /etc/shadow — nothing attenuates → promote.
	e := NewEngine()
	r := e.Evaluate(Input{
		Facts: brp.EventFacts{Action: "file_write", Path: "/etc/shadow"},
	})
	if r.Outcome != OutcomePromote {
		t.Errorf("unattributed /etc/shadow: outcome=%s score=%.2f, want promote",
			r.Outcome, r.Score)
	}
}

func TestEngine_FullStack_OperatorAnchoredCronEntry(t *testing.T) {
	// Cron entry write from an interactive sudo session — operator
	// definitely doing maintenance, not an attack.
	//   path_classifier: +3 (service/persistence)
	//   source_lineage: -2 (sudo anchor)
	//   phase: bootstrap → -1.5
	//   total: -0.5 → benign
	e := NewEngine()
	r := e.Evaluate(Input{
		Facts:          brp.EventFacts{Action: "file_write", Path: "/etc/cron.d/maint"},
		SourceAnchorID: 100,
		AnchorKind:     "sudo",
		Phase:          "bootstrap",
	})
	if r.Outcome != OutcomeBenign {
		t.Errorf("operator-anchored cron entry: outcome=%s score=%.2f, want benign",
			r.Outcome, r.Score)
	}
}

func TestEngine_FullStack_DegradedHostAnchoredShadow(t *testing.T) {
	// Worst case: writes /etc/shadow, no operator anchor, recent crash.
	//   path_classifier: +5
	//   phase: degraded → +2
	//   source_lineage: host → +1
	//   total: +8 → promote
	e := NewEngine()
	r := e.Evaluate(Input{
		Facts:          brp.EventFacts{Action: "file_write", Path: "/etc/shadow"},
		Phase:          "degraded",
		SourceAnchorID: 1,
		AnchorKind:     "host",
	})
	if r.Outcome != OutcomePromote {
		t.Errorf("degraded+host+shadow: outcome=%s, want promote", r.Outcome)
	}
	if r.Score < 6 {
		t.Errorf("expected high score, got %.2f", r.Score)
	}
}
