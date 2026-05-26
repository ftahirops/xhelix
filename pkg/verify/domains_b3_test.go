package verify

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/brp"
)

// ──────────────────────────────────────────────────────────────────
// SecretContext domain tests
// ──────────────────────────────────────────────────────────────────

func TestSecretContext_CleanLineageIsZero(t *testing.T) {
	s, _ := SecretContext{}.Score(Input{})
	if s != 0 {
		t.Errorf("clean: got %v, want 0", s)
	}
}

func TestSecretContext_SecretTouchedBase(t *testing.T) {
	s, reason := SecretContext{}.Score(Input{
		SecretTaint: "secret_touched",
	})
	if s != 1.0 {
		t.Errorf("secret_touched base: got %v, want 1.0", s)
	}
	if !strings.Contains(reason, "touched secrets") {
		t.Errorf("reason: %q", reason)
	}
}

func TestSecretContext_ContainmentRequiredHigh(t *testing.T) {
	s, _ := SecretContext{}.Score(Input{
		SecretTaint: "containment_required",
	})
	if s != 5.0 {
		t.Errorf("containment_required: got %v, want 5.0", s)
	}
}

func TestSecretContext_MetadataClassBoost(t *testing.T) {
	// secret_touched (1.0) + metadata class (2.0) = 3.0
	s, _ := SecretContext{}.Score(Input{
		SecretTaint:   "secret_touched",
		SecretClasses: []string{"metadata"},
	})
	if s != 3.0 {
		t.Errorf("metadata-class boost: got %v, want 3.0", s)
	}
}

func TestSecretContext_MultipleClassesCapped(t *testing.T) {
	// metadata + cloud_creds + kube_token = 2.0 + 1.5 + 1.5 = 5.0, capped to 4.0
	// + state secret_touched (1.0) = 5.0
	s, _ := SecretContext{}.Score(Input{
		SecretTaint:   "secret_touched",
		SecretClasses: []string{"metadata", "cloud_creds", "kube_token"},
	})
	if s != 5.0 {
		t.Errorf("multiple classes capped: got %v, want 5.0", s)
	}
}

func TestSecretContext_OutboundAfterTouchChain(t *testing.T) {
	// outbound_restricted (2.5) + class metadata (2.0) + net_connect (1.5) = 6.0
	s, reason := SecretContext{}.Score(Input{
		SecretTaint:   "outbound_restricted",
		SecretClasses: []string{"metadata"},
		Facts:         brp.EventFacts{Action: "net_connect"},
	})
	if s != 6.0 {
		t.Errorf("outbound chain: got %v, want 6.0", s)
	}
	if !strings.Contains(reason, "outbound after secret touch") {
		t.Errorf("reason missing chain marker: %q", reason)
	}
}

func TestSecretContext_PersistenceAfterTouchChain(t *testing.T) {
	// containment_required (5.0) + secret_file (1.0) + persistence write (2.0) = 8.0 (cap)
	s, _ := SecretContext{}.Score(Input{
		SecretTaint:   "containment_required",
		SecretClasses: []string{"secret_file"},
		Facts:         brp.EventFacts{Action: "file_write", Path: "/etc/cron.d/.implant"},
	})
	if s != 8.0 {
		t.Errorf("persistence chain capped at 8.0: got %v", s)
	}
}

// ──────────────────────────────────────────────────────────────────
// AssetContext domain tests
// ──────────────────────────────────────────────────────────────────

func TestAssetContext_NoClassIsZero(t *testing.T) {
	s, _ := AssetContext{}.Score(Input{})
	if s != 0 {
		t.Errorf("empty class: %v", s)
	}
}

func TestAssetContext_SecretFileHighestWeight(t *testing.T) {
	s, _ := AssetContext{}.Score(Input{AssetClass: "secret_file"})
	if s != 5.0 {
		t.Errorf("secret_file: got %v, want 5.0", s)
	}
}

func TestAssetContext_MetadataHighestWeight(t *testing.T) {
	s, _ := AssetContext{}.Score(Input{AssetClass: "metadata_endpoint"})
	if s != 5.0 {
		t.Errorf("metadata_endpoint: got %v, want 5.0", s)
	}
}

func TestAssetContext_PersistenceWeight(t *testing.T) {
	s, _ := AssetContext{}.Score(Input{AssetClass: "persistence_surface"})
	if s != 3.0 {
		t.Errorf("persistence_surface: got %v, want 3.0", s)
	}
}

func TestAssetContext_BenignClassesAreZero(t *testing.T) {
	for _, c := range []string{"config", "log_sink", "cache", "temp"} {
		s, _ := AssetContext{}.Score(Input{AssetClass: c})
		if s != 0 {
			t.Errorf("class %q should be benign, got %v", c, s)
		}
	}
}

func TestAssetContext_UnknownClassIsZero(t *testing.T) {
	s, _ := AssetContext{}.Score(Input{AssetClass: "made_up_class"})
	if s != 0 {
		t.Errorf("unknown class: %v", s)
	}
}

// ──────────────────────────────────────────────────────────────────
// End-to-end attack-chain test through the verifier engine
// ──────────────────────────────────────────────────────────────────

// TestB3_FullChainPromotion exercises the canonical secret-theft chain
// through the verifier engine end-to-end:
//
//   1. lineage touched metadata (secret_taint=secret_touched, class=metadata)
//   2. now attempts net_connect to a novel external destination
//   3. target is an external_api_peer (asset class)
//
// Expected: combined score >= HighThreshold (4.0) → OutcomePromote.
func TestB3_FullChainPromotion(t *testing.T) {
	e := NewEngine()
	r := e.Evaluate(Input{
		Facts: brp.EventFacts{
			Action:   "net_connect",
			DestHost: "evil.example.com",
			DestPort: 443,
		},
		SecretTaint:   "secret_touched",
		SecretClasses: []string{"metadata"},
		AssetClass:    "external_api_peer",
		DestClass:     "novel_external",
		Phase:         "steady",
	})
	if r.Outcome != OutcomePromote {
		t.Errorf("expected promote, got %s (score=%v)", r.Outcome, r.Score)
	}
	if r.Score < e.HighThreshold {
		t.Errorf("score %v below HighThreshold %v", r.Score, e.HighThreshold)
	}
}

// TestB3_AuthenticatedAdminLineageStaysBenign verifies that the same
// "touched secrets + outbound" pattern, when corroborated by integrity
// authentic + baseline known + operator anchor, does NOT promote —
// because legitimate admin maintenance should attenuate.
func TestB3_AuthenticatedAdminLineageStaysBenign(t *testing.T) {
	e := NewEngine()
	r := e.Evaluate(Input{
		Facts: brp.EventFacts{
			Action:   "net_connect",
			DestHost: "iam.amazonaws.com",
			DestPort: 443,
		},
		SecretTaint:        "secret_touched",
		SecretClasses:      []string{"cloud_creds"},
		AssetClass:         "identity_provider",
		DestClass:          "known_upstream",
		IntegrityAuthentic: true,
		BaselineKnown:      true,
		SourceAnchorID:     42,
		AnchorKind:         "sudo",
		Phase:              "steady",
	})
	// secret_touched(1.0) + cloud_creds(1.5) + outbound(1.5) = 4.0 from SecretContext
	// + asset identity_provider(0.5)
	// + network known_upstream(-1.0)
	// + integrity authentic(-3.0)
	// + baseline known(-2.0)
	// + source operator sudo(-2.0)
	// = -2.0 → benign
	if r.Outcome != OutcomeBenign {
		t.Errorf("legitimate admin: outcome=%s score=%v (want benign)", r.Outcome, r.Score)
	}
}

// TestB3_CleanLineageReadingSecret confirms the verifier's first contact
// with a secret-tier asset class promotes even before any taint exists.
// (The pipeline observes the touch on the SAME event; PathClassifier
// already exists as a separate weight. AssetContext should fire too.)
func TestB3_CleanLineageReadingSecret(t *testing.T) {
	e := NewEngine()
	r := e.Evaluate(Input{
		Facts: brp.EventFacts{
			Action: "file_open",
			Path:   "/etc/shadow",
			Mode:   "read",
		},
		AssetClass: "secret_file",
		// SecretTaint empty — this is the first contact event
	})
	// PathClassifier doesn't score reads (only writes), so this rests on
	// AssetContext (+5) — that alone meets HighThreshold (4.0) → promote.
	if r.Outcome != OutcomePromote {
		t.Errorf("first-contact secret read: outcome=%s score=%v", r.Outcome, r.Score)
	}
}
