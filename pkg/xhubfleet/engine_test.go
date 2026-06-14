package xhubfleet

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/baselinehub"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(EngineConfig{
		Weights:      DefaultWeights(),
		Gates:        DefaultCandidateGates(),
		TrustPolicy:  DefaultTrustPolicy(),
		PublisherDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestEngine_Ingest_VerdictFeedback_QuarantinesOnCritical(t *testing.T) {
	e := newTestEngine(t)
	now := time.Now()
	host := "h-evil"
	u := baselinehub.Upload{
		HostTag:        host,
		VerdictSummary: &baselinehub.VerdictSummary{Critical: 1, Total: 1},
	}
	e.Ingest(u, now)
	if e.trust.CanTeach(host) {
		t.Fatal("a host reporting a critical verdict must NOT be allowed to teach")
	}
}

func TestEngine_Ingest_NilVerdictSummary_NoChange(t *testing.T) {
	e := newTestEngine(t)
	now := time.Now()
	u := baselinehub.Upload{HostTag: "h-quiet"} // VerdictSummary nil
	e.Ingest(u, now)                            // must not panic; See/Evaluate only
	if e.trust.Evaluate("h-quiet", now) == TrustQuarantined {
		t.Fatal("nil verdict summary must not quarantine")
	}
}
