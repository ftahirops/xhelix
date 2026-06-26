package synth

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/brp"
)

func TestBuildProfile_CandidateShape(t *testing.T) {
	o := Observed{
		App:         "shop",
		SampleCount: 42,
		ExecRaws:    []string{"/usr/bin/curl"},
		EgressKeys:  []string{"api.stripe.com:443"},
		WriteDirs:   map[string][]string{"/u/up": {"/u/up/a", "/u/up/b", "/u/up/c"}},
	}
	p := BuildProfile(o, 3)

	if p.Confidence != brp.ConfidenceUnprofiled {
		t.Errorf("synth profile must be ConfidenceUnprofiled, got %v", p.Confidence)
	}
	if p.SampleCount != 42 || p.Key.App != "shop" {
		t.Errorf("profile meta wrong: %+v", p)
	}
	if p.ProfileID != "synth-shop" {
		t.Errorf("ProfileID = %q", p.ProfileID)
	}
	if len(p.Behavior.ExecAllowed) != 1 || p.Behavior.ExecAllowed[0] != "/usr/bin/curl" {
		t.Errorf("ExecAllowed = %v", p.Behavior.ExecAllowed)
	}
	if len(p.Behavior.UpstreamHosts) != 1 || p.Behavior.UpstreamHosts[0] != "api.stripe.com" {
		t.Errorf("UpstreamHosts = %v", p.Behavior.UpstreamHosts)
	}
	if len(p.Behavior.WriteRoots) != 1 || p.Behavior.WriteRoots[0] != "/u/up/**" {
		t.Errorf("WriteRoots = %v", p.Behavior.WriteRoots)
	}
	if len(p.Behavior.ListenPorts) != 0 || len(p.Behavior.ReadRoots) != 0 {
		t.Error("ListenPorts/ReadRoots must be empty (not synthesizable)")
	}
	// The honesty note must be present.
	found := false
	for _, w := range p.Behavior.ParseWarnings {
		if w != "" {
			found = true
		}
	}
	if !found {
		t.Error("expected a ParseWarnings note about un-synthesizable dimensions")
	}
}
