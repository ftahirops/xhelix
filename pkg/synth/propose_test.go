package synth

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xhelix/xhelix/pkg/brp"
	"github.com/xhelix/xhelix/pkg/contractpropose"
	"github.com/xhelix/xhelix/pkg/recorder"
)

func TestPropose_FilesPendingProposalWithProfileJSON(t *testing.T) {
	r := fakeReader{
		shapes: []recorder.ShapeRow{{AppID: "shop", ShapeHash: "s1", Count: 7}},
		byKey: map[string]map[recorder.EdgeKind]map[string][]string{
			"s1": {recorder.EdgeExec: {"php": {"/usr/bin/php"}}},
		},
	}
	store, err := contractpropose.Open(filepath.Join(t.TempDir(), "prop.db"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := Propose(r, store, "shop", 3, 1) // minSamples=1 → gate off
	if err != nil {
		t.Fatal(err)
	}
	if p.App != "shop" || p.Status != contractpropose.StatusPending {
		t.Errorf("proposal meta wrong: %+v", p)
	}
	var prof brp.Profile
	if err := json.Unmarshal(p.DeclarationJSON, &prof); err != nil {
		t.Fatalf("DeclarationJSON not a Profile: %v", err)
	}
	if prof.Confidence != brp.ConfidenceUnprofiled || len(prof.Behavior.ExecAllowed) != 1 {
		t.Errorf("embedded profile wrong: %+v", prof)
	}
}

func TestPropose_NoShapesReturnsErrNoData(t *testing.T) {
	store, _ := contractpropose.Open(filepath.Join(t.TempDir(), "p.db"))
	_, err := Propose(fakeReader{}, store, "ghost", 3, 5)
	if err != ErrNoData {
		t.Errorf("want ErrNoData for app with no shapes, got %v", err)
	}
}

func TestPropose_BelowSampleGateReturnsErrInsufficientSamples(t *testing.T) {
	// App observed only twice (Count: 2) with a minSamples gate of 5 → no file.
	r := fakeReader{
		shapes: []recorder.ShapeRow{{AppID: "thin", ShapeHash: "s1", Count: 2}},
		byKey: map[string]map[recorder.EdgeKind]map[string][]string{
			"s1": {recorder.EdgeExec: {"x": {"/usr/bin/x"}}},
		},
	}
	store, _ := contractpropose.Open(filepath.Join(t.TempDir(), "p.db"))
	if _, err := Propose(r, store, "thin", 3, 5); err != ErrInsufficientSamples {
		t.Errorf("want ErrInsufficientSamples (count 2 < gate 5), got %v", err)
	}
	// At/above the gate it files normally.
	r.shapes[0].Count = 5
	if _, err := Propose(r, store, "thin", 3, 5); err != nil {
		t.Errorf("count 5 == gate 5 should file, got %v", err)
	}
}
