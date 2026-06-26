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
	p, err := Propose(r, store, "shop", 3)
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
	_, err := Propose(fakeReader{}, store, "ghost", 3)
	if err != ErrNoData {
		t.Errorf("want ErrNoData for app with no shapes, got %v", err)
	}
}
