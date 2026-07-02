package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/brp"
	parser "github.com/xhelix/xhelix/pkg/brp/parser"
	"github.com/xhelix/xhelix/pkg/contractpropose"
)

// TestPromoteProposal_SignsInstallsApproves is the auto-promote end-to-end:
// a pending proposal is signed with the operator key, installed as a
// *.signed.json that verifies against the operator's public key, and the
// proposal is marked approved.
func TestPromoteProposal_SignsInstallsApproves(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	dir := t.TempDir()
	store, err := contractpropose.Open(filepath.Join(dir, "contract-propose.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	prof := brp.Profile{
		ProfileID:  "brp-testapp-v1",
		Confidence: brp.ConfidenceConstrainedAdaptation,
		Key:        parser.ProfileKey{App: "testapp"},
	}
	js, err := json.Marshal(prof)
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.Create(contractpropose.Proposal{
		App:             "testapp",
		Submitter:       "synthesizer",
		DeclarationJSON: js,
	})
	if err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "brp")
	dst, err := promoteProposal(store, "testapp", p.ID, priv, "ops-local", outDir, false)
	if err != nil {
		t.Fatalf("promoteProposal: %v", err)
	}

	// Installed file verifies against the operator public key.
	sp, err := brp.LoadSigned(dst)
	if err != nil {
		t.Fatalf("load installed profile: %v", err)
	}
	if err := brp.Verify(sp, pub); err != nil {
		t.Errorf("installed profile does not verify against operator key: %v", err)
	}
	if sp.Signer != "ops-local" {
		t.Errorf("signer = %q, want ops-local", sp.Signer)
	}

	// Proposal is now approved.
	got, ok := store.Get("testapp", p.ID)
	if !ok || got.Status != contractpropose.StatusApproved {
		t.Errorf("proposal status = %v (ok=%v), want approved", got.Status, ok)
	}

	// Re-promoting without --force refuses to clobber the installed file.
	if _, err := promoteProposal(store, "testapp", p.ID, priv, "ops-local", outDir, false); err == nil {
		t.Error("expected refusal to overwrite existing signed profile without force")
	}
}

func TestRenderProposalList_ShowsIDStatusReason(t *testing.T) {
	out := renderProposalList([]contractpropose.Proposal{
		{ID: "p1", App: "shop", Status: contractpropose.StatusPending, Reason: "synthesized from 42 observations", CreatedAt: time.Unix(1_700_000_000, 0)},
	})
	for _, want := range []string{"p1", "shop", "pending", "42 observations"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered list missing %q\n%s", want, out)
		}
	}
}
