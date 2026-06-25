package workflowchain

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
)

func TestCompute_WebRequest_Learnable(t *testing.T) {
	in := Inputs{
		AppID:            "shop:site-a.com",
		RootID:           7,
		RootType:         lineage.RootWeb,
		RequestID:        "req-abc",
		AdminShell:       false,
		RedZone:          false,
		RecordWindowOpen: true,
	}
	got := Compute(in)

	if got.ChainID == "" {
		t.Fatal("ChainID must be non-empty")
	}
	if got.RootID != "7" {
		t.Errorf("RootID = %q, want \"7\"", got.RootID)
	}
	if got.RootType != "web" {
		t.Errorf("RootType = %q, want \"web\"", got.RootType)
	}
	if got.Phase != "request" {
		t.Errorf("Phase = %q, want \"request\"", got.Phase)
	}
	if got.Fidelity != "precise" {
		t.Errorf("Fidelity = %q, want \"precise\" (request_id present)", got.Fidelity)
	}
	if !got.Learnable {
		t.Error("Learnable must be true: app_scoped + chain_scoped + record window + no red zone + not admin")
	}
}

func TestCompute_ChainID_StableAndRequestSensitive(t *testing.T) {
	base := Inputs{AppID: "a", RootID: 7, RootType: lineage.RootWeb, RecordWindowOpen: true}

	a := Compute(base)
	b := Compute(base) // identical inputs → identical id
	if a.ChainID != b.ChainID {
		t.Error("ChainID must be deterministic for identical inputs")
	}

	withReq := base
	withReq.RequestID = "req-1"
	c := Compute(withReq)
	if c.ChainID == a.ChainID {
		t.Error("ChainID must differ when a request_id splits the workflow")
	}

	withReq2 := base
	withReq2.RequestID = "req-2"
	if Compute(withReq2).ChainID == c.ChainID {
		t.Error("Different request_ids must yield different chain_ids")
	}
}

func TestCompute_LineageFallback_NoRequestID(t *testing.T) {
	// No request/job id → lineage-granular: fidelity coarse, chain bound to root only.
	in := Inputs{AppID: "a", RootID: 42, RootType: lineage.RootCron, RecordWindowOpen: true}
	got := Compute(in)
	if got.Fidelity != "coarse" {
		t.Errorf("Fidelity = %q, want \"coarse\"", got.Fidelity)
	}
	if got.Phase != "job" {
		t.Errorf("Phase = %q, want \"job\"", got.Phase)
	}
}

func TestCompute_Learnable_FalseCases(t *testing.T) {
	ok := Inputs{AppID: "a", RootID: 7, RootType: lineage.RootWeb, RecordWindowOpen: true}
	if !Compute(ok).Learnable {
		t.Fatal("baseline must be learnable")
	}
	cases := map[string]func(*Inputs){
		"no app boundary":   func(i *Inputs) { i.AppID = "" },
		"no chain root":     func(i *Inputs) { i.RootID = 0 },
		"red zone":          func(i *Inputs) { i.RedZone = true },
		"admin shell noise": func(i *Inputs) { i.AdminShell = true },
		"record closed":     func(i *Inputs) { i.RecordWindowOpen = false },
	}
	for name, mut := range cases {
		in := ok
		mut(&in)
		if Compute(in).Learnable {
			t.Errorf("%s: Learnable must be false", name)
		}
	}
}

func TestResult_Apply_WritesExpectedTags(t *testing.T) {
	r := Result{
		ChainID: "deadbeef", RootID: "7", RootType: "web",
		RequestID: "req-1", Phase: "request", Learnable: true, Fidelity: "precise",
	}
	tags := map[string]string{"app_id": "shop"}
	r.Apply(tags)

	want := map[string]string{
		"chain_id":   "deadbeef",
		"root_id":    "7",
		"root_type":  "web",
		"request_id": "req-1",
		"phase":      "request",
		"learnable":  "true",
		"fidelity":   "precise",
		"app_id":     "shop", // untouched
	}
	for k, v := range want {
		if tags[k] != v {
			t.Errorf("tags[%q] = %q, want %q", k, tags[k], v)
		}
	}
	if _, ok := tags["job_id"]; ok {
		t.Error("empty job_id must not be written")
	}
}

func TestResult_Apply_NilMapIsNoOp(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Apply on nil map must not panic: %v", r)
		}
	}()
	Result{ChainID: "x"}.Apply(nil)
}
