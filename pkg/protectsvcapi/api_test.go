package protectsvcapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func loadReg(t *testing.T) *protectedsvc.Registry {
	t.Helper()
	c, _ := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleReverseProxy)
	reg := protectedsvc.NewRegistry()
	if err := reg.Load([]protectedsvc.ProtectedService{
		{
			Name: "nginx-main", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleReverseProxy,
			Unit: "nginx.service", ExecPath: "/usr/sbin/nginx",
			CgroupPrefix: "/system.slice/nginx.service",
			Contract:     c,
			Response: protectedsvc.ResponseProfile{
				Deception: protectedsvc.AllOn(),
			},
		},
		{
			Name: "nginx-static", Kind: protectedsvc.KindNginx, Role: protectedsvc.RoleStatic,
			Unit: "nginx-static.service", ExecPath: "/usr/sbin/nginx",
			CgroupPrefix: "/system.slice/nginx-static.service",
		},
	}); err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestHandleList_SortsAndCounts(t *testing.T) {
	a := &API{Reg: loadReg(t)}
	out, err := a.handleList(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	svcs := out.([]ServiceSummary)
	if len(svcs) != 2 {
		t.Fatalf("got %d services", len(svcs))
	}
	// Sorted alphabetically.
	if svcs[0].Name != "nginx-main" || svcs[1].Name != "nginx-static" {
		t.Fatalf("not sorted: %+v", svcs)
	}
	// Mode reflects deception state.
	if svcs[0].DeceptionMode != "trap" {
		t.Fatalf("nginx-main DeceptionMode=%q want trap", svcs[0].DeceptionMode)
	}
	if svcs[1].DeceptionMode != "off" {
		t.Fatalf("nginx-static DeceptionMode=%q want off", svcs[1].DeceptionMode)
	}
}

func TestHandleContract(t *testing.T) {
	a := &API{Reg: loadReg(t)}
	raw := json.RawMessage(`{"name":"nginx-main"}`)
	out, err := a.handleContract(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	cv := out.(ContractView)
	if cv.Name != "nginx-main" {
		t.Fatalf("Name=%q", cv.Name)
	}
	if cv.DenyExecCount == 0 {
		t.Fatal("DenyExecCount should be non-zero (built-in NeverLearnable list)")
	}
	if cv.DenySyscallCount == 0 {
		t.Fatal("DenySyscallCount should be non-zero")
	}
}

func TestHandleContract_NotFound(t *testing.T) {
	a := &API{Reg: loadReg(t)}
	raw := json.RawMessage(`{"name":"missing"}`)
	if _, err := a.handleContract(context.Background(), raw); err == nil {
		t.Fatal("missing service should error")
	}
}

func TestHandleDeceptionCoverage(t *testing.T) {
	a := &API{Reg: loadReg(t)}
	out, err := a.handleDeceptionCoverage(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	covs := out.([]DeceptionCoverage)
	if len(covs) != 2 {
		t.Fatalf("got %d coverages", len(covs))
	}
	for _, c := range covs {
		switch c.Name {
		case "nginx-main":
			if c.Score != 4 {
				t.Errorf("nginx-main Score=%d want 4", c.Score)
			}
		case "nginx-static":
			if c.Score != 0 {
				t.Errorf("nginx-static Score=%d want 0", c.Score)
			}
		}
	}
}

func TestHandleResidualRisk(t *testing.T) {
	a := &API{Reg: loadReg(t)}
	raw := json.RawMessage(`{"name":"nginx-static"}`)
	out, err := a.handleResidualRisk(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	rr := out.(ResidualRisk)
	if rr.Name != "nginx-static" {
		t.Fatal("name wrong")
	}
	// deception off → expect "deception (master switch)" in DisabledLayers
	found := false
	for _, l := range rr.DisabledLayers {
		if l == "deception (master switch)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected disabled master switch; got %v", rr.DisabledLayers)
	}
	// Notes should mention what we DON'T detect.
	if len(rr.Notes) == 0 {
		t.Fatal("Notes should warn about in-process exploitation")
	}
}

func TestHandleResidualRisk_AllOnHasFewerWarnings(t *testing.T) {
	a := &API{Reg: loadReg(t)}
	raw := json.RawMessage(`{"name":"nginx-main"}`)
	out, _ := a.handleResidualRisk(context.Background(), raw)
	rr := out.(ResidualRisk)
	if len(rr.DisabledLayers) != 0 {
		t.Fatalf("all-on service should have no disabled layers: %v", rr.DisabledLayers)
	}
}

func TestNilRegistry_AllHandlersError(t *testing.T) {
	a := &API{}
	if _, err := a.handleList(context.Background(), nil); err == nil {
		t.Fatal("nil reg → handleList should error")
	}
	if _, err := a.handleContract(context.Background(), json.RawMessage(`{"name":"x"}`)); err == nil {
		t.Fatal("nil reg → handleContract should error")
	}
	if _, err := a.handleDeceptionCoverage(context.Background(), nil); err == nil {
		t.Fatal("nil reg → handleDeceptionCoverage should error")
	}
	if _, err := a.handleResidualRisk(context.Background(), json.RawMessage(`{"name":"x"}`)); err == nil {
		t.Fatal("nil reg → handleResidualRisk should error")
	}
}
