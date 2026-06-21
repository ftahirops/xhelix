package contractcompiler

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/redzones"
)

func TestCompileCarriesEgress(t *testing.T) {
	app := appregistry.App{
		Name: "shop",
		Services: []appregistry.Service{{
			Name:              "nginx",
			UnitName:          "nginx.service",
			ServiceType:       appregistry.ServiceType("nginx"),
			EgressDefaultDeny: true,
			EgressAllowCIDRs:  []string{"10.0.0.0/8"},
		}},
	}
	cc := Compile(app, redzones.Default())
	if len(cc.Services) != 1 {
		t.Fatalf("want 1 service, got %d", len(cc.Services))
	}
	cs := cc.Services[0]
	if !cs.EgressDefaultDeny {
		t.Error("EgressDefaultDeny not carried to CompiledService")
	}
	if len(cs.EgressAllowCIDRs) != 1 || cs.EgressAllowCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("EgressAllowCIDRs not carried: %v", cs.EgressAllowCIDRs)
	}
}

func TestCompileEgressDefaultsOff(t *testing.T) {
	app := appregistry.App{
		Name:     "shop",
		Services: []appregistry.Service{{Name: "nginx", UnitName: "nginx.service"}},
	}
	cc := Compile(app, redzones.Default())
	if cc.Services[0].EgressDefaultDeny {
		t.Error("egress must default off when not declared")
	}
}
