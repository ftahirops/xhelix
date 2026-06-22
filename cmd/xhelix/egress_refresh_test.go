package main

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/appregistry"
)

func TestRegistryUnitSourceFiltersOptedIn(t *testing.T) {
	apps := []appregistry.App{{
		Name: "shop",
		Services: []appregistry.Service{
			{UnitName: "nginx.service", EgressDefaultDeny: true,
				EgressAllowCIDRs: []string{"10.0.0.0/8"}, EgressAllowFQDNs: []string{"api.example.com"}},
			{UnitName: "side.service", EgressDefaultDeny: false, EgressAllowFQDNs: []string{"x.example.com"}},
			{UnitName: "nofqdn.service", EgressDefaultDeny: true},
		},
	}}
	units := unitsFromApps(apps)
	if len(units) != 1 {
		t.Fatalf("want 1 opted-in+fqdn unit, got %d: %+v", len(units), units)
	}
	if units[0].Name != "nginx.service" || len(units[0].FQDNs) != 1 {
		t.Errorf("wrong unit mapped: %+v", units[0])
	}
}
