package main

import (
	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/egressrefresh"
)

// registryUnitSource adapts the app registry to egressrefresh.UnitSource:
// it yields one Unit per service that opted into EgressDefaultDeny AND
// declared FQDNs (services with only static CIDRs need no re-resolution).
type registryUnitSource struct{ reg *appregistry.Registry }

func (s registryUnitSource) Units() []egressrefresh.Unit {
	if s.reg == nil {
		return nil
	}
	apps, err := s.reg.List()
	if err != nil {
		return nil
	}
	return unitsFromApps(apps)
}

// unitsFromApps is the pure mapping (split out for testing).
func unitsFromApps(apps []appregistry.App) []egressrefresh.Unit {
	var out []egressrefresh.Unit
	for _, app := range apps {
		for _, svc := range app.Services {
			if !svc.EgressDefaultDeny || len(svc.EgressAllowFQDNs) == 0 {
				continue
			}
			unit := svc.UnitName
			if unit == "" {
				unit = svc.Name
			}
			out = append(out, egressrefresh.Unit{
				Name:        unit,
				StaticCIDRs: append([]string(nil), svc.EgressAllowCIDRs...),
				FQDNs:       append([]string(nil), svc.EgressAllowFQDNs...),
			})
		}
	}
	return out
}
