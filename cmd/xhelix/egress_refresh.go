package main

import (
	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/egressrefresh"
)

// registryUnitSource adapts the app registry to egressrefresh.UnitSource:
// it yields one Unit per service that opted into EgressDefaultDeny and either
// declared FQDNs or set EgressLive. Live services are tracked even when they
// have only static CIDRs (so their 51- drop-in is maintained); non-live
// static-CIDR-only services need no re-resolution and are skipped.
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
			if !svc.EgressDefaultDeny {
				continue
			}
			if len(svc.EgressAllowFQDNs) == 0 && !svc.EgressLive {
				continue // static-CIDR-only non-live services need no refresh
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
