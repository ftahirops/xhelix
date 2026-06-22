package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/contractcompiler"
)

type fakeEgressResolver map[string][]net.IP

func (f fakeEgressResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	ips, ok := f[host]
	if !ok || len(ips) == 0 {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

func TestResolveEgressFQDNsMergesIntoCIDRs(t *testing.T) {
	cc := &contractcompiler.CompiledContract{
		App: "shop",
		Services: []contractcompiler.CompiledService{{
			Unit:              "nginx.service",
			EgressDefaultDeny: true,
			EgressAllowCIDRs:  []string{"10.0.0.0/8"},
			EgressAllowFQDNs:  []string{"api.stripe.com"},
		}},
	}
	r := fakeEgressResolver{"api.stripe.com": {net.ParseIP("203.0.113.7")}}
	if err := resolveEgressFQDNs(context.Background(), r, cc); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	got := cc.Services[0].EgressAllowCIDRs
	has := func(c string) bool {
		for _, x := range got {
			if x == c {
				return true
			}
		}
		return false
	}
	if !has("10.0.0.0/8") || !has("203.0.113.7/32") {
		t.Errorf("merged CIDRs missing static or resolved entry: %v", got)
	}
}

func TestResolveEgressFQDNsSkipsNonOptedIn(t *testing.T) {
	cc := &contractcompiler.CompiledContract{
		App: "shop",
		Services: []contractcompiler.CompiledService{{
			Unit:              "nginx.service",
			EgressDefaultDeny: false, // not opted in
			EgressAllowFQDNs:  []string{"nope.example.com"},
		}},
	}
	if err := resolveEgressFQDNs(context.Background(), fakeEgressResolver{}, cc); err != nil {
		t.Fatalf("non-opted-in service must be skipped, got err: %v", err)
	}
}

func TestResolveEgressFQDNsFailsArmOnUnresolvable(t *testing.T) {
	cc := &contractcompiler.CompiledContract{
		App: "shop",
		Services: []contractcompiler.CompiledService{{
			Unit:              "nginx.service",
			EgressDefaultDeny: true,
			EgressAllowFQDNs:  []string{"nope.example.com"},
		}},
	}
	if err := resolveEgressFQDNs(context.Background(), fakeEgressResolver{}, cc); err == nil {
		t.Fatal("expected arm to fail when an FQDN is unresolvable")
	}
}

func TestSpecsForLiveServiceGetsFloorOnly(t *testing.T) {
	cc := &contractcompiler.CompiledContract{App: "shop", Services: []contractcompiler.CompiledService{{
		Unit: "nginx.service", EgressDefaultDeny: true, EgressLive: true,
		EgressAllowCIDRs: []string{"10.0.0.0/8"}, // must NOT appear in the arm drop-in
	}}}
	specs := specsFor(cc)
	d := specs[0].EgressDirective
	if !strings.Contains(d, "IPAddressDeny=any") || !strings.Contains(d, "localhost") {
		t.Fatalf("live service should still get the floor: %q", d)
	}
	if strings.Contains(d, "10.0.0.0/8") {
		t.Errorf("live service arm drop-in must NOT carry dynamic/static IPs (refresher owns them): %q", d)
	}
}
