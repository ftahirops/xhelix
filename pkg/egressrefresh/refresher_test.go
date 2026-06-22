package egressrefresh

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/egressresolve"
)

type fakeSource struct{ units []Unit }

func (f fakeSource) Units() []Unit { return f.units }

type fakeResolver map[string][]net.IP

func (f fakeResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	ips, ok := f[host]
	if !ok || len(ips) == 0 {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

var _ egressresolve.Resolver = fakeResolver{}

type recApplier struct {
	mu   sync.Mutex
	last map[string][]string
}

func newRecApplier() *recApplier { return &recApplier{last: map[string][]string{}} }
func (r *recApplier) Apply(unit string, cidrs []string) error {
	r.mu.Lock()
	r.last[unit] = append([]string(nil), cidrs...)
	r.mu.Unlock()
	return nil
}

func TestRefreshMergesStaticAndResolved(t *testing.T) {
	src := fakeSource{units: []Unit{{
		Name: "nginx.service", StaticCIDRs: []string{"10.0.0.0/8"}, FQDNs: []string{"api.example.com"},
	}}}
	res := fakeResolver{"api.example.com": {net.ParseIP("203.0.113.7")}}
	app := newRecApplier()
	r := New(src, res, app, 10*time.Minute)

	r.RefreshOnce(context.Background(), t0)

	got := app.last["nginx.service"]
	if !eq(got, []string{"10.0.0.0/8", "203.0.113.7/32"}) {
		t.Errorf("merged allow-set wrong: %v", got)
	}
}

func TestRefreshDoesNotShrinkOnResolveFailure(t *testing.T) {
	src := fakeSource{units: []Unit{{
		Name: "nginx.service", FQDNs: []string{"api.example.com"},
	}}}
	res := fakeResolver{"api.example.com": {net.ParseIP("203.0.113.7")}}
	app := newRecApplier()
	r := New(src, res, app, 10*time.Minute)

	r.RefreshOnce(context.Background(), t0) // resolves -> 203.0.113.7/32 tracked

	// Now DNS fails; 5 min later, within grace -> IP must persist.
	r2 := New(src, brokenResolver{}, app, 10*time.Minute)
	r2.tracker = r.tracker // share tracked state
	r2.RefreshOnce(context.Background(), t0.Add(5*time.Minute))

	got := app.last["nginx.service"]
	if !eq(got, []string{"203.0.113.7/32"}) {
		t.Errorf("transient DNS failure must NOT shrink allow-set, got %v", got)
	}
}

type brokenResolver struct{}

func (brokenResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	return nil, errors.New("dns down")
}

func TestRefreshOnlyAppliesOnChange(t *testing.T) {
	src := fakeSource{units: []Unit{{Name: "u", StaticCIDRs: []string{"10.0.0.0/8"}}}}
	app := &countApplier{}
	r := New(src, fakeResolver{}, app, time.Hour)
	r.RefreshOnce(context.Background(), t0)
	r.RefreshOnce(context.Background(), t0.Add(time.Minute)) // identical set
	if app.n != 1 {
		t.Errorf("Apply called %d times; want 1 (no change second pass)", app.n)
	}
}

type countApplier struct{ n int }

func (c *countApplier) Apply(string, []string) error { c.n++; return nil }
