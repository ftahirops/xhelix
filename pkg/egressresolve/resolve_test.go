package egressresolve

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeResolver map[string][]net.IP

func (f fakeResolver) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	ips, ok := f[host]
	if !ok || len(ips) == 0 {
		return nil, errors.New("no such host")
	}
	return ips, nil
}

func TestResolveCIDRsConvertsAndSorts(t *testing.T) {
	r := fakeResolver{
		"b.example.com": {net.ParseIP("10.0.0.2"), net.ParseIP("2001:db8::1")},
		"a.example.com": {net.ParseIP("10.0.0.1")},
	}
	got, err := ResolveCIDRs(context.Background(), r, []string{"b.example.com", "a.example.com"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := []string{"10.0.0.1/32", "10.0.0.2/32", "2001:db8::1/128"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%q want %q (full %v)", i, got[i], want[i], got)
		}
	}
}

func TestResolveCIDRsDedupes(t *testing.T) {
	r := fakeResolver{
		"x.example.com": {net.ParseIP("10.0.0.5")},
		"y.example.com": {net.ParseIP("10.0.0.5")}, // same IP
	}
	got, err := ResolveCIDRs(context.Background(), r, []string{"x.example.com", "y.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "10.0.0.5/32" {
		t.Errorf("expected one deduped CIDR, got %v", got)
	}
}

func TestResolveCIDRsFailsOnUnresolvable(t *testing.T) {
	r := fakeResolver{"ok.example.com": {net.ParseIP("10.0.0.1")}}
	_, err := ResolveCIDRs(context.Background(), r, []string{"ok.example.com", "nope.example.com"})
	if err == nil {
		t.Fatal("expected error when an FQDN resolves to zero IPs")
	}
}

func TestResolveCIDRsEmptyInput(t *testing.T) {
	got, err := ResolveCIDRs(context.Background(), fakeResolver{}, nil)
	if err != nil || got != nil {
		t.Errorf("empty input must yield (nil,nil); got (%v,%v)", got, err)
	}
}
