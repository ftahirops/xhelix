package netban

import (
	"net"
	"testing"
	"time"
)

type fakeXDP struct {
	added   map[string]bool
	removed map[string]bool
}

func newFake() *fakeXDP {
	return &fakeXDP{added: map[string]bool{}, removed: map[string]bool{}}
}
func (f *fakeXDP) Add(ip net.IP) error    { f.added[ip.String()] = true; return nil }
func (f *fakeXDP) Remove(ip net.IP) error { f.removed[ip.String()] = true; return nil }
func (f *fakeXDP) List() ([]net.IP, error) {
	out := make([]net.IP, 0, len(f.added))
	for s := range f.added {
		out = append(out, net.ParseIP(s))
	}
	return out, nil
}

func TestBanFlowsToXDP(t *testing.T) {
	x := newFake()
	b := NewBanner(x, false /* nft off in tests */)
	ip := net.ParseIP("198.51.100.5")
	if err := b.Ban(ip, "test", time.Minute); err != nil {
		t.Fatal(err)
	}
	if !x.added["198.51.100.5"] {
		t.Errorf("XDP did not see ban")
	}
	list, _ := b.List()
	if len(list) != 1 {
		t.Errorf("List len = %d, want 1", len(list))
	}
	if err := b.Unban(ip); err != nil {
		t.Fatal(err)
	}
	if !x.removed["198.51.100.5"] {
		t.Errorf("XDP did not see unban")
	}
}

func TestSweepExpiresEntries(t *testing.T) {
	x := newFake()
	b := NewBanner(x, false)
	b.Ban(net.ParseIP("1.2.3.4"), "test", time.Microsecond)
	time.Sleep(2 * time.Millisecond)
	b.Sweep()
	list, _ := b.List()
	if len(list) != 0 {
		t.Errorf("expected expiry to clear; have %d", len(list))
	}
	if !x.removed["1.2.3.4"] {
		t.Error("XDP did not see expiry-driven removal")
	}
}
