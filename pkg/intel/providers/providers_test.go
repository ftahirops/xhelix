package providers

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeProvider struct {
	name    string
	verdict Verdict
	err     error
	delay   time.Duration
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Lookup(ctx context.Context, q Query) (Verdict, error) {
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return Verdict{}, ctx.Err()
		}
	}
	if f.err != nil {
		return Verdict{}, f.err
	}
	v := f.verdict
	v.Provider = f.name
	return v, nil
}

func TestEmptyAggregator(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	v, _ := a.Lookup(context.Background(), Query{Domain: "example.com"})
	if v.Class != ClassUnknown {
		t.Fatalf("class = %s, want unknown", v.Class)
	}
}

func TestSingleProviderDeny(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "p1", verdict: Verdict{Class: ClassDeny, Reasons: []string{"in-list"}}}})
	v, perProv := a.Lookup(context.Background(), Query{Domain: "evil.example"})
	if v.Class != ClassDeny {
		t.Fatalf("class = %s", v.Class)
	}
	if len(perProv) != 1 || perProv[0].Provider != "p1" {
		t.Fatalf("per-provider = %+v", perProv)
	}
}

func TestDenyIfAnyOneDenies(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "p1", verdict: Verdict{Class: ClassClean}}})
	a.Register(Entry{Provider: &fakeProvider{name: "p2", verdict: Verdict{Class: ClassDeny, Reasons: []string{"hit"}}}})
	a.Register(Entry{Provider: &fakeProvider{name: "p3", verdict: Verdict{Class: ClassClean}}})
	v, _ := a.Lookup(context.Background(), Query{Domain: "x"})
	if v.Class != ClassDeny {
		t.Fatalf("class = %s, want deny", v.Class)
	}
}

func TestMajorityPolicy(t *testing.T) {
	a := NewAggregator(PolicyMajority, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "p1", verdict: Verdict{Class: ClassDeny}}})
	a.Register(Entry{Provider: &fakeProvider{name: "p2", verdict: Verdict{Class: ClassDeny}}})
	a.Register(Entry{Provider: &fakeProvider{name: "p3", verdict: Verdict{Class: ClassClean}}})
	v, _ := a.Lookup(context.Background(), Query{Domain: "x"})
	if v.Class != ClassDeny {
		t.Fatalf("class = %s, want deny (2 of 3)", v.Class)
	}

	// Flip one to clean → majority is now clean
	a2 := NewAggregator(PolicyMajority, 0)
	a2.Register(Entry{Provider: &fakeProvider{name: "p1", verdict: Verdict{Class: ClassDeny}}})
	a2.Register(Entry{Provider: &fakeProvider{name: "p2", verdict: Verdict{Class: ClassClean}}})
	a2.Register(Entry{Provider: &fakeProvider{name: "p3", verdict: Verdict{Class: ClassClean}}})
	v, _ = a2.Lookup(context.Background(), Query{Domain: "x"})
	if v.Class != ClassClean {
		t.Fatalf("class = %s, want clean", v.Class)
	}
}

func TestUnanimousPolicy(t *testing.T) {
	a := NewAggregator(PolicyUnanimous, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "p1", verdict: Verdict{Class: ClassDeny}}})
	a.Register(Entry{Provider: &fakeProvider{name: "p2", verdict: Verdict{Class: ClassClean}}})
	v, _ := a.Lookup(context.Background(), Query{Domain: "x"})
	if v.Class == ClassDeny {
		t.Fatalf("class = %s, want NOT deny", v.Class)
	}
}

func TestErrorProviderMappedToUnknown(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "broken", err: errors.New("network down")}})
	a.Register(Entry{Provider: &fakeProvider{name: "ok", verdict: Verdict{Class: ClassClean}}})
	v, perProv := a.Lookup(context.Background(), Query{Domain: "x"})
	if v.Class != ClassClean {
		t.Fatalf("class = %s, want clean", v.Class)
	}
	if perProv[0].Class != ClassUnknown {
		t.Fatalf("broken provider should be unknown; got %s", perProv[0].Class)
	}
}

func TestTimeoutAppliesToSlowProvider(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 10*time.Millisecond)
	a.Register(Entry{Provider: &fakeProvider{name: "slow", delay: 200 * time.Millisecond, verdict: Verdict{Class: ClassDeny}}})
	a.Register(Entry{Provider: &fakeProvider{name: "fast", verdict: Verdict{Class: ClassClean}}})
	start := time.Now()
	v, perProv := a.Lookup(context.Background(), Query{Domain: "x"})
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("lookup took %v, expected under 100ms", elapsed)
	}
	// Slow provider should have errored out
	if perProv[0].Class != ClassUnknown {
		t.Fatalf("slow provider should be unknown; got %s", perProv[0].Class)
	}
	if v.Class != ClassClean {
		t.Fatalf("class = %s, want clean (since slow timed out)", v.Class)
	}
}

func TestNamesInRegistrationOrder(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "a"}})
	a.Register(Entry{Provider: &fakeProvider{name: "b"}})
	a.Register(Entry{Provider: &fakeProvider{name: "c"}})
	got := a.Names()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("names = %v", got)
	}
}

func TestNilProviderIgnored(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	a.Register(Entry{Provider: nil})
	if got := a.Names(); len(got) != 0 {
		t.Fatalf("nil provider should not register; got %v", got)
	}
}

func TestAdviseClass(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "p1", verdict: Verdict{Class: ClassAdvise, Reasons: []string{"newly-registered"}}}})
	v, _ := a.Lookup(context.Background(), Query{Domain: "x"})
	if v.Class != ClassAdvise {
		t.Fatalf("class = %s, want advise", v.Class)
	}
}

func TestReasonsAggregatedAndPrefixed(t *testing.T) {
	a := NewAggregator(PolicyDenyIfAny, 0)
	a.Register(Entry{Provider: &fakeProvider{name: "spamhaus", verdict: Verdict{Class: ClassDeny, Reasons: []string{"in-drop-list"}}}})
	a.Register(Entry{Provider: &fakeProvider{name: "tor", verdict: Verdict{Class: ClassAdvise, Reasons: []string{"exit-node"}}}})
	v, _ := a.Lookup(context.Background(), Query{IP: "1.2.3.4"})
	if v.Class != ClassDeny {
		t.Fatalf("class = %s", v.Class)
	}
	// Reasons must be sorted and provider-prefixed
	wantPrefix1 := "spamhaus:"
	wantPrefix2 := "tor:"
	if len(v.Reasons) != 2 {
		t.Fatalf("reasons = %v", v.Reasons)
	}
	found1, found2 := false, false
	for _, r := range v.Reasons {
		if len(r) >= len(wantPrefix1) && r[:len(wantPrefix1)] == wantPrefix1 {
			found1 = true
		}
		if len(r) >= len(wantPrefix2) && r[:len(wantPrefix2)] == wantPrefix2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("reasons missing prefixes; got %v", v.Reasons)
	}
}
