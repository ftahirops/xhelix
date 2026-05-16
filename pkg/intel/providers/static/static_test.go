package static

import (
	"context"
	"testing"

	"github.com/xhelix/xhelix/pkg/intel/providers"
)

func TestEmptyProviderReturnsClean(t *testing.T) {
	p := New("")
	v, err := p.Lookup(context.Background(), providers.Query{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Class != providers.ClassClean {
		t.Fatalf("class = %s", v.Class)
	}
}

func TestDirectDomainMatch(t *testing.T) {
	p := New("static")
	p.AddDomain("evil.example", Entry{Source: "spamhaus", Reason: "in-drop-list"})
	v, _ := p.Lookup(context.Background(), providers.Query{Domain: "evil.example"})
	if v.Class != providers.ClassDeny {
		t.Fatalf("class = %s", v.Class)
	}
	if len(v.Reasons) != 1 || v.Reasons[0] != "spamhaus:in-drop-list" {
		t.Fatalf("reasons = %v", v.Reasons)
	}
}

func TestSubdomainSuffixMatch(t *testing.T) {
	p := New("static")
	p.AddDomain("evil.example", Entry{Source: "feed", Reason: "parent"})
	v, _ := p.Lookup(context.Background(), providers.Query{Domain: "tracker.evil.example"})
	if v.Class != providers.ClassDeny {
		t.Fatalf("subdomain should match; class = %s", v.Class)
	}
}

func TestIPMatch(t *testing.T) {
	p := New("static")
	p.AddIP("1.2.3.4", Entry{Source: "tor", Reason: "exit-node"})
	v, _ := p.Lookup(context.Background(), providers.Query{IP: "1.2.3.4"})
	if v.Class != providers.ClassDeny {
		t.Fatalf("class = %s", v.Class)
	}
}

func TestCaseInsensitiveDomain(t *testing.T) {
	p := New("")
	p.AddDomain("EVIL.example", Entry{Source: "x", Reason: "y"})
	v, _ := p.Lookup(context.Background(), providers.Query{Domain: "evil.EXAMPLE"})
	if v.Class != providers.ClassDeny {
		t.Fatal("case-insensitive match failed")
	}
}

func TestTrailingDotNormalized(t *testing.T) {
	p := New("")
	p.AddDomain("evil.example.", Entry{Source: "x", Reason: "y"})
	v, _ := p.Lookup(context.Background(), providers.Query{Domain: "evil.example"})
	if v.Class != providers.ClassDeny {
		t.Fatal("trailing-dot normalization failed")
	}
}

func TestSetDenyListsSwapsAtomically(t *testing.T) {
	p := New("")
	p.AddDomain("a.example", Entry{Source: "x", Reason: "y"})
	if d, _ := p.Counts(); d != 1 {
		t.Fatalf("count = %d, want 1", d)
	}

	newDomains := map[string]Entry{
		"b.example": {Source: "y", Reason: "z"},
		"c.example": {Source: "y", Reason: "z"},
	}
	p.SetDenyLists(newDomains, nil)
	if d, _ := p.Counts(); d != 2 {
		t.Fatalf("count after swap = %d, want 2", d)
	}

	v, _ := p.Lookup(context.Background(), providers.Query{Domain: "a.example"})
	if v.Class != providers.ClassClean {
		t.Fatal("old entry should be gone after SetDenyLists")
	}
}

func TestNoMatchReturnsClean(t *testing.T) {
	p := New("")
	p.AddDomain("evil.example", Entry{})
	v, _ := p.Lookup(context.Background(), providers.Query{Domain: "good.example"})
	if v.Class != providers.ClassClean {
		t.Fatalf("class = %s", v.Class)
	}
}
