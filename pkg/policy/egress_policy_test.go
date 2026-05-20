package policy

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/verdict"
)

func TestLoadCompilesDenyCIDRsAndMatchesIPv4(t *testing.T) {
	p := New()
	p.Load(&Document{
		Global: Global{
			DenyIPCIDRs: []string{"203.0.113.0/24", "198.51.100.7"},
		},
	})

	doc := p.Current()
	if got := matchGlobal(doc.Global, "", verdict.Conn{DstIP: "203.0.113.42"}); got == "" {
		t.Fatal("expected CIDR-based deny to match IPv4 destination")
	}
	if got := matchGlobal(doc.Global, "", verdict.Conn{DstIP: "198.51.100.7"}); got == "" {
		t.Fatal("expected bare IP deny to normalize and match")
	}
	if got := matchGlobal(doc.Global, "", verdict.Conn{DstIP: "192.0.2.55"}); got != "" {
		t.Fatalf("unexpected deny for unrelated IP: %s", got)
	}
}

func TestLoadCompilesDenyCIDRsAndMatchesIPv6(t *testing.T) {
	p := New()
	p.Load(&Document{
		Global: Global{
			DenyIPCIDRs: []string{"2001:db8::/32"},
		},
	})

	doc := p.Current()
	if got := matchGlobal(doc.Global, "", verdict.Conn{DstIP: "2001:db8::1234"}); got == "" {
		t.Fatal("expected CIDR-based deny to match IPv6 destination")
	}
}
