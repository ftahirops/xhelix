package geoip

import (
	"net/netip"
	"testing"
)

func mkEntry(cidr, country, asn, org string) Entry {
	return Entry{
		Prefix: netip.MustParsePrefix(cidr),
		Result: Result{Country: country, ASN: asn, ASNOrg: org},
	}
}

func TestEmptyProviderMisses(t *testing.T) {
	p := NewInMemory()
	if _, ok := p.Lookup("1.2.3.4"); ok {
		t.Fatal("empty provider should miss")
	}
}

func TestExactCIDRMatch(t *testing.T) {
	p := NewInMemory()
	p.Load([]Entry{mkEntry("8.8.8.8/32", "US", "AS15169", "Google")})
	r, ok := p.Lookup("8.8.8.8")
	if !ok {
		t.Fatal("expected hit")
	}
	if r.Country != "US" || r.ASN != "AS15169" {
		t.Fatalf("wrong result: %+v", r)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	p := NewInMemory()
	p.Load([]Entry{
		mkEntry("10.0.0.0/8", "ZZ", "AS-RFC1918", "Private"),
		mkEntry("10.0.0.0/16", "ZZ", "AS-INNER", "Inner"),
		mkEntry("10.0.0.0/24", "ZZ", "AS-CORE", "Core"),
	})
	r, _ := p.Lookup("10.0.0.5")
	if r.ASN != "AS-CORE" {
		t.Fatalf("longest-prefix miss; got %q", r.ASN)
	}
	r, _ = p.Lookup("10.0.5.1") // /16 should win
	if r.ASN != "AS-INNER" {
		t.Fatalf("got %q, want AS-INNER", r.ASN)
	}
	r, _ = p.Lookup("10.5.0.1") // /8 only
	if r.ASN != "AS-RFC1918" {
		t.Fatalf("got %q, want AS-RFC1918", r.ASN)
	}
}

func TestIPv6Lookup(t *testing.T) {
	p := NewInMemory()
	p.Load([]Entry{mkEntry("2001:db8::/32", "US", "AS-DOC", "Doc")})
	r, ok := p.Lookup("2001:db8::1")
	if !ok {
		t.Fatal("expected v6 hit")
	}
	if r.ASN != "AS-DOC" {
		t.Fatalf("wrong: %+v", r)
	}
}

func TestInvalidIPFails(t *testing.T) {
	p := NewInMemory()
	p.Load(SeedEntries())
	if _, ok := p.Lookup("not-an-ip"); ok {
		t.Fatal("invalid IP should miss")
	}
	if _, ok := p.Lookup(""); ok {
		t.Fatal("empty IP should miss")
	}
}

func TestSeedEntriesCoverPrivateAndMetadata(t *testing.T) {
	p := NewInMemory()
	p.Load(SeedEntries())
	for _, ip := range []string{
		"127.0.0.1", "10.5.5.5", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "8.8.8.8", "1.1.1.1",
	} {
		if _, ok := p.Lookup(ip); !ok {
			t.Errorf("seed missed %s", ip)
		}
	}
}

func TestIsPrivate(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5", true},
		{"172.16.5.1", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"fe80::1", true},
		{"fc00::1", true},
		{"8.8.8.8", false},
		{"2606:4700:4700::1111", false},
		{"not-an-ip", false},
	}
	for _, c := range cases {
		if got := IsPrivate(c.ip); got != c.want {
			t.Errorf("IsPrivate(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestLoadFiltersInvalidPrefixes(t *testing.T) {
	p := NewInMemory()
	// Construct one valid + one zero-value (invalid) Entry.
	p.Load([]Entry{
		mkEntry("1.0.0.0/8", "AU", "AS-X", "Y"),
		{}, // invalid prefix
	})
	if p.Len() != 1 {
		t.Fatalf("len = %d, want 1 (invalid filtered)", p.Len())
	}
}

func TestLenSplitsIPVersions(t *testing.T) {
	p := NewInMemory()
	p.Load([]Entry{
		mkEntry("10.0.0.0/8", "ZZ", "AS-X", ""),
		mkEntry("2001:db8::/32", "ZZ", "AS-Y", ""),
	})
	if p.Len() != 2 {
		t.Fatalf("len = %d", p.Len())
	}
}

func TestProviderInterface(t *testing.T) {
	// Compile-time check
	var _ Provider = NewInMemory()
}
