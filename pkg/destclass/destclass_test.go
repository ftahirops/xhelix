package destclass

import (
	"net"
	"testing"
)

type fakeIntel struct{ bad map[string]bool }

func (f fakeIntel) IsBad(ip net.IP) bool { return f.bad[ip.String()] }

type fakeFleet struct{ counts map[string]int }

func (f fakeFleet) SeenCount(ip net.IP, sni string) int {
	if n, ok := f.counts[sni]; ok {
		return n
	}
	return f.counts[ip.String()]
}

func TestClassifyIntelBadWinsAlways(t *testing.T) {
	c := New(WithIntel(fakeIntel{bad: map[string]bool{"1.2.3.4": true}}))
	d := c.Classify(net.ParseIP("1.2.3.4"), "github.com", 443)
	if d.Class != ClassIntelBad {
		t.Errorf("intel-bad must beat suffix match; got %s", d.Class)
	}
}

func TestClassifyPrivate(t *testing.T) {
	c := New()
	for _, addr := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1",
		"172.16.0.10", "169.254.1.1", "::1", "fe80::1", "100.64.5.5"} {
		d := c.Classify(net.ParseIP(addr), "", 443)
		if d.Class != ClassPrivate {
			t.Errorf("%s should be private; got %s", addr, d.Class)
		}
	}
}

func TestClassifyDevRegistryBySNI(t *testing.T) {
	c := New()
	cases := []struct{ sni, want string }{
		{"github.com", "github.com"},
		{"api.github.com", "github.com"},
		{"raw.githubusercontent.com", "githubusercontent.com"},
		{"registry.npmjs.org", "npmjs.org"},
		{"files.pythonhosted.org", "pythonhosted.org"},
		{"crates.io", "crates.io"},
		{"proxy.golang.org", "proxy.golang.org"},
	}
	for _, tc := range cases {
		d := c.Classify(net.ParseIP("8.8.8.8"), tc.sni, 443)
		if d.Class != ClassDevRegistry {
			t.Errorf("%s should be dev_registry; got %s (reason %s)", tc.sni, d.Class, d.Reason)
		}
	}
}

func TestClassifyOSUpdate(t *testing.T) {
	c := New()
	for _, sni := range []string{"security.debian.org", "archive.ubuntu.com",
		"download.fedoraproject.org", "windowsupdate.com"} {
		d := c.Classify(net.ParseIP("8.8.8.8"), sni, 443)
		if d.Class != ClassOSUpdate {
			t.Errorf("%s should be os_update; got %s", sni, d.Class)
		}
	}
}

func TestClassifyCDNBySuffix(t *testing.T) {
	c := New()
	for _, sni := range []string{"cdnjs.cloudflare.com", "abc.fastly.net",
		"d2.cloudfront.net", "fonts.gstatic.com"} {
		d := c.Classify(net.ParseIP("8.8.8.8"), sni, 443)
		if d.Class != ClassCDN {
			t.Errorf("%s should be cdn; got %s", sni, d.Class)
		}
	}
}

func TestClassifyCloudBySuffix(t *testing.T) {
	c := New()
	for _, sni := range []string{"s3.amazonaws.com", "storage.googleapis.com",
		"foo.azurewebsites.net"} {
		d := c.Classify(net.ParseIP("8.8.8.8"), sni, 443)
		if d.Class != ClassCloudProvider {
			t.Errorf("%s should be cloud_provider; got %s", sni, d.Class)
		}
	}
}

func TestClassifyByCIDRWithoutSNI(t *testing.T) {
	c := New()
	// Hetzner range from builtin (prod host's own block)
	d := c.Classify(net.ParseIP("65.108.246.67"), "", 443)
	if d.Class != ClassCloudProvider {
		t.Errorf("hetzner IP should be cloud_provider; got %s", d.Class)
	}
	// Cloudflare IPv4
	d = c.Classify(net.ParseIP("104.16.0.1"), "", 443)
	if d.Class != ClassCDN {
		t.Errorf("cloudflare IPv4 should be cdn; got %s", d.Class)
	}
	// Cloudflare IPv6 — the gap observed in prod
	d = c.Classify(net.ParseIP("2606:4700:3033::6815:51a4"), "", 443)
	if d.Class != ClassCDN {
		t.Errorf("cloudflare IPv6 should be cdn; got %s (reason: %s)", d.Class, d.Reason)
	}
	// AWS us-west-2 EC2 (observed in prod as unknown)
	d = c.Classify(net.ParseIP("52.25.121.154"), "", 443)
	if d.Class != ClassCloudProvider {
		t.Errorf("AWS us-west-2 IP should be cloud_provider; got %s", d.Class)
	}
	// AWS IPv6
	d = c.Classify(net.ParseIP("2600:1f00::1"), "", 443)
	if d.Class != ClassCloudProvider {
		t.Errorf("AWS IPv6 should be cloud_provider; got %s", d.Class)
	}
}

func TestClassifyFleetBaseline(t *testing.T) {
	c := New(WithFleet(fakeFleet{counts: map[string]int{
		"api.weirdservice.example": 5,
	}}, 3))
	d := c.Classify(net.ParseIP("8.8.8.8"), "api.weirdservice.example", 443)
	if d.Class != ClassFleetBaseline {
		t.Errorf("seen=5 should be fleet_baseline; got %s", d.Class)
	}
	// Below threshold → unknown
	c = New(WithFleet(fakeFleet{counts: map[string]int{
		"api.weirdservice.example": 1,
	}}, 3))
	d = c.Classify(net.ParseIP("8.8.8.8"), "api.weirdservice.example", 443)
	if d.Class != ClassUnknown {
		t.Errorf("seen=1 (below min=3) should be unknown; got %s", d.Class)
	}
}

func TestClassifyUnknown(t *testing.T) {
	c := New()
	d := c.Classify(net.ParseIP("8.8.8.8"), "evil-c2-domain.example", 443)
	if d.Class != ClassUnknown {
		t.Errorf("uncategorized destination should be unknown; got %s", d.Class)
	}
}

func TestClassifyNilIPSafe(t *testing.T) {
	c := New()
	d := c.Classify(nil, "github.com", 443)
	if d.Class != ClassUnknown {
		t.Errorf("nil IP must not panic; got %s", d.Class)
	}
}

func TestSuffixMatchExactness(t *testing.T) {
	c := New()
	// "evil-github.com" (contains "github.com" as substring but not as
	// suffix-from-dot) must NOT match.
	d := c.Classify(net.ParseIP("8.8.8.8"), "evil-github.com", 443)
	if d.Class == ClassDevRegistry {
		t.Errorf("evil-github.com should not match github.com suffix")
	}
}

func TestExtraSuffixesAndCIDRs(t *testing.T) {
	c := New(
		WithExtraSuffixes(ClassDevRegistry, "internal-registry.corp"),
		WithExtraCIDRs(ClassCloudProvider, "192.0.2.0/24"),
	)
	d := c.Classify(net.ParseIP("8.8.8.8"), "pkg.internal-registry.corp", 443)
	if d.Class != ClassDevRegistry {
		t.Errorf("extra suffix should match; got %s", d.Class)
	}
	d = c.Classify(net.ParseIP("192.0.2.42"), "", 443)
	if d.Class != ClassCloudProvider {
		t.Errorf("extra CIDR should match; got %s", d.Class)
	}
}
