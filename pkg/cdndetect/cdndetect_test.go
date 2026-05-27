package cdndetect

import (
	"net"
	"testing"
	"time"
)

func TestLookupProvider_Cloudflare(t *testing.T) {
	if p := LookupProvider(net.ParseIP("104.18.10.10")); p != ProviderCloudflare {
		t.Errorf("104.18.10.10 → %q want cloudflare", p)
	}
}

func TestLookupProvider_Fastly(t *testing.T) {
	if p := LookupProvider(net.ParseIP("151.101.65.69")); p != ProviderFastly {
		t.Errorf("151.101.65.69 → %q want fastly", p)
	}
}

func TestLookupProvider_NonCDN(t *testing.T) {
	if p := LookupProvider(net.ParseIP("8.8.8.8")); p != ProviderUnknown {
		t.Errorf("8.8.8.8 → %q want unknown", p)
	}
}

func TestClassify_BareIPToCDN(t *testing.T) {
	dns := NewDNSCache(time.Minute, 16)
	r, prov := Classify("/bin/curl", "104.18.10.10", "", dns, time.Now())
	if r != ReasonBareIPToCDN {
		t.Errorf("reason=%q want %q", r, ReasonBareIPToCDN)
	}
	if prov != ProviderCloudflare {
		t.Errorf("prov=%q want cloudflare", prov)
	}
}

func TestClassify_SNIDNSMismatch(t *testing.T) {
	dns := NewDNSCache(time.Minute, 16)
	now := time.Now()
	dns.Note("/usr/bin/python3", "legit-app.example.com", now)
	r, _ := Classify("/usr/bin/python3", "104.18.10.10", "attacker-c2.cdn.host", dns, now)
	if r != ReasonSNIDNSMiss {
		t.Errorf("reason=%q want %q", r, ReasonSNIDNSMiss)
	}
}

func TestClassify_MatchingSNI(t *testing.T) {
	dns := NewDNSCache(time.Minute, 16)
	now := time.Now()
	dns.Note("/usr/bin/curl", "api.example.com", now)
	r, _ := Classify("/usr/bin/curl", "104.18.10.10", "api.example.com", dns, now)
	if r != ReasonNone {
		t.Errorf("reason=%q want none", r)
	}
}

func TestClassify_NonCDNSilent(t *testing.T) {
	dns := NewDNSCache(time.Minute, 16)
	r, prov := Classify("/bin/x", "8.8.8.8", "", dns, time.Now())
	if r != ReasonNone || prov != ProviderUnknown {
		t.Errorf("non-CDN should be silent; got reason=%q prov=%q", r, prov)
	}
}

func TestDNSCache_RetentionEvicts(t *testing.T) {
	c := NewDNSCache(time.Minute, 16)
	now := time.Now()
	c.Note("/bin/x", "old.example.com", now.Add(-2*time.Minute))
	c.Note("/bin/x", "recent.example.com", now)
	r := c.Recent("/bin/x", now)
	if len(r) != 1 || r[0] != "recent.example.com" {
		t.Errorf("Recent=%v want [recent.example.com]", r)
	}
}
