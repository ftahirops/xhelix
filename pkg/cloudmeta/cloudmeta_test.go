package cloudmeta

import "testing"

func TestIsMetadataIP(t *testing.T) {
	cases := []struct {
		ip   string
		want Provider
	}{
		{"169.254.169.254", ProviderAWS},
		{"100.100.100.200", ProviderAlibaba},
		{"192.0.0.192", ProviderOracle},
		{"8.8.8.8", ProviderNone},
		{"", ProviderNone},
	}
	for _, c := range cases {
		got, ok := IsMetadataIP(c.ip)
		if c.want == ProviderNone {
			if ok {
				t.Errorf("IsMetadataIP(%q): unexpected hit %s", c.ip, got)
			}
			continue
		}
		if got != c.want || !ok {
			t.Errorf("IsMetadataIP(%q) = (%s,%v), want (%s,true)", c.ip, got, ok, c.want)
		}
	}
}

func TestIsMetadataDomain(t *testing.T) {
	cases := []struct {
		q    string
		want Provider
	}{
		{"metadata.google.internal", ProviderGCP},
		{"Metadata.Google.Internal.", ProviderGCP},
		{"metadata.azure.com", ProviderAzure},
		{"example.com", ProviderNone},
		{"", ProviderNone},
	}
	for _, c := range cases {
		got, ok := IsMetadataDomain(c.q)
		if c.want == ProviderNone {
			if ok {
				t.Errorf("IsMetadataDomain(%q): unexpected hit", c.q)
			}
			continue
		}
		if got != c.want || !ok {
			t.Errorf("IsMetadataDomain(%q) = (%s,%v), want (%s,true)", c.q, got, ok, c.want)
		}
	}
}

func TestClassifyBenignSDK(t *testing.T) {
	h, ok := Classify(Context{
		IP: "169.254.169.254", Comm: "cloud-init", IsKnownSDK: true,
	})
	if !ok || h.Severity != SeverityInfo {
		t.Fatalf("got %+v ok=%v", h, ok)
	}
}

func TestClassifyShellPivot(t *testing.T) {
	h, ok := Classify(Context{
		IP: "169.254.169.254", Comm: "curl", ParentExe: "/bin/bash",
	})
	if !ok || h.Severity != SeverityCritical {
		t.Fatalf("got %+v ok=%v, want Critical", h, ok)
	}
}

func TestClassifyWebServerSSRF(t *testing.T) {
	h, ok := Classify(Context{
		IP: "169.254.169.254", Comm: "go-app", ParentExe: "/usr/sbin/nginx",
	})
	if !ok || h.Severity != SeverityHigh {
		t.Fatalf("got %+v ok=%v, want High", h, ok)
	}
}

func TestClassifyUnknownDefault(t *testing.T) {
	h, ok := Classify(Context{IP: "169.254.169.254", Comm: "mystery"})
	if !ok || h.Severity != SeverityNotice {
		t.Fatalf("got %+v, want Notice default", h)
	}
}

func TestClassifyDomainOnly(t *testing.T) {
	h, ok := Classify(Context{Domain: "metadata.google.internal", Comm: "curl"})
	if !ok || h.Provider != ProviderGCP || h.Severity != SeverityCritical {
		t.Fatalf("got %+v ok=%v", h, ok)
	}
}

func TestClassifyNoMatch(t *testing.T) {
	if _, ok := Classify(Context{IP: "8.8.8.8"}); ok {
		t.Fatal("expected no match")
	}
}

func TestAllowedCallersNonEmpty(t *testing.T) {
	if len(AllowedCallers()) == 0 {
		t.Fatal("AllowedCallers must include cloud-init and friends")
	}
}
