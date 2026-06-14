package egressledger

import (
	"net"
	"testing"
)

func parseIP(s string) net.IP { return net.ParseIP(s) }

// All non-dropped IPs return the exact address regardless of destclass.
// The earlier /16 bucketing policy was removed — operators need exact
// IPs for rDNS / ASN / intel / safety-net blocking.
func TestFlowKeyForIP_AlwaysExact(t *testing.T) {
	cases := []struct {
		name, ip, class, want string
	}{
		{"cloudflare-v4", "104.16.5.27", "cloudflare", "104.16.5.27"},
		{"cdn-canonical", "104.16.5.27", "cdn", "104.16.5.27"},
		{"cloud_provider", "52.84.1.1", "cloud_provider", "52.84.1.1"},
		{"private-class", "192.168.5.10", "private", "192.168.5.10"},
		{"raw", "78.142.45.123", "raw", "78.142.45.123"},
		{"empty-class", "78.142.45.123", "", "78.142.45.123"},
		{"metadata-exact", "169.254.169.254", "metadata", "169.254.169.254"},

		// Loopback / link-local / multicast → dropped (no exception for IMDS aside from the explicit metadata classes).
		{"loopback", "127.0.0.1", "any", ""},
		{"link-local-non-imds", "169.254.1.1", "raw", ""},
		{"multicast", "224.0.0.1", "raw", ""},

		// IPv6 exact.
		{"v6-cloudflare", "2606:4700:1::a29f:c001", "cloudflare", "2606:4700:1::a29f:c001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := flowKeyForIP(parseIP(tc.ip), tc.class)
			if got != tc.want {
				t.Fatalf("flowKeyForIP(%s, %q) = %q, want %q", tc.ip, tc.class, got, tc.want)
			}
		})
	}
}
