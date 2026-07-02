package pipeline

import "testing"

func TestBurstAllowlistedChild(t *testing.T) {
	allowed := []string{"iptables", "ip6tables", "iptables-restore", "nft", "runc", "containerd-shim", "docker-proxy"}
	for _, c := range allowed {
		if !burstAllowlistedChild(c) {
			t.Errorf("%q should be burst-allowlisted (container-host runtime/network churn)", c)
		}
	}
	denied := []string{"bash", "sh", "python3", "curl", "php-fpm", "nc"}
	for _, c := range denied {
		if burstAllowlistedChild(c) {
			t.Errorf("%q must NOT be allowlisted — real burst spawners", c)
		}
	}
}
