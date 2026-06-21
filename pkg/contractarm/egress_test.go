package contractarm

import "testing"

func TestEgressDirectivesEmptyIsLockdown(t *testing.T) {
	got := EgressDirectives(nil)
	want := "IPAddressAllow=localhost link-local\nIPAddressDeny=any"
	if got != want {
		t.Errorf("EgressDirectives(nil) =\n%q\nwant\n%q", got, want)
	}
}

func TestEgressDirectivesWithCIDRs(t *testing.T) {
	got := EgressDirectives([]string{"10.0.0.0/8", " ", "192.168.1.0/24", ""})
	want := "IPAddressAllow=localhost link-local 10.0.0.0/8 192.168.1.0/24\nIPAddressDeny=any"
	if got != want {
		t.Errorf("EgressDirectives =\n%q\nwant\n%q", got, want)
	}
}

func TestEgressDirectivesAlwaysAllowsLoopback(t *testing.T) {
	got := EgressDirectives([]string{"203.0.113.0/24"})
	const prefix = "IPAddressAllow=localhost link-local"
	if got[:len(prefix)] != prefix {
		t.Errorf("loopback not always allowed: %q", got)
	}
}
