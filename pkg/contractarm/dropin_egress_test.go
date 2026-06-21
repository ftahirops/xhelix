package contractarm

import (
	"strings"
	"testing"
	"time"
)

var egressTestNow = time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)

func TestRenderDropInIncludesEgress(t *testing.T) {
	eg := EgressDirectives([]string{"10.0.0.0/8"})
	out := RenderDropIn("shop", "locked", "nginx.service", "", "", eg, egressTestNow)
	if out == "" {
		t.Fatal("egress-only service must still produce a drop-in")
	}
	if !strings.Contains(out, "IPAddressDeny=any") {
		t.Errorf("drop-in missing egress directives:\n%s", out)
	}
	if !strings.Contains(out, "[Service]") {
		t.Errorf("drop-in missing [Service] header:\n%s", out)
	}
}

func TestRenderDropInNoEgressUnchanged(t *testing.T) {
	if out := RenderDropIn("shop", "observe", "nginx.service", "", "", "", egressTestNow); out != "" {
		t.Errorf("expected empty drop-in, got:\n%s", out)
	}
}

func TestRenderDropInSeccompPlusEgress(t *testing.T) {
	out := RenderDropIn("shop", "locked", "nginx.service",
		"SystemCallFilter=~ptrace", "", "IPAddressAllow=localhost link-local\nIPAddressDeny=any", egressTestNow)
	if !strings.Contains(out, "SystemCallFilter=~ptrace") || !strings.Contains(out, "IPAddressDeny=any") {
		t.Errorf("drop-in should carry both seccomp and egress:\n%s", out)
	}
}
