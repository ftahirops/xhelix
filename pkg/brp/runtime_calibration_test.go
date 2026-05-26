package brp

import (
	"strings"
	"testing"
)

// Tests for the 2026-05-23 protected-paths calibration:
//   A — attributed unprofiled writer → Verify (was HardDeny)
//   B — TrustedSystemWriters comm bypasses protected-path check
//   D — unattributed write → Verify (not HardDeny)
//   C — verified by /etc/systemd/system/ no longer being protected

func TestProtectedPath_TrustedWriterBypasses(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	// Real dpkg: comm=dpkg AND exe under /usr/bin/ — bypass fires, the
	// envelope check then returns Unknown (unprofiled). NOT HardDeny.
	d, _ := r.Evaluate(MatchResult{Confidence: ConfidenceUnprofiled},
		EventFacts{
			Action: "file_write", Path: "/etc/sudoers",
			Comm: "dpkg", ExePath: "/usr/bin/dpkg", PID: 42,
		})
	if d == DecisionHardDeny {
		t.Errorf("real dpkg writing protected path should not hard-deny, got %s", d)
	}
}

func TestProtectedPath_SpoofedCommRejected(t *testing.T) {
	// Attacker spoofs comm to "dpkg" via prctl(PR_SET_NAME) but their
	// binary lives in /tmp — exe-path gate MUST reject the bypass.
	r := NewRuntime(DefaultInvariants())
	d, reason := r.Evaluate(MatchResult{Confidence: ConfidenceUnprofiled},
		EventFacts{
			Action: "file_write", Path: "/etc/sudoers",
			Comm: "dpkg", ExePath: "/tmp/.fake_dpkg", PID: 99,
		})
	// Should fall into the rule-A demoted Verify, NOT bypass.
	if d != DecisionVerify {
		t.Errorf("spoofed-comm bypass: got %s, want verify (reason=%q)", d, reason)
	}
	// And reason must NOT say "trusted writer" — must say "protected path".
	if !strings.Contains(reason, "protected path") {
		t.Errorf("reason should mention protected path, got %q", reason)
	}
}

func TestProtectedPath_TrustedCommNoExePathRejected(t *testing.T) {
	// Sensor blind spot: comm available but exe path empty. Must fail
	// closed (require positive identification).
	r := NewRuntime(DefaultInvariants())
	d, _ := r.Evaluate(MatchResult{Confidence: ConfidenceUnprofiled},
		EventFacts{
			Action: "file_write", Path: "/etc/sudoers",
			Comm: "dpkg", PID: 7, // ExePath: ""
		})
	if d != DecisionVerify {
		t.Errorf("missing exe-path: got %s, want verify (fail-closed)", d)
	}
}

func TestIsTrustedSystemWriter_Cases(t *testing.T) {
	cases := []struct {
		comm, exe string
		want      bool
	}{
		{"dpkg", "/usr/bin/dpkg", true},
		{"snapd", "/usr/lib/snapd/snapd", true},
		{"apt", "/usr/bin/apt", true},
		{"systemctl", "/usr/bin/systemctl", true},
		{"dpkg", "/tmp/.fake", false},    // spoofed exe
		{"dpkg", "", false},               // no exe info
		{"evilbinary", "/usr/bin/dpkg", false}, // wrong comm
		{"", "/usr/bin/dpkg", false},      // no comm
	}
	for _, c := range cases {
		got := isTrustedSystemWriter(c.comm, c.exe)
		if got != c.want {
			t.Errorf("isTrustedSystemWriter(%q, %q) = %v, want %v",
				c.comm, c.exe, got, c.want)
		}
	}
}


func TestProtectedPath_UnattributedDemoted(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	d, reason := r.Evaluate(MatchResult{Confidence: ConfidenceUnprofiled},
		EventFacts{Action: "file_write", Path: "/etc/shadow"}) // no Comm/PID
	if d != DecisionVerify {
		t.Errorf("unattributed protected-path write: got %s, want verify (got reason=%q)", d, reason)
	}
}

func TestProtectedPath_AttributedNonTrustedDemoted(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	d, _ := r.Evaluate(MatchResult{Confidence: ConfidenceUnprofiled},
		EventFacts{Action: "file_write", Path: "/etc/shadow", Comm: "evilbinary", PID: 99})
	if d != DecisionVerify {
		t.Errorf("attributed-non-trusted protected-path write: got %s, want verify", d)
	}
}

func TestProtectedPath_ExecStillHardDeny(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	// Exec of a protected path remains hard-deny — execing /etc/shadow
	// has no legitimate variant; nothing to demote.
	d, _ := r.Evaluate(MatchResult{Confidence: ConfidenceUnprofiled},
		EventFacts{Action: "exec", TargetImage: "/etc/shadow"})
	if d != DecisionHardDeny {
		t.Errorf("exec of protected path: got %s, want hard_deny", d)
	}
}

func TestProtectedPath_SystemdSystemNoLongerProtected(t *testing.T) {
	// Rule C: /etc/systemd/system/ was removed from the protected list.
	if IsProtectedPath("/etc/systemd/system/snap-foo.mount") {
		t.Error("/etc/systemd/system/ should not be protected after C calibration")
	}
	// But /etc/systemd/network/ remains protected.
	if !IsProtectedPath("/etc/systemd/network/10-foo.network") {
		t.Error("/etc/systemd/network/ should still be protected")
	}
}

func TestAlwaysSuspicious_StillFires(t *testing.T) {
	// Calibration must NOT weaken the always-suspicious invariants.
	r := NewRuntime(DefaultInvariants())
	d, _ := r.Evaluate(MatchResult{}, EventFacts{Action: "ptrace_attach"})
	if d != DecisionHardDeny {
		t.Errorf("ptrace_attach: got %s, want hard_deny (must not be weakened)", d)
	}
}

func TestRoleInvariant_StillFires(t *testing.T) {
	// Calibration must NOT weaken role invariants (web role exec shell).
	r := NewRuntime(DefaultInvariants())
	d, _ := r.Evaluate(MatchResult{},
		EventFacts{Action: "exec", TargetImage: "/bin/sh", Role: "nginx-reverse-proxy"})
	if d != DecisionHardDeny {
		t.Errorf("nginx exec shell: got %s, want hard_deny", d)
	}
}

// TestL0_MetadataAccess_NonCloudRole verifies the Phase A.3 promotion:
// IMDS access by any role NOT in isCloudAwareRole hard-denies.
func TestL0_MetadataAccess_NonCloudRole(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	d, reason := r.Evaluate(MatchResult{}, EventFacts{
		Action:   "net_connect",
		DestHost: "169.254.169.254",
		DestPort: 80,
		Role:     "nginx-reverse-proxy",
	})
	if d != DecisionHardDeny {
		t.Errorf("nginx → IMDS: got %s, want hard_deny (reason=%q)", d, reason)
	}
}

func TestL0_MetadataAccess_CloudRoleAllowed(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	d, _ := r.Evaluate(MatchResult{}, EventFacts{
		Action:   "net_connect",
		DestHost: "169.254.169.254",
		DestPort: 80,
		Role:     "aws-cli",
	})
	if d == DecisionHardDeny {
		t.Errorf("aws-cli → IMDS: hard-denied; cloud-aware role should pass L0")
	}
}

func TestL0_MetadataAccess_UnprofiledRoleStillDenies(t *testing.T) {
	// Role="" (unprofiled) cannot legitimately claim cloud usage.
	r := NewRuntime(DefaultInvariants())
	d, _ := r.Evaluate(MatchResult{}, EventFacts{
		Action:   "net_connect",
		DestHost: "169.254.169.254",
	})
	if d != DecisionHardDeny {
		t.Errorf("unprofiled → IMDS: got %s, want hard_deny", d)
	}
}

// TestL0_TmpfsExec verifies the Phase A.3 promotion.
func TestL0_TmpfsExec_Denies(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	cases := []string{
		"/dev/shm/.implant",
		"/run/user/1000/.payload",
		"/tmp/.hidden_binary",
	}
	for _, target := range cases {
		d, reason := r.Evaluate(MatchResult{}, EventFacts{
			Action:      "exec",
			TargetImage: target,
		})
		if d != DecisionHardDeny {
			t.Errorf("exec %q: got %s, want hard_deny (%q)", target, d, reason)
		}
	}
}

func TestL0_TmpfsExec_NormalPathPasses(t *testing.T) {
	r := NewRuntime(DefaultInvariants())
	d, _ := r.Evaluate(MatchResult{}, EventFacts{
		Action:      "exec",
		TargetImage: "/usr/bin/ls",
	})
	if d == DecisionHardDeny {
		t.Errorf("normal /usr/bin/ls exec hard-denied — false positive on L0 tmpfs invariant")
	}
}

func TestIsCloudAwareRole_Cases(t *testing.T) {
	cases := map[string]bool{
		"aws-cli":       true,
		"gcp-sdk":       true,
		"azure-cli":     true,
		"k8s-kubelet":   true,
		"cloud-init":    true,
		"kubelet":       true,
		"amazon-ssm-agent": true,
		"nginx-reverse-proxy": false,
		"mysql-default": false,
		"":              false,
	}
	for role, want := range cases {
		got := isCloudAwareRole(role)
		if got != want {
			t.Errorf("isCloudAwareRole(%q) = %v, want %v", role, got, want)
		}
	}
}

func TestIsTmpfsLikelyPath_Cases(t *testing.T) {
	cases := map[string]bool{
		"/dev/shm/.x":       true,
		"/run/user/0/.a":    true,
		"/tmp/.hidden":      true,
		"/tmp/visible":      false, // requires leading .
		"/usr/bin/ls":       false,
		"/home/user/script": false,
		"":                  false,
	}
	for p, want := range cases {
		got := isTmpfsLikelyPath(p)
		if got != want {
			t.Errorf("isTmpfsLikelyPath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestTrustedWriters_SetIsComplete(t *testing.T) {
	// Sanity check that key writers are in the set so calibration is
	// effective for the common Debian/Ubuntu/RHEL adminstrative path.
	mustHave := []string{"snapd", "dpkg", "apt", "apt-get", "systemctl", "rpm", "yum", "dnf"}
	for _, c := range mustHave {
		if !TrustedSystemWriters[c] {
			t.Errorf("TrustedSystemWriters missing %q", c)
		}
	}
}
