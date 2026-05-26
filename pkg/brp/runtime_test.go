package brp

import (
	"testing"

	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

// helper: build a MatchResult with a Strict-confidence nginx profile
// whose behavior is whatever the caller supplies.
func strictMatch(role string, b parser.ConfigDerivedBehavior) MatchResult {
	p := minimalProfile()
	p.Confidence = ConfidenceStrict
	p.Key.App = "nginx"
	p.Key.Role = role
	p.Behavior = b
	return MatchResult{Profile: &p, Confidence: ConfidenceStrict, Reason: "strict match"}
}

func newRuntime() *Runtime { return NewRuntime(DefaultInvariants()) }

// ─── 1. Forever-suspicious actions always hard-deny ─────────────────────
func TestRuntime_AlwaysSuspicious_HardDeny(t *testing.T) {
	r := newRuntime()
	cases := []string{"ptrace_attach", "memfd_exec", "process_vm_writev"}
	for _, action := range cases {
		t.Run(action, func(t *testing.T) {
			d, reason := r.Evaluate(MatchResult{Confidence: ConfidenceStrict}, EventFacts{
				PID: 100, Action: action,
			})
			if d != DecisionHardDeny {
				t.Errorf("Decision=%v, want HardDeny", d)
			}
			if reason == "" {
				t.Error("expected an operator-readable reason")
			}
		})
	}
}

// Even with a (theoretically) signed profile saying "memfd_exec is OK",
// the invariant beats the profile. Defense in depth.
func TestRuntime_AlwaysSuspicious_BeatsProfile(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{})
	d, _ := r.Evaluate(m, EventFacts{PID: 100, Action: "memfd_exec"})
	if d != DecisionHardDeny {
		t.Errorf("invariant must beat profile; Decision=%v", d)
	}
}

// ─── 2. Protected-paths write/exec hard-deny ────────────────────────────
func TestRuntime_ProtectedPath_WriteVerifyUntilT07(t *testing.T) {
	// After the 2026-05-23 calibration (see runtime.go rules A/B/D), an
	// attributed non-trusted writer to a protected path returns Verify,
	// not HardDeny — the verifier engine (T07) will re-promote when ready.
	// Exec invariants and role invariants remain HardDeny (see other
	// tests in this file + runtime_calibration_test.go).
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{
		WriteRoots: []string{"/etc/", "/var/log/nginx/"},
	})
	cases := []string{
		"/etc/shadow", "/etc/psa/.psa.shadow",
		"/var/lib/mysql/ibdata1", "/etc/cron.d/backup",
		"/root/.ssh/authorized_keys", "/boot/vmlinuz",
	}
	for _, path := range cases {
		t.Run(path, func(t *testing.T) {
			d, _ := r.Evaluate(m, EventFacts{
				PID: 100, Comm: "evilbinary",
				Action: "file_write", Path: path,
			})
			if d != DecisionVerify {
				t.Errorf("write to %s: Decision=%v, want Verify (calibration A)", path, d)
			}
		})
	}
}

func TestRuntime_ProtectedPath_ExecHardDeny(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{})
	d, _ := r.Evaluate(m, EventFacts{
		PID:         100,
		Action:      "exec",
		TargetImage: "/usr/local/psa/admin/bin/admin",
	})
	if d != DecisionHardDeny {
		t.Errorf("exec of protected path: Decision=%v, want HardDeny", d)
	}
}

// ─── 3. Role-invariant: web role + shell exec → hard-deny ───────────────
func TestRuntime_WebRoleShellExec_HardDeny(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{
		// Even if profile allowed /bin/sh, role invariant should beat it.
		ExecAllowed: []string{"/bin/sh"},
	})
	d, reason := r.Evaluate(m, EventFacts{
		PID:         100,
		Action:      "exec",
		TargetImage: "/bin/sh",
		Role:        "nginx-reverse-proxy",
	})
	if d != DecisionHardDeny {
		t.Errorf("web+sh: Decision=%v, want HardDeny", d)
	}
	if reason == "" || !contains(reason, "role-invariant") {
		t.Errorf("reason should mention role-invariant, got: %q", reason)
	}
}

func TestRuntime_ApacheCGIShellExec_HardDeny(t *testing.T) {
	r := newRuntime()
	m := strictMatch("apache-cgi", parser.ConfigDerivedBehavior{})
	for _, shell := range []string{"/bin/bash", "/usr/bin/python3", "/usr/bin/nc"} {
		t.Run(shell, func(t *testing.T) {
			d, _ := r.Evaluate(m, EventFacts{
				PID: 100, Action: "exec", TargetImage: shell, Role: "apache-cgi",
			})
			if d != DecisionHardDeny {
				t.Errorf("apache-cgi + %s: Decision=%v, want HardDeny", shell, d)
			}
		})
	}
}

// Non-web roles should NOT be subject to web-role exec deny.
func TestRuntime_NonWebRole_ShellExec_NotHardDeny(t *testing.T) {
	r := newRuntime()
	// sshd default doesn't have a hard-deny entry for /bin/bash.
	m := strictMatch("sshd-default", parser.ConfigDerivedBehavior{
		ExecAllowed: []string{"/bin/bash"},
	})
	d, _ := r.Evaluate(m, EventFacts{
		PID: 100, Action: "exec", TargetImage: "/bin/bash", Role: "sshd-default",
	})
	if d == DecisionHardDeny {
		t.Errorf("sshd-default + /bin/bash should NOT hard-deny; got %v", d)
	}
}

// ─── 4. Unprofiled returns DecisionUnknown ──────────────────────────────
func TestRuntime_NoMatch_Unknown(t *testing.T) {
	r := newRuntime()
	d, _ := r.Evaluate(MatchResult{Confidence: ConfidenceUnprofiled}, EventFacts{
		PID: 100, Action: "file_open", Path: "/tmp/x",
	})
	if d != DecisionUnknown {
		t.Errorf("Unprofiled match should return Unknown, got %v", d)
	}
}

// ─── 5. BRP envelope: inside = Allow, outside = Verify ──────────────────
func TestRuntime_FileWrite_InsideEnvelope_Allow(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{
		WriteRoots: []string{"/var/log/nginx/", "/var/cache/nginx/"},
	})
	d, _ := r.Evaluate(m, EventFacts{
		PID: 100, Action: "file_write", Path: "/var/log/nginx/access.log",
	})
	if d != DecisionAllow {
		t.Errorf("write inside envelope: Decision=%v, want Allow", d)
	}
}

func TestRuntime_FileWrite_OutsideEnvelope_Verify(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{
		WriteRoots: []string{"/var/log/nginx/"},
	})
	d, reason := r.Evaluate(m, EventFacts{
		PID: 100, Action: "file_write", Path: "/tmp/payload",
	})
	if d != DecisionVerify {
		t.Errorf("write outside envelope: Decision=%v, want Verify", d)
	}
	if !contains(reason, "outside declared WriteRoots") {
		t.Errorf("reason should describe envelope miss, got: %q", reason)
	}
}

func TestRuntime_FileRead_InsideReadOrWriteRoots(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{
		ReadRoots:  []string{"/etc/nginx/", "/var/www/"},
		WriteRoots: []string{"/var/log/nginx/"},
	})
	cases := []struct {
		path  string
		want  Decision
	}{
		{"/etc/nginx/nginx.conf", DecisionAllow},
		{"/var/www/index.html", DecisionAllow},
		{"/var/log/nginx/access.log", DecisionAllow}, // WriteRoot also satisfies read
		{"/home/user/secret.txt", DecisionVerify},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			d, _ := r.Evaluate(m, EventFacts{
				PID: 100, Action: "file_open", Path: c.path, Mode: "read",
			})
			if d != c.want {
				t.Errorf("%s: Decision=%v, want %v", c.path, d, c.want)
			}
		})
	}
}

func TestRuntime_NetConnect_UpstreamMatch(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{
		UpstreamHosts: []string{"backend:8080", "api.internal:443"},
	})
	cases := []struct {
		host string
		port uint16
		want Decision
	}{
		{"backend", 8080, DecisionAllow},
		{"api.internal", 443, DecisionAllow},
		{"backend", 9999, DecisionVerify}, // wrong port
		{"evil.com", 443, DecisionVerify}, // wrong host
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			d, _ := r.Evaluate(m, EventFacts{
				PID: 100, Action: "net_connect", DestHost: c.host, DestPort: c.port,
			})
			if d != c.want {
				t.Errorf("%s:%d → Decision=%v, want %v", c.host, c.port, d, c.want)
			}
		})
	}
}

func TestRuntime_NetConnect_UpstreamSocket(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-fastcgi", parser.ConfigDerivedBehavior{
		UpstreamSockets: []string{"/run/php/php-fpm.sock"},
	})
	d, _ := r.Evaluate(m, EventFacts{
		PID: 100, Action: "net_connect", DestSocket: "/run/php/php-fpm.sock",
	})
	if d != DecisionAllow {
		t.Errorf("declared socket: Decision=%v, want Allow", d)
	}
	d2, _ := r.Evaluate(m, EventFacts{
		PID: 100, Action: "net_connect", DestSocket: "/tmp/evil.sock",
	})
	if d2 != DecisionVerify {
		t.Errorf("undeclared socket: Decision=%v, want Verify", d2)
	}
}

func TestRuntime_NetListen_PortMatch(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-static", parser.ConfigDerivedBehavior{
		ListenPorts: []int{80, 443},
	})
	d, _ := r.Evaluate(m, EventFacts{PID: 100, Action: "net_listen", DestPort: 443})
	if d != DecisionAllow {
		t.Errorf("declared port: Decision=%v, want Allow", d)
	}
	d2, _ := r.Evaluate(m, EventFacts{PID: 100, Action: "net_listen", DestPort: 9999})
	if d2 != DecisionVerify {
		t.Errorf("undeclared port: Decision=%v, want Verify", d2)
	}
}

// ─── 6. Empty ExecAllowed means no restriction ──────────────────────────
func TestRuntime_EmptyExecAllowed_NoRestriction(t *testing.T) {
	r := newRuntime()
	// systemd-like profile: legitimately execs arbitrary helpers.
	m := strictMatch("systemd-default", parser.ConfigDerivedBehavior{
		ExecAllowed: nil,
	})
	d, _ := r.Evaluate(m, EventFacts{
		PID: 100, Action: "exec", TargetImage: "/usr/bin/curl", Role: "systemd-default",
	})
	if d != DecisionAllow {
		t.Errorf("empty ExecAllowed should allow; got %v", d)
	}
}

// ─── 7. Unknown action falls through to Allow ───────────────────────────
func TestRuntime_UnknownAction_FallthroughAllow(t *testing.T) {
	r := newRuntime()
	m := strictMatch("nginx-reverse-proxy", parser.ConfigDerivedBehavior{})
	d, _ := r.Evaluate(m, EventFacts{PID: 100, Action: "weird_unhandled_action"})
	if d != DecisionAllow {
		t.Errorf("unknown action fallthrough should Allow; got %v", d)
	}
}

// ─── 8. Decision string round-trip ──────────────────────────────────────
func TestDecision_String(t *testing.T) {
	cases := map[Decision]string{
		DecisionAllow:    "allow",
		DecisionVerify:   "verify",
		DecisionHardDeny: "hard_deny",
		DecisionUnknown:  "unknown",
		Decision(99):     "invalid",
	}
	for d, want := range cases {
		if got := d.String(); got != want {
			t.Errorf("Decision(%d).String() = %q, want %q", d, got, want)
		}
	}
}

// helper
func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
