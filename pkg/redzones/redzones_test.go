package redzones

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/execguard"
)

func TestDefault_NotEmpty(t *testing.T) {
	p := Default()
	if len(p.ExecPaths) == 0 {
		t.Fatal("ExecPaths must not be empty")
	}
	if len(p.WriteZones) == 0 {
		t.Fatal("WriteZones must not be empty")
	}
	if len(p.DenySyscalls) == 0 {
		t.Fatal("DenySyscalls must not be empty")
	}
}

func TestWebWorkerExecRules_ShellIsDenied(t *testing.T) {
	rules := Default().WebWorkerExecRules()
	if len(rules) == 0 {
		t.Fatal("expected non-empty exec rules")
	}
	for _, r := range rules {
		if r.Decision != execguard.Deny {
			t.Errorf("rule %+v is not Deny", r)
		}
		// Every rule must match something
		if r.PathEquals == "" && r.PathHasPrefix == "" && r.PathHasSuffix == "" && r.PathContains == "" {
			t.Errorf("rule has no path matcher: %+v", r)
		}
	}
}

func TestWebWorkerExecRules_NoDuplicates(t *testing.T) {
	rules := Default().WebWorkerExecRules()
	seen := map[string]bool{}
	for _, r := range rules {
		key := r.PathEquals + "|" + r.PathHasPrefix
		if seen[key] {
			t.Errorf("duplicate rule key: %q", key)
		}
		seen[key] = true
	}
}

func TestWebWorkerExecRules_PrefixWildcard(t *testing.T) {
	p := &Policy{
		ExecPaths: []string{"/usr/bin/python*"},
	}
	rules := p.WebWorkerExecRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if r.PathHasPrefix != "/usr/bin/python" {
		t.Errorf("expected PathHasPrefix=/usr/bin/python, got %q", r.PathHasPrefix)
	}
	if r.PathEquals != "" {
		t.Errorf("expected no PathEquals for wildcard entry, got %q", r.PathEquals)
	}
}

func TestWebWorkerExecRules_ExactPath(t *testing.T) {
	p := &Policy{
		ExecPaths: []string{"/bin/sh"},
	}
	rules := p.WebWorkerExecRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].PathEquals != "/bin/sh" {
		t.Errorf("expected PathEquals=/bin/sh, got %q", rules[0].PathEquals)
	}
}

func TestNilPolicy_Safe(t *testing.T) {
	var p *Policy
	if p.WebWorkerExecRules() != nil {
		t.Error("nil policy should return nil exec rules")
	}
	if p.WriteZonePrefixes() != nil {
		t.Error("nil policy should return nil write zones")
	}
	if p.ReadZonePrefixes() != nil {
		t.Error("nil policy should return nil read zones")
	}
	if p.SyscallNames() != nil {
		t.Error("nil policy should return nil syscalls")
	}
}

func TestDefault_ContainsExpectedShells(t *testing.T) {
	p := Default()
	shells := []string{"/bin/sh", "/bin/bash", "/usr/bin/bash"}
	for _, s := range shells {
		found := false
		for _, ep := range p.ExecPaths {
			if ep == s {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in ExecPaths", s)
		}
	}
}

func TestDefault_ContainsExpectedSyscalls(t *testing.T) {
	p := Default()
	want := []string{"ptrace", "bpf", "userfaultfd"}
	for _, sc := range want {
		found := false
		for _, s := range p.DenySyscalls {
			if s == sc {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected syscall %q in DenySyscalls", sc)
		}
	}
}

func TestDefault_WriteZonesAbsolute(t *testing.T) {
	p := Default()
	for _, z := range p.WriteZones {
		if !strings.HasPrefix(z, "/") {
			t.Errorf("write zone %q is not an absolute path", z)
		}
	}
}
