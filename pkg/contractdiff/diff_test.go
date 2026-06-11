package contractdiff

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/contractcompiler"
)

func svc(unit string, execAllow, denySys []string) contractcompiler.CompiledService {
	return contractcompiler.CompiledService{Unit: unit, ExecAllow: execAllow, DenySyscalls: denySys}
}

func TestCompute_NoChange(t *testing.T) {
	a := &contractcompiler.CompiledContract{App: "x", ArtifactSHA: "h1",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"/usr/sbin/nginx"}, []string{"ptrace"})}}
	b := &contractcompiler.CompiledContract{App: "x", ArtifactSHA: "h1",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"/usr/sbin/nginx"}, []string{"ptrace"})}}
	d := Compute(a, b)
	if !d.Empty() {
		t.Errorf("identical contracts should diff empty, got %v", d.Changes)
	}
	if d.Unchanged == 0 {
		t.Error("expected unchanged count > 0")
	}
}

func TestCompute_AddRemoveExecAllow(t *testing.T) {
	from := &contractcompiler.CompiledContract{App: "x", ArtifactSHA: "h1",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"/usr/sbin/nginx", "/usr/bin/old"}, nil)}}
	to := &contractcompiler.CompiledContract{App: "x", ArtifactSHA: "h2",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"/usr/sbin/nginx", "/usr/bin/new"}, nil)}}
	d := Compute(from, to)
	var added, removed string
	for _, c := range d.Changes {
		if c.Kind == KindExecAllow && c.Op == OpAdded {
			added = c.Value
		}
		if c.Kind == KindExecAllow && c.Op == OpRemoved {
			removed = c.Value
		}
	}
	if added != "/usr/bin/new" {
		t.Errorf("added = %q, want /usr/bin/new", added)
	}
	if removed != "/usr/bin/old" {
		t.Errorf("removed = %q, want /usr/bin/old", removed)
	}
}

func TestCompute_ServiceAddedRemoved(t *testing.T) {
	from := &contractcompiler.CompiledContract{App: "x",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"/usr/sbin/nginx"}, nil)}}
	to := &contractcompiler.CompiledContract{App: "x",
		Services: []contractcompiler.CompiledService{svc("php-fpm", []string{"/usr/sbin/php-fpm"}, nil)}}
	d := Compute(from, to)
	var svcAdded, svcRemoved bool
	for _, c := range d.Changes {
		if c.Kind == KindService && c.Op == OpAdded && c.Value == "php-fpm" {
			svcAdded = true
		}
		if c.Kind == KindService && c.Op == OpRemoved && c.Value == "nginx" {
			svcRemoved = true
		}
	}
	if !svcAdded || !svcRemoved {
		t.Errorf("expected nginx removed + php-fpm added, got %v", d.Changes)
	}
}

func TestCompute_NilFromIsAllAdded(t *testing.T) {
	to := &contractcompiler.CompiledContract{App: "x", ArtifactSHA: "h1",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"/usr/sbin/nginx"}, []string{"ptrace"})}}
	d := Compute(nil, to)
	if d.Empty() {
		t.Fatal("nil prior version should show everything as added")
	}
	// nginx service add + exec_allow add + deny_syscalls add.
	if d.FromSHA != "" || d.ToSHA != "h1" {
		t.Errorf("SHAs wrong: from=%q to=%q", d.FromSHA, d.ToSHA)
	}
}

func TestCompute_Deterministic(t *testing.T) {
	from := &contractcompiler.CompiledContract{App: "x",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"a", "b", "c"}, nil)}}
	to := &contractcompiler.CompiledContract{App: "x",
		Services: []contractcompiler.CompiledService{svc("nginx", []string{"b", "d", "e"}, nil)}}
	d1 := Compute(from, to)
	d2 := Compute(from, to)
	if len(d1.Changes) != len(d2.Changes) {
		t.Fatal("nondeterministic change count")
	}
	for i := range d1.Changes {
		if d1.Changes[i] != d2.Changes[i] {
			t.Errorf("change order nondeterministic at %d: %v vs %v", i, d1.Changes[i], d2.Changes[i])
		}
	}
}
