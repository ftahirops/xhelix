package seccomp

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func TestLookupSyscall(t *testing.T) {
	nr, ok := LookupSyscall("ptrace", ArchX86_64)
	if !ok || nr != 101 {
		t.Fatalf("x86_64 ptrace nr=%d ok=%v want 101 true", nr, ok)
	}
	nr, ok = LookupSyscall("ptrace", ArchAArch64)
	if !ok || nr != 117 {
		t.Fatalf("aarch64 ptrace nr=%d ok=%v want 117 true", nr, ok)
	}
	if _, ok := LookupSyscall("totally_made_up", ArchX86_64); ok {
		t.Fatal("unknown syscall should return ok=false")
	}
}

func TestKnownSyscalls_CoverAllNeverLearnable(t *testing.T) {
	// Every NeverLearnableSyscall MUST have an NR on both arches we
	// support — that's the whole point.
	for _, a := range []Arch{ArchX86_64, ArchAArch64} {
		for _, name := range contracts.NeverLearnableSyscalls {
			if _, ok := LookupSyscall(name, a); !ok {
				t.Errorf("%s: never-learnable syscall %q has no NR", a, name)
			}
		}
	}
}

func TestCompile_NginxStaticIncludesAllInvariants(t *testing.T) {
	c, _ := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic)
	p, err := Compile(c, ArchX86_64)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// All never-learnable must end up in Denied.
	for _, name := range contracts.NeverLearnableSyscalls {
		found := false
		for _, d := range p.Denied {
			if d == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Denied missing never-learnable %q (skipped=%v)", name, p.Skipped)
		}
	}
}

func TestCompile_DeterministicOrder(t *testing.T) {
	c := protectedsvc.ServiceContract{
		DenySyscalls: []string{"ptrace", "bpf", "mount", "ptrace"}, // dup
	}
	p1, _ := Compile(c, ArchX86_64)
	c.DenySyscalls = []string{"mount", "bpf", "ptrace"} // different order
	p2, _ := Compile(c, ArchX86_64)

	if len(p1.Instructions) != len(p2.Instructions) {
		t.Fatalf("instruction count differs: %d vs %d", len(p1.Instructions), len(p2.Instructions))
	}
	for i := range p1.Instructions {
		if p1.Instructions[i] != p2.Instructions[i] {
			t.Fatalf("instruction %d differs: %+v vs %+v", i, p1.Instructions[i], p2.Instructions[i])
		}
	}
}

func TestCompile_FilterShape(t *testing.T) {
	c := protectedsvc.ServiceContract{
		DenySyscalls: []string{"ptrace", "bpf"},
	}
	p, err := Compile(c, ArchX86_64)
	if err != nil {
		t.Fatal(err)
	}
	// Expected layout:
	//   0: LD  arch
	//   1: JEQ AUDIT_ARCH, +1, +0
	//   2: RET EPERM            (arch mismatch)
	//   3: LD  nr
	//   4: JEQ bpf,  +0, +1
	//   5: RET EPERM
	//   6: JEQ ptrace, +0, +1
	//   7: RET EPERM
	//   8: RET ALLOW
	if got := len(p.Instructions); got != 9 {
		t.Fatalf("expected 9 instructions, got %d:\n%s", got, p.Render())
	}
	last := p.Instructions[len(p.Instructions)-1]
	if last.K != seccompRetAllow {
		t.Fatalf("final instruction should be ALLOW; got K=%x", last.K)
	}
}

func TestCompile_UnsupportedArch(t *testing.T) {
	c := protectedsvc.ServiceContract{DenySyscalls: []string{"ptrace"}}
	if _, err := Compile(c, Arch("riscv64")); err == nil {
		t.Fatal("riscv64 should be unsupported")
	}
}

func TestCompile_UnknownSyscallSkippedNotFatal(t *testing.T) {
	c := protectedsvc.ServiceContract{
		DenySyscalls: []string{"ptrace", "future_syscall_2030"},
	}
	p, err := Compile(c, ArchX86_64)
	if err != nil {
		t.Fatalf("unknown syscall should not be fatal: %v", err)
	}
	if len(p.Skipped) != 1 || p.Skipped[0] != "future_syscall_2030" {
		t.Fatalf("Skipped wrong: %v", p.Skipped)
	}
	if len(p.Denied) != 1 || p.Denied[0] != "ptrace" {
		t.Fatalf("Denied wrong: %v", p.Denied)
	}
}

func TestCompile_EmptyContractStillValid(t *testing.T) {
	c := protectedsvc.ServiceContract{} // nothing denied
	p, err := Compile(c, ArchX86_64)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("empty profile should still validate: %v", err)
	}
	// Should have just the arch-check (3 instr) + load-nr (1) + allow (1) = 5
	if got := len(p.Instructions); got != 5 {
		t.Fatalf("empty profile expected 5 instr, got %d", got)
	}
}

func TestValidate_RejectsTooLong(t *testing.T) {
	p := Profile{Arch: ArchX86_64, Instructions: make([]Instruction, MaxLen+1)}
	if err := p.Validate(); err == nil {
		t.Fatal("over-long profile should fail validation")
	}
}

func TestSystemdDirective(t *testing.T) {
	c := protectedsvc.ServiceContract{
		DenySyscalls: []string{"ptrace", "bpf", "mount"},
	}
	d := SystemdDirective(c)
	if !strings.HasPrefix(d, "SystemCallFilter=~") {
		t.Fatalf("missing ~ deny-list prefix: %q", d)
	}
	for _, name := range []string{"bpf", "mount", "ptrace"} {
		if !strings.Contains(d, name) {
			t.Errorf("missing %q in directive: %q", name, d)
		}
	}

	// Empty contract → empty directive.
	if SystemdDirective(protectedsvc.ServiceContract{}) != "" {
		t.Fatal("empty contract should produce empty directive")
	}
}

func TestRender_HumanReadable(t *testing.T) {
	c, _ := contracts.Builtin(protectedsvc.KindNginx, protectedsvc.RoleStatic)
	p, _ := Compile(c, ArchX86_64)
	out := p.Render()
	if !strings.Contains(out, "seccomp filter") {
		t.Fatalf("Render header missing: %s", out)
	}
	if !strings.Contains(out, "deny") {
		t.Fatalf("Render should mention deny count: %s", out)
	}
}

func TestCurrentArch_KnownPlatforms(t *testing.T) {
	a := CurrentArch()
	// On amd64 dev/CI hosts, this returns ArchX86_64. On arm64 it
	// returns ArchAArch64. Anywhere else, "".
	switch a {
	case ArchX86_64, ArchAArch64, "":
		// ok
	default:
		t.Fatalf("unexpected CurrentArch: %q", a)
	}
}
