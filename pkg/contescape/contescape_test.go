package contescape

import "testing"

func TestPivotRootByRuntimeIsBenign(t *testing.T) {
	f := Classify(Spec{
		Syscall: SyscallPivotRoot,
		Exe:     "/usr/sbin/runc", Comm: "runc",
	})
	if f.Severity != SeverityNotice { // SeverityInfo() maps to Notice
		t.Fatalf("severity = %s, want notice", f.Severity)
	}
}

func TestPivotRootInContainerByWorkloadIsCritical(t *testing.T) {
	f := Classify(Spec{
		Syscall:     SyscallPivotRoot,
		Comm:        "exploit-poc",
		Exe:         "/tmp/exploit",
		CGroupClass: "container",
	})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical", f.Severity)
	}
}

func TestPivotRootByNonRuntimeOnHostIsHigh(t *testing.T) {
	f := Classify(Spec{
		Syscall: SyscallPivotRoot,
		Comm:    "weird",
		Exe:     "/tmp/weird",
		CGroupClass: "system",
	})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestPivotRootByRuntimeDescendant(t *testing.T) {
	f := Classify(Spec{
		Syscall:   SyscallPivotRoot,
		Exe:       "/usr/bin/setup",
		Comm:      "setup",
		Ancestors: []string{"/usr/bin/setup", "/usr/sbin/runc"},
	})
	if f.Severity != SeverityNotice {
		t.Fatalf("descendant of runtime → notice; got %s", f.Severity)
	}
}

func TestUnshareWithNoFlagsIsNone(t *testing.T) {
	f := Classify(Spec{Syscall: SyscallUnshare, Flags: 0})
	if f.Severity != SeverityNone {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestUnshareUserInsideContainerCritical(t *testing.T) {
	f := Classify(Spec{
		Syscall: SyscallUnshare,
		Flags:   CLONE_NEWUSER | CLONE_NEWNS,
		Comm:    "exploit",
		Exe:     "/tmp/x",
		CGroupClass: "container",
	})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
	if len(f.Namespaces) != 2 {
		t.Errorf("namespaces = %v", f.Namespaces)
	}
}

func TestUnshareUnderWebDaemonHigh(t *testing.T) {
	f := Classify(Spec{
		Syscall:   SyscallUnshare,
		Flags:     CLONE_NEWUSER | CLONE_NEWNS,
		Comm:      "cmd",
		Exe:       "/tmp/cmd",
		ParentExe: "/usr/sbin/nginx",
		CGroupClass: "system",
	})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestUnshareUserAloneIsHigh(t *testing.T) {
	f := Classify(Spec{
		Syscall: SyscallUnshare,
		Flags:   CLONE_NEWUSER,
		Comm:    "tool",
		Exe:     "/usr/bin/tool",
		CGroupClass: "system",
	})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s, want high", f.Severity)
	}
}

func TestUnshareByKnownRuntimeIsNotice(t *testing.T) {
	f := Classify(Spec{
		Syscall: SyscallUnshare,
		Flags:   CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER,
		Comm:    "runc",
		Exe:     "/usr/sbin/runc",
	})
	if f.Severity != SeverityNotice {
		t.Fatalf("severity = %s, want notice", f.Severity)
	}
}

func TestUnshareBenignFlagsBelowRiskySetIsWarn(t *testing.T) {
	// CLONE_NEWUTS alone — not in the risky-set, not a runtime.
	f := Classify(Spec{
		Syscall: SyscallUnshare,
		Flags:   CLONE_NEWUTS,
		Comm:    "x", Exe: "/tmp/x",
	})
	// risky = 0 → falls to default Notice branch.
	if f.Severity != SeverityNotice {
		t.Fatalf("severity = %s, want notice", f.Severity)
	}
}

func TestDecodeFlagsAllNamespaces(t *testing.T) {
	all := CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWPID |
		CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWCGROUP
	got := decodeFlags(all)
	if len(got) != 7 {
		t.Fatalf("got %d namespaces, want 7: %v", len(got), got)
	}
}

func TestDecodeFlagsZero(t *testing.T) {
	if got := decodeFlags(0); len(got) != 0 {
		t.Fatalf("zero flags should decode to empty; got %v", got)
	}
}

func TestIsKnownRuntimePrefixMatch(t *testing.T) {
	if !isKnownRuntime("containerd-shim-runc-v3") {
		t.Fatal("containerd-shim prefix should match")
	}
	if isKnownRuntime("nginx") {
		t.Fatal("nginx is not a runtime")
	}
}

func TestBasename(t *testing.T) {
	if basename("/usr/sbin/runc") != "runc" {
		t.Fatal("basename failed")
	}
	if basename("runc") != "runc" {
		t.Fatal("basename of bare name failed")
	}
}
