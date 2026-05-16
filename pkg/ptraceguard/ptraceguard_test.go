package ptraceguard

import "testing"

func TestPokeTextIsCritical(t *testing.T) {
	f := Classify(Spec{Request: PTRACE_POKETEXT, SourcePID: 100, TargetPID: 200})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestSetRegsIsHigh(t *testing.T) {
	f := Classify(Spec{Request: PTRACE_SETREGS, SourcePID: 100, TargetPID: 200})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestAttachIsHigh(t *testing.T) {
	f := Classify(Spec{Request: PTRACE_ATTACH, SourcePID: 100, TargetPID: 200})
	if f.Severity != SeverityHigh {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestTraceMEIsNotice(t *testing.T) {
	f := Classify(Spec{Request: PTRACE_TRACEME, SourcePID: 100})
	if f.Severity != SeverityNotice {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestSelfTraceIsNotice(t *testing.T) {
	f := Classify(Spec{Request: PTRACE_ATTACH, SourcePID: 100, TargetPID: 100, IsSelfTrace: true})
	if f.Severity != SeverityNotice {
		t.Fatalf("severity = %s, want notice (self-trace)", f.Severity)
	}
}

func TestKnownDebuggerDowngradesAttach(t *testing.T) {
	f := Classify(Spec{
		Request: PTRACE_ATTACH, SourceComm: "gdb",
		SourcePID: 100, TargetPID: 200,
	})
	if f.Severity != SeverityWarn {
		t.Fatalf("severity = %s, want warn (gdb downgrade)", f.Severity)
	}
}

func TestKnownDebuggerDoesNotDowngradePoke(t *testing.T) {
	f := Classify(Spec{
		Request: PTRACE_POKETEXT, SourceComm: "gdb",
		SourcePID: 100, TargetPID: 200,
	})
	if f.Severity != SeverityCritical {
		t.Fatalf("POKETEXT must stay critical even for gdb; got %s", f.Severity)
	}
}

func TestHighValueTargetUpgrade(t *testing.T) {
	f := Classify(Spec{
		Request: PTRACE_PEEKDATA, // would be Warn
		SourcePID: 100, TargetPID: 22, TargetComm: "sshd",
	})
	if f.Severity != SeverityCritical {
		t.Fatalf("severity = %s, want critical (sshd target)", f.Severity)
	}
}

func TestContainerCallerUpgradesAttach(t *testing.T) {
	f := Classify(Spec{
		Request: PTRACE_ATTACH,
		SourcePID: 100, TargetPID: 200,
		CGroupClass: "container",
	})
	if f.Severity < SeverityHigh {
		t.Fatalf("severity = %s, want high+ (container caller)", f.Severity)
	}
}

func TestUnknownRequestCode(t *testing.T) {
	f := Classify(Spec{Request: 9999, SourcePID: 1, TargetPID: 2})
	if f.RequestName != "PTRACE_9999" {
		t.Fatalf("name = %q", f.RequestName)
	}
	if f.Severity != SeverityNotice {
		t.Fatalf("severity = %s", f.Severity)
	}
}

func TestIsInjection(t *testing.T) {
	for _, req := range []uint32{PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_POKEUSR, PTRACE_SETREGS, PTRACE_SETFPREGS} {
		if !IsInjection(req) {
			t.Errorf("IsInjection(%d) should be true", req)
		}
	}
	if IsInjection(PTRACE_PEEKDATA) {
		t.Error("PEEKDATA is not injection")
	}
}

func TestRequestNameStable(t *testing.T) {
	cases := map[uint32]string{
		PTRACE_POKETEXT: "PTRACE_POKETEXT",
		PTRACE_ATTACH:   "PTRACE_ATTACH",
		PTRACE_SEIZE:    "PTRACE_SEIZE",
	}
	for in, want := range cases {
		if got := RequestName(in); got != want {
			t.Errorf("RequestName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestKilLAndDetachAreNotice(t *testing.T) {
	for _, req := range []uint32{PTRACE_KILL, PTRACE_DETACH, PTRACE_CONT} {
		f := Classify(Spec{Request: req, SourcePID: 1, TargetPID: 2})
		if f.Severity != SeverityNotice {
			t.Errorf("req=%d severity = %s, want notice", req, f.Severity)
		}
	}
}

func TestBasenameExported(t *testing.T) {
	if Basename("/usr/bin/gdb") != "gdb" {
		t.Fatal("Basename failed")
	}
}
