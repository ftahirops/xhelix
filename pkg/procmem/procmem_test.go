package procmem

import (
	"os"
	"testing"
)

func TestPcInRanges(t *testing.T) {
	r := []memRange{
		{start: 0x400000, end: 0x401000},
		{start: 0x7f0000000000, end: 0x7f0000010000},
	}
	cases := map[uint64]bool{
		0x400500:       true,
		0x401000:       false, // exclusive end
		0x3ffFFF:       false,
		0x7f0000005000: true,
		0x800000000000: false,
	}
	for pc, want := range cases {
		if got := pcInRanges(pc, r); got != want {
			t.Errorf("pcInRanges(0x%x)=%v want %v", pc, got, want)
		}
	}
}

func TestScannerNoFalsePositiveOnSelf(t *testing.T) {
	// Running the scanner on our own /proc state must not flag the
	// test binary as having a thread-outside-module — Go's
	// runtime threads execute inside the Go binary's text segment.
	s := New(nil)
	fs := s.Scan()
	for _, f := range fs {
		if f.Kind != "deleted_exe" {
			// thread_outside_module shouldn't fire on healthy
			// processes that aren't JIT runtimes; the test
			// binary itself is one such healthy process.
			// Best-effort: don't fail on production-host noise;
			// just check none claim our own pid.
			if int(f.PID) == ourPID() {
				t.Errorf("scanner flagged self: %+v", f)
			}
		}
	}
}

func TestScannerHandlesEmptyProcGracefully(t *testing.T) {
	s := New(nil)
	_ = s.Scan() // must not panic on missing/perm-denied procs
}

// allowStub is a tiny Allowlister for tests.
type allowStub struct{ matchAll bool }

func (a allowStub) MatchAny(_, _ string) bool { return a.matchAll }

func TestAllowlistExempts(t *testing.T) {
	// With matchAll=true, nothing should be flagged as
	// thread_outside_module regardless of process state.
	s := New(allowStub{matchAll: true})
	fs := s.Scan()
	for _, f := range fs {
		if f.Kind == "thread_outside_module" {
			t.Errorf("allowlist failed to exempt: %+v", f)
		}
	}
}

func ourPID() int { return os.Getpid() }
