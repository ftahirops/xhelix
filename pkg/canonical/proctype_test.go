package canonical

import (
	"os"
	"strconv"
	"testing"
)

func TestProcKey_IsValidEqualString(t *testing.T) {
	zero := ProcKey{}
	if zero.IsValid() {
		t.Error("zero ProcKey should not be valid")
	}
	if zero.String() != "0@0" {
		t.Errorf("zero String = %q, want 0@0", zero.String())
	}

	a := ProcKey{PID: 100, StartTicks: 2048}
	b := ProcKey{PID: 100, StartTicks: 2048}
	c := ProcKey{PID: 100, StartTicks: 4096} // same PID, different start = different process
	d := ProcKey{PID: 200, StartTicks: 2048} // different PID

	if !a.IsValid() {
		t.Error("ProcKey with PID + StartTicks should be valid")
	}
	if !a.Equal(b) {
		t.Error("identical ProcKeys should be Equal")
	}
	if a.Equal(c) {
		t.Error("same PID + different StartTicks must NOT be Equal (PID reuse)")
	}
	if a.Equal(d) {
		t.Error("different PIDs must NOT be Equal")
	}
	if a.String() != "100@2048" {
		t.Errorf("String = %q, want 100@2048", a.String())
	}
}

func TestParseStartTime_SimpleStatLine(t *testing.T) {
	// Synthetic stat line with known field 22.
	// Fields after closing paren of comm:
	//   3 state, 4 ppid, 5 pgrp, 6 session, 7 tty_nr, 8 tpgid,
	//   9 flags, 10 minflt, 11 cminflt, 12 majflt, 13 cmajflt,
	//   14 utime, 15 stime, 16 cutime, 17 cstime, 18 priority,
	//   19 nice, 20 num_threads, 21 itrealvalue, 22 starttime
	// In our zero-indexed post-paren slice that's index 19.
	//
	// We need 20 fields total to reach starttime at index 19.
	line := []byte("1234 (bash) S 1 1 1 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 8675309 99999 99999 99999 99999 99999 99999")
	ticks, err := parseStartTime(line)
	if err != nil {
		t.Fatalf("parseStartTime error: %v", err)
	}
	if ticks != 8675309 {
		t.Errorf("ticks = %d, want 8675309", ticks)
	}
}

func TestParseStartTime_CommWithSpacesAndParens(t *testing.T) {
	// Comm field can contain spaces and parens (rare but legal).
	// Real example: a binary literally named "weird (parens) name".
	line := []byte("42 (weird (parens) name) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 0 0 0 0 0 0 0")
	ticks, err := parseStartTime(line)
	if err != nil {
		t.Fatalf("parseStartTime error: %v", err)
	}
	if ticks != 555 {
		t.Errorf("ticks = %d, want 555 (parser must find LAST closing paren)", ticks)
	}
}

func TestParseStartTime_MalformedLines(t *testing.T) {
	cases := map[string][]byte{
		"empty":            []byte(""),
		"no closing paren": []byte("1234 (bash S 1 1 1"),
		"too few fields":   []byte("1234 (bash) S 1 1 1"),
		"starttime is zero": []byte("1 (init) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseStartTime(line)
			if err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestReadProcKey_RealProcess(t *testing.T) {
	// Read our own /proc/self/stat (the test binary's pid).
	pid := uint32(os.Getpid())
	k, err := ReadProcKey(pid)
	if err != nil {
		t.Fatalf("ReadProcKey(self): %v", err)
	}
	if !k.IsValid() {
		t.Errorf("self key not valid: %+v", k)
	}
	if k.PID != pid {
		t.Errorf("key.PID = %d, want %d", k.PID, pid)
	}
	if k.StartTicks == 0 {
		t.Error("self start ticks should be > 0")
	}
}

func TestReadProcKey_NonexistentProcess(t *testing.T) {
	// Find a pid that almost certainly does not exist.
	// /proc/sys/kernel/pid_max is typically 4194304; pick something
	// above what any real system would have allocated.
	highPID := uint32(99999999)
	_, err := ReadProcKey(highPID)
	if err == nil {
		t.Fatalf("expected error for non-existent pid %d", highPID)
	}
	if _, ok := err.(ProcKeyNotFound); !ok {
		t.Errorf("expected ProcKeyNotFound, got %T: %v", err, err)
	}
}

func TestReadProcKey_PIDZero(t *testing.T) {
	_, err := ReadProcKey(0)
	if err == nil {
		t.Error("PID 0 should error")
	}
}

func BenchmarkReadProcKey_Self(b *testing.B) {
	pid := uint32(os.Getpid())
	for i := 0; i < b.N; i++ {
		_, err := ReadProcKey(pid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Sanity: confirm we can ReadProcKey for every entry currently in /proc.
// This catches edge cases in parsing across whatever real processes
// happen to be running on the test machine.
func TestReadProcKey_AllRunningProcesses(t *testing.T) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Skip("/proc not available")
	}
	tried, succeeded := 0, 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		tried++
		k, err := ReadProcKey(uint32(pid))
		if err != nil {
			if _, ok := err.(ProcKeyNotFound); ok {
				continue // raced exit, fine
			}
			t.Errorf("pid %d: %v", pid, err)
			continue
		}
		if !k.IsValid() {
			t.Errorf("pid %d returned invalid key %+v", pid, k)
			continue
		}
		succeeded++
	}
	if tried == 0 {
		t.Skip("no pids found in /proc")
	}
	if succeeded == 0 {
		t.Errorf("read %d /proc entries, succeeded on 0", tried)
	}
	t.Logf("read ProcKey for %d/%d running processes", succeeded, tried)
}
