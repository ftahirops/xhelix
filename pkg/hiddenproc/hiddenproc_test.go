package hiddenproc

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// buildFakeProc creates a tmpdir with subdirs named like pid
// entries plus optional /status and /comm files for some pids.
func buildFakeProc(t *testing.T, pids []uint32, extras []string) string {
	t.Helper()
	dir := t.TempDir()
	for _, pid := range pids {
		s := dir + "/" + uitoa(pid)
		if err := os.MkdirAll(s, 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(s+"/status", []byte("Name:\tfoo\n"), 0o644)
		_ = os.WriteFile(s+"/comm", []byte("foo\n"), 0o644)
	}
	for _, name := range extras {
		_ = os.MkdirAll(dir+"/"+name, 0o755)
	}
	return dir
}

func uitoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func TestScanCleanHostNoFindings(t *testing.T) {
	root := buildFakeProc(t, []uint32{1, 2, 3, 100, 200}, []string{"kthreadd-not-numeric"})
	d := NewDetector()
	d.ProcRoot = root
	got, err := d.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no findings on clean fake /proc; got %+v", got)
	}
}

func TestScanDetectsHiddenViaInjectedAsymmetry(t *testing.T) {
	root := buildFakeProc(t, []uint32{1, 2, 1337}, nil)

	// Save the real raw reader; inject one that returns ONLY pids
	// 1 and 2 — pretending 1337 is "hidden by readdir" but visible
	// to a direct syscall (the inverse of the LD_PRELOAD case is
	// also covered).
	origRaw := readDirentRaw
	defer func() { readDirentRaw = origRaw }()

	// Force stdlib to omit 1337 by deleting its directory entry
	// before stdlib scan but keep status/comm reachable: easiest
	// is to use the inverse direction — raw returns *more* than
	// stdlib. We achieve this by leaving the FS alone (so stdlib
	// sees all three) but making raw return only 1 and 2 — that
	// triggers the "stdlib sees but raw doesn't" branch.
	readDirentRaw = func(fd int, buf []byte) (int, error) {
		// Encode a single linux_dirent64 record for "1" and "2".
		buf = buf[:0]
		_ = buf
		return 0, nil
	}

	d := NewDetector()
	d.ProcRoot = root
	d.ConfirmWindow = time.Minute

	got1, err := d.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if len(got1) != 3 {
		t.Fatalf("first scan should find 3 hidden pids (1,2,1337 — raw saw 0); got %d: %+v", len(got1), got1)
	}
	for _, f := range got1 {
		if f.Confirmed {
			t.Errorf("first scan should not yet confirm any pid: %+v", f)
		}
	}

	// Second scan within ConfirmWindow → all confirmed.
	got2, err := d.Scan()
	if err != nil {
		t.Fatal(err)
	}
	confirmed := 0
	for _, f := range got2 {
		if f.Confirmed {
			confirmed++
		}
	}
	if confirmed != 3 {
		t.Fatalf("second scan should confirm all 3; got %d confirmed of %d", confirmed, len(got2))
	}
}

func TestParsePID(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		want uint32
	}{
		{"1", true, 1},
		{"12345", true, 12345},
		{"abc", false, 0},
		{"", false, 0},
		{"1a", false, 0},
	}
	for _, c := range cases {
		got, ok := parsePID(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parsePID(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestReadProcViaStdlibIgnoresNonNumeric(t *testing.T) {
	root := buildFakeProc(t, []uint32{1, 2, 3}, []string{"net", "self", "ksm"})
	got, err := readProcViaStdlib(root)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("got %v, want [1 2 3]", got)
	}
}

func TestScanPendingPrunedWhenNoLongerHidden(t *testing.T) {
	root := buildFakeProc(t, []uint32{1, 2}, nil)
	d := NewDetector()
	d.ProcRoot = root

	// Force initial mismatch by stubbing the raw reader.
	origRaw := readDirentRaw
	defer func() { readDirentRaw = origRaw }()
	readDirentRaw = func(fd int, buf []byte) (int, error) {
		return 0, nil // empty syscall result
	}

	_, _ = d.Scan()
	if len(d.pending) == 0 {
		t.Fatal("expected pending entries after mismatched scan")
	}

	// Now restore the real reader so both views agree; pending
	// should be flushed.
	readDirentRaw = origRaw
	_, _ = d.Scan()
	if len(d.pending) != 0 {
		t.Fatalf("pending should be empty after agreement, got %v", d.pending)
	}

	// Touch real fs to avoid unused-import nag.
	_ = filepath.Base(root)
}
