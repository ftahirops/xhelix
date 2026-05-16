package bpfprobe

import "testing"

func TestCompareEmpty(t *testing.T) {
	if !Compare(Snapshot{}, Snapshot{}).IsEmpty() {
		t.Fatal("empty vs empty should be empty diff")
	}
}

func TestCompareAddRemove(t *testing.T) {
	base := Snapshot{Progs: []ProgInfo{
		{ID: 1, Name: "old", Tag: "aaaa1111"},
		{ID: 2, Name: "shared", Tag: "bbbb2222"},
	}}
	cur := Snapshot{Progs: []ProgInfo{
		{ID: 2, Name: "shared", Tag: "bbbb2222"},
		{ID: 3, Name: "new", Tag: "cccc3333"},
	}}
	d := Compare(base, cur)
	if len(d.Added) != 1 || d.Added[0].Tag != "cccc3333" {
		t.Errorf("added = %+v", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0].Tag != "aaaa1111" {
		t.Errorf("removed = %+v", d.Removed)
	}
}

func TestCompareNoTagFallsBackToNameType(t *testing.T) {
	base := Snapshot{Progs: []ProgInfo{{ID: 1, Name: "x", Type: 2}}}
	cur := Snapshot{Progs: []ProgInfo{{ID: 1, Name: "x", Type: 2}}}
	if !Compare(base, cur).IsEmpty() {
		t.Fatal("same name+type should match without tag")
	}
}

func TestIsWhitelistedByTag(t *testing.T) {
	wl := []Whitelist{{Tag: "deadbeef"}}
	if !IsWhitelisted(ProgInfo{Tag: "deadbeef"}, wl) {
		t.Fatal("tag match should whitelist")
	}
	if IsWhitelisted(ProgInfo{Tag: "00000000"}, wl) {
		t.Fatal("different tag should not whitelist")
	}
}

func TestIsWhitelistedByNameCaseInsensitive(t *testing.T) {
	wl := []Whitelist{{Name: "tp_sys_enter_execve"}}
	if !IsWhitelisted(ProgInfo{Name: "TP_SYS_ENTER_EXECVE"}, wl) {
		t.Fatal("case-insensitive name match should whitelist")
	}
}

func TestFilterUnknown(t *testing.T) {
	s := Snapshot{Progs: []ProgInfo{
		{Name: "tp_sys_enter_execve"}, // xhelix's own — whitelisted
		{Name: "unknown_attacker_prog"},
	}}
	out := FilterUnknown(s, XhelixWhitelist())
	if len(out) != 1 || out[0].Name != "unknown_attacker_prog" {
		t.Fatalf("filter wrong: %+v", out)
	}
}

func TestXhelixWhitelistNonEmpty(t *testing.T) {
	if len(XhelixWhitelist()) < 5 {
		t.Fatalf("xhelix whitelist too small: %d", len(XhelixWhitelist()))
	}
}

func TestProgTypeName(t *testing.T) {
	cases := map[uint32]string{
		2:   "BPF_PROG_TYPE_KPROBE",
		5:   "BPF_PROG_TYPE_TRACEPOINT",
		29:  "BPF_PROG_TYPE_LSM",
		31:  "BPF_PROG_TYPE_SYSCALL",
		999: "BPF_PROG_TYPE_999",
	}
	for in, want := range cases {
		if got := ProgTypeName(in); got != want {
			t.Errorf("ProgTypeName(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestEqualFold(t *testing.T) {
	if !equalFold("Foo", "fOO") {
		t.Fatal("Foo == fOO case-fold")
	}
	if equalFold("foo", "fooo") {
		t.Fatal("different lengths should not match")
	}
	if equalFold("foo", "bar") {
		t.Fatal("different chars should not match")
	}
}

func TestSnapshotNowDoesNotPanic(t *testing.T) {
	// Best-effort: as non-root we may get nothing; just confirm no
	// panic, and the result type is sensible.
	snap, err := SnapshotNow()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Progs == nil {
		snap.Progs = []ProgInfo{} // both nil and empty are valid
	}
}
