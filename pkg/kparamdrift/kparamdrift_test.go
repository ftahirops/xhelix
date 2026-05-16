package kparamdrift

import (
	"os"
	"path/filepath"
	"testing"
)

// buildFakeProcSys creates a tmpdir mirroring /proc/sys with the
// given key→content map.
func buildFakeProcSys(t *testing.T, vals map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for k, v := range vals {
		full := filepath.Join(root, k)
		_ = os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSnapReadsValues(t *testing.T) {
	root := buildFakeProcSys(t, map[string]string{
		"kernel/yama/ptrace_scope":  "2\n",
		"kernel/kptr_restrict":      "1\n",
		"net/ipv4/tcp_syncookies":   "1\n",
		"fs/protected_hardlinks":    "1\n",
	})
	snap := Snap(root, nil)
	if v := snap.Values["kernel/yama/ptrace_scope"]; v.Numeric != 2 {
		t.Errorf("ptrace_scope = %d, want 2", v.Numeric)
	}
	if v := snap.Values["kernel/kptr_restrict"]; v.Numeric != 1 {
		t.Errorf("kptr_restrict = %d, want 1", v.Numeric)
	}
}

func TestCompareDetectsLooser(t *testing.T) {
	base := Snapshot{Values: map[string]Value{
		"kernel/yama/ptrace_scope": {Key: "kernel/yama/ptrace_scope", Raw: "2", Numeric: 2},
	}}
	cur := Snapshot{Values: map[string]Value{
		"kernel/yama/ptrace_scope": {Key: "kernel/yama/ptrace_scope", Raw: "0", Numeric: 0},
	}}
	d := Compare(base, cur, []Param{
		{Key: "kernel/yama/ptrace_scope", Direction: DirectionUp, HardenedFloor: 1},
	})
	if len(d.Drifts) != 1 {
		t.Fatalf("expected 1 drift; got %+v", d.Drifts)
	}
	if d.Drifts[0].Kind != DriftLooser {
		t.Errorf("kind = %s, want looser", d.Drifts[0].Kind)
	}
	if !d.Drifts[0].BelowFloor {
		t.Errorf("BelowFloor should be true (0 < floor 1)")
	}
	if !d.HasLooser() {
		t.Errorf("HasLooser should be true")
	}
}

func TestCompareDetectsStricter(t *testing.T) {
	base := Snapshot{Values: map[string]Value{
		"fs/protected_hardlinks": {Key: "fs/protected_hardlinks", Raw: "0", Numeric: 0},
	}}
	cur := Snapshot{Values: map[string]Value{
		"fs/protected_hardlinks": {Key: "fs/protected_hardlinks", Raw: "1", Numeric: 1},
	}}
	d := Compare(base, cur, []Param{
		{Key: "fs/protected_hardlinks", Direction: DirectionUp, HardenedFloor: 1},
	})
	if d.Drifts[0].Kind != DriftStricter {
		t.Fatalf("kind = %s, want stricter", d.Drifts[0].Kind)
	}
	if d.HasLooser() {
		t.Errorf("HasLooser should be false on stricter drift")
	}
}

func TestCompareDirectionDown(t *testing.T) {
	// accept_redirects: direction Down (lower is more secure)
	base := Snapshot{Values: map[string]Value{
		"net/ipv4/conf/all/accept_redirects": {Raw: "0", Numeric: 0},
	}}
	cur := Snapshot{Values: map[string]Value{
		"net/ipv4/conf/all/accept_redirects": {Raw: "1", Numeric: 1},
	}}
	d := Compare(base, cur, []Param{
		{Key: "net/ipv4/conf/all/accept_redirects", Direction: DirectionDown, HardenedFloor: 0},
	})
	if d.Drifts[0].Kind != DriftLooser {
		t.Fatalf("kind = %s, want looser (down-direction param went up)", d.Drifts[0].Kind)
	}
}

func TestCompareNoChange(t *testing.T) {
	v := Value{Raw: "1", Numeric: 1}
	d := Compare(
		Snapshot{Values: map[string]Value{"x": v}},
		Snapshot{Values: map[string]Value{"x": v}},
		[]Param{{Key: "x", Direction: DirectionUp, HardenedFloor: 1}},
	)
	if !d.IsEmpty() {
		t.Fatalf("expected empty diff; got %+v", d)
	}
}

func TestFloorAuditReportsBelowOnly(t *testing.T) {
	cur := Snapshot{Values: map[string]Value{
		"kernel/yama/ptrace_scope": {Numeric: 0},
		"kernel/kptr_restrict":     {Numeric: 2},
	}}
	params := []Param{
		{Key: "kernel/yama/ptrace_scope", Direction: DirectionUp, HardenedFloor: 1},
		{Key: "kernel/kptr_restrict", Direction: DirectionUp, HardenedFloor: 1},
	}
	out := FloorAudit(cur, params)
	if len(out) != 1 {
		t.Fatalf("expected 1 below-floor finding; got %+v", out)
	}
	if out[0].Key != "kernel/yama/ptrace_scope" {
		t.Errorf("wrong key: %s", out[0].Key)
	}
}

func TestSnapHandlesMissingFiles(t *testing.T) {
	root := buildFakeProcSys(t, map[string]string{
		"kernel/yama/ptrace_scope": "1\n",
	})
	snap := Snap(root, nil)
	if v, ok := snap.Values["kernel/yama/ptrace_scope"]; !ok || v.Numeric != 1 {
		t.Errorf("missing or wrong: %v", v)
	}
	// All other keys absent, no panic.
	if _, ok := snap.Values["kernel/kptr_restrict"]; ok {
		t.Error("missing key should not appear")
	}
}

func TestSnapHandlesMultilineValue(t *testing.T) {
	// Some sysctl files have multi-word output (e.g. some net keys).
	root := buildFakeProcSys(t, map[string]string{
		"net/core/somaxconn": "4096  some extra\n",
	})
	snap := Snap(root, []Param{
		{Key: "net/core/somaxconn", Direction: DirectionUp, HardenedFloor: 1024},
	})
	if v := snap.Values["net/core/somaxconn"]; v.Numeric != 4096 {
		t.Errorf("numeric = %d, want 4096", v.Numeric)
	}
}
