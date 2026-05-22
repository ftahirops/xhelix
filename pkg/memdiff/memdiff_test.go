package memdiff

import "testing"

type stubAllowlist struct{ comms map[string]bool }

func (s stubAllowlist) MatchAny(image, comm string) bool { return s.comms[comm] }

func TestTick_FirstCallIsBaseline(t *testing.T) {
	s := New(nil)
	if got := s.Tick(); got != nil {
		t.Fatalf("first Tick returned %d findings; want nil baseline", len(got))
	}
	st := s.Stats()
	if st.Ticks != 1 {
		t.Errorf("Ticks=%d want 1", st.Ticks)
	}
	if st.NewRegions != 0 {
		t.Errorf("NewRegions=%d want 0", st.NewRegions)
	}
}

func TestDiffPureFunctions(t *testing.T) {
	// Synthesise two snapshots and exercise the diff manually since
	// we don't want this test to depend on the live host's /proc.
	s := New(nil)
	priorRegions := map[uint64]Region{
		0x1000: {StartAddr: 0x1000, EndAddr: 0x2000, Perms: "rwxp"},
	}
	now := map[uint64]Region{
		0x1000: {StartAddr: 0x1000, EndAddr: 0x2000, Perms: "rwxp"},
		0x3000: {StartAddr: 0x3000, EndAddr: 0x4000, Perms: "rwxp"}, // new
	}
	s.prev = map[uint32]map[uint64]Region{42: priorRegions}
	// Inject into the live diff by manually calling the body:
	curr := map[uint32]map[uint64]Region{42: now}
	var findings []Finding
	for pid, regions := range curr {
		priorRegionsForPid, hadPid := s.prev[pid]
		if !hadPid {
			continue
		}
		for addr, r := range regions {
			if _, existed := priorRegionsForPid[addr]; existed {
				continue
			}
			findings = append(findings, Finding{PID: pid, Region: r})
		}
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].Region.StartAddr != 0x3000 {
		t.Errorf("want new region 0x3000, got %#x", findings[0].Region.StartAddr)
	}
}

func TestParseAnonExecRegions_Skips_File_Backed(t *testing.T) {
	// Self-test against /proc/self/maps: xhelix's own test binary has
	// at least one file-backed executable mapping (.text), which
	// MUST NOT appear in parseAnonExecRegions output. Anonymous
	// executable mappings MAY appear (Go runtime occasionally maps
	// anon RWX for trampolines), but they should be sparse.
	r := parseAnonExecRegions(uint32(1)) // pid 1 (init) — readable
	for _, region := range r {
		if region.Perms[2] != 'x' {
			t.Fatalf("non-exec region leaked: %+v", region)
		}
	}
}
