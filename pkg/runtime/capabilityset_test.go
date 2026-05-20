package runtime

import (
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/decision"
)

func TestNew_Empty(t *testing.T) {
	c := New()
	if c == nil || c.WitnessedKnobs == nil {
		t.Fatal("New() should initialize maps")
	}
	if c.NetbanReady || c.QuarantineReady {
		t.Fatal("zero value should have no readiness flags")
	}
}

func TestMarkers(t *testing.T) {
	c := New()
	c.MarkNetbanReady()
	c.MarkQuarantineReady()
	c.MarkRemediateReady()
	c.MarkSnapshotReady()
	c.MarkMemscanReady()
	c.MarkTarpitReady()
	c.MarkWebAuthnReady()
	c.MarkOffHostMirror()
	c.MarkEBPFLoaded()
	c.SetBastionCount(3)
	c.RecordWitness("storage.hot.path")

	if !c.NetbanReady || !c.QuarantineReady || !c.RemediateReady ||
		!c.SnapshotReady || !c.MemscanReady || !c.TarpitReady ||
		!c.WebAuthnReady || !c.OffHostMirror || !c.EBPFLoaded {
		t.Fatalf("marker not recorded: %+v", c)
	}
	if c.BastionCount != 3 {
		t.Fatalf("BastionCount=%d, want 3", c.BastionCount)
	}
	if !c.WitnessedKnobs["storage.hot.path"] {
		t.Fatal("Witness not recorded")
	}
}

func TestCanExecute_AllMissing(t *testing.T) {
	c := New() // nothing ready
	p := &decision.ActionPlan{
		AlertID: "a", PlanID: "p",
		Snapshot: true, SuspendProcess: true, IsolateCgroup: true,
		BanRemoteIP: true, RequireStepUp: true,
	}
	w := c.CanExecute(p)
	if len(w) == 0 {
		t.Fatal("CanExecute should report missing capabilities")
	}
	// Should mention key actions.
	all := strings.Join(w, "|")
	for _, must := range []string{"snapshot", "suspend_process", "ban_remote_ip", "require_step_up"} {
		if !strings.Contains(all, must) {
			t.Fatalf("missing %s in warnings: %v", must, w)
		}
	}
}

func TestCanExecute_AllPresent(t *testing.T) {
	c := New()
	c.MarkSnapshotReady()
	c.MarkQuarantineReady()
	c.MarkNetbanReady()
	c.MarkWebAuthnReady()
	// Force kernel-feature flags directly (Discover() would read /proc).
	c.HasCgroupV2 = true
	c.HasNFTables = true

	p := decision.NewSuspend("a", "p", 80)
	if w := c.CanExecute(p); len(w) != 0 {
		t.Fatalf("expected no warnings, got %v", w)
	}
}

func TestCanExecute_IsolateHostNeedsTwoBastions(t *testing.T) {
	c := New()
	c.MarkNetbanReady()
	c.MarkOffHostMirror()
	c.HasNFTables = true
	c.HasCgroupV2 = true
	c.MarkQuarantineReady()
	c.MarkSnapshotReady()
	c.MarkMemscanReady()
	c.SetBastionCount(1) // only one bastion

	p := decision.NewContain("a", "p", 100, []string{"bastion_count>=2", "off_host_mirror"})
	w := c.CanExecute(p)
	found := false
	for _, x := range w {
		if strings.Contains(x, "BastionCount>=2") {
			found = true
		}
	}
	if !found {
		t.Fatalf("should warn on bastion shortage: %v", w)
	}

	c.SetBastionCount(2)
	if w := c.CanExecute(p); len(w) != 0 {
		t.Fatalf("with 2 bastions and off-host mirror, expected 0 warnings, got %v", w)
	}
}

func TestAnnotatePlan_AttachesWarnings(t *testing.T) {
	c := New() // nothing ready
	p := decision.NewSuspend("a", "p", 80)
	c.AnnotatePlan(p)
	if len(p.CapabilityWarnings) == 0 {
		t.Fatal("AnnotatePlan should attach warnings")
	}
}

func TestSnapshot_DeepCopy(t *testing.T) {
	c := New()
	c.RecordWitness("k1")
	snap := c.Snapshot()
	c.RecordWitness("k2")
	if snap.WitnessedKnobs["k2"] {
		t.Fatal("Snapshot must be a deep copy of WitnessedKnobs")
	}
}

func TestKernelAtLeast(t *testing.T) {
	cases := []struct {
		rel  string
		M, m int
		want bool
	}{
		{"5.3.0-generic", 5, 3, true},
		{"5.2.99", 5, 3, false},
		{"6.1.0", 5, 15, true},
		{"4.19.0", 5, 0, false},
		{"", 5, 0, false},
		{"garbage", 5, 0, false},
	}
	for _, tc := range cases {
		got := kernelAtLeast(tc.rel, tc.M, tc.m)
		if got != tc.want {
			t.Errorf("kernelAtLeast(%q, %d, %d) = %v, want %v", tc.rel, tc.M, tc.m, got, tc.want)
		}
	}
}

func TestDiscover_DoesNotPanic(t *testing.T) {
	c := New()
	c.Discover()
	if c.DiscoveredAt.IsZero() {
		t.Fatal("Discover should set DiscoveredAt")
	}
	if c.GOOS == "" {
		t.Fatal("GOOS should be populated")
	}
}
