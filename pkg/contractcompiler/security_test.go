package contractcompiler

import (
	"strings"
	"sync"
	"testing"

	"github.com/xhelix/xhelix/pkg/appregistry"
)

// TestExecDecision_ConcurrentShadowNoRace exercises the hot path under
// the race detector — the shadowCount increment must be a data-race-free
// atomic, not a map write under RLock.
func TestExecDecision_ConcurrentShadowNoRace(t *testing.T) {
	m := NewManager(nil, "", nil)
	m.Recompile(sampleApp(appregistry.ModeShadow))
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service")
		}()
	}
	wg.Wait()
	if got := m.ShadowCount("wordpress"); got != 64 {
		t.Errorf("shadow tally = %d, want 64 (atomic increments lost?)", got)
	}
}

// TestExecDecision_OverlappingCgroupLongestWins proves the verdict is
// deterministic when two apps claim overlapping cgroups — the most
// specific (longest) match governs, regardless of map order.
func TestExecDecision_OverlappingCgroupLongestWins(t *testing.T) {
	m := NewManager(nil, "", nil)
	// Broad app claims the slice in locked mode, allows nothing extra.
	m.Recompile(appregistry.App{
		Name: "broad", Mode: appregistry.ModeLocked,
		Services: []appregistry.Service{{Name: "all", CgroupMatch: "/system.slice", BinaryPath: "/usr/bin/broad"}},
	})
	// Specific app claims the nested cgroup and allows nginx.
	m.Recompile(appregistry.App{
		Name: "specific", Mode: appregistry.ModeLocked,
		Services: []appregistry.Service{{Name: "nginx", CgroupMatch: "/system.slice/nginx.service", BinaryPath: "/usr/sbin/nginx"}},
	})
	// A process in the nested cgroup must be judged by the specific app.
	for i := 0; i < 20; i++ { // repeat — map order is randomized per run
		d, reason := m.ExecDecisionFor("/usr/sbin/nginx", "/system.slice/nginx.service")
		if d != DecisionAllow {
			t.Fatalf("expected specific app to allow nginx, got %v (%s)", d, reason)
		}
		d, reason = m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service")
		if d != DecisionDeny || !strings.Contains(reason, "specific") {
			t.Fatalf("expected specific app to deny+name, got %v (%s)", d, reason)
		}
	}
}

// TestWriteArtifacts_JailsAppName ensures a crafted app name cannot
// escape the artifact dir even if validation were bypassed upstream.
func TestWriteArtifacts_JailsAppName(t *testing.T) {
	m := NewManager(nil, t.TempDir(), nil)
	cc := &CompiledContract{App: "../../etc/cron.d", Mode: appregistry.ModeLocked}
	if err := m.writeArtifacts(cc); err == nil {
		t.Error("expected writeArtifacts to reject an app name escaping the artifact dir")
	}
}

// TestArtifactSHA_StableAcrossModeFlip proves the content hash (the signed
// version identity) is invariant to mode + recompile, but changes when the
// declaration drifts — the core P7 "sealed = unsigned drift blocked" property.
func TestArtifactSHA_StableAcrossModeFlip(t *testing.T) {
	locked := sampleApp(appregistry.ModeLocked)
	sealed := sampleApp(appregistry.ModeSealed)
	h1 := Compile(locked, nil).ArtifactSHA
	h2 := Compile(sealed, nil).ArtifactSHA
	if h1 == "" || h1 != h2 {
		t.Errorf("hash must be invariant to mode: locked=%s sealed=%s", h1, h2)
	}
	// Recompiling the same declaration yields the same hash.
	if Compile(locked, nil).ArtifactSHA != h1 {
		t.Error("hash must be deterministic across recompiles")
	}
	// Drift: change a declared binary → hash must change.
	drifted := sampleApp(appregistry.ModeLocked)
	drifted.Services[0].BinaryPath = "/usr/sbin/php-fpm9.9"
	if Compile(drifted, nil).ArtifactSHA == h1 {
		t.Error("declaration drift must change the artifact hash (unsigned drift)")
	}
}
