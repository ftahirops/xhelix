package contractpropose_test

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/contractcompiler"
	"github.com/xhelix/xhelix/pkg/contractdiff"
	"github.com/xhelix/xhelix/pkg/contractpropose"
)

func wpApp(binary string) appregistry.App {
	return appregistry.App{
		Name: "wp", Mode: appregistry.ModeLocked,
		Services: []appregistry.Service{
			{Name: "php-fpm", UnitName: "php-fpm.service", CgroupMatch: "/system.slice/php-fpm.service",
				BinaryPath: binary, ServiceType: appregistry.ServicePhpFpm},
		},
	}
}

// TestProposeApproveFlow mirrors the daemon provider: declare → propose a
// drifted declaration → diff shows it → approve applies + recompiles →
// registry reflects the new declaration; reject leaves it untouched.
func TestProposeApproveFlow(t *testing.T) {
	dir := t.TempDir()
	reg, err := appregistry.Open(filepath.Join(dir, "apps.db"))
	if err != nil { t.Fatal(err) }
	defer reg.Close()
	store, err := contractpropose.Open(filepath.Join(dir, "prop.db"))
	if err != nil { t.Fatal(err) }
	defer store.Close()

	// Declare the live app (v1).
	if err := reg.Create(wpApp("/usr/sbin/php-fpm8.2")); err != nil { t.Fatal(err) }
	mgr := contractcompiler.NewManager(nil, "", nil)
	cur, _ := reg.Get("wp")
	mgr.Recompile(*cur)

	// CI proposes a drifted declaration (new binary).
	proposed := wpApp("/usr/sbin/php-fpm9.9")
	declJSON, _ := json.Marshal(proposed)
	target := contractcompiler.Compile(proposed, nil)
	p, err := store.Create(contractpropose.Proposal{App: "wp", Submitter: "operator",
		Reason: "deploy v2", TargetSHA: target.ArtifactSHA, DeclarationJSON: declJSON})
	if err != nil { t.Fatal(err) }

	// Diff: proposed vs current → shows the binary swap.
	df := contractdiff.Compute(mgr.Get("wp"), &target)
	if df.Empty() { t.Fatal("proposal diff should be non-empty") }

	// Approve: apply + recompile + decide (provider sequence).
	if err := reg.Update(proposed); err != nil { t.Fatalf("apply: %v", err) }
	now, _ := reg.Get("wp")
	mgr.Recompile(*now)
	if err := store.Decide("wp", p.ID, contractpropose.StatusApproved, "admin"); err != nil { t.Fatal(err) }

	// Registry now reflects the proposed binary; compiled version == target.
	if now.Services[0].BinaryPath != "/usr/sbin/php-fpm9.9" {
		t.Errorf("registry not updated: %s", now.Services[0].BinaryPath)
	}
	if mgr.Get("wp").ArtifactSHA != target.ArtifactSHA {
		t.Error("recompiled version should match approved target")
	}
	got, _ := store.Get("wp", p.ID)
	if got.Status != contractpropose.StatusApproved || got.DecidedBy != "admin" {
		t.Errorf("proposal not marked approved: %+v", got)
	}
	// Cgroup attribution still resolves after the update.
	if reg.AppForCgroup("/system.slice/php-fpm.service") != "wp" {
		t.Error("cgroup index broken after Update")
	}
}
