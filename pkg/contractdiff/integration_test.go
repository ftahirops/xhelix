package contractdiff_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/contractcompiler"
	"github.com/xhelix/xhelix/pkg/contractdiff"
	"github.com/xhelix/xhelix/pkg/contractsign"
)

func appV(binary string) appregistry.App {
	return appregistry.App{
		Name: "wordpress", Mode: appregistry.ModeSealed,
		Services: []appregistry.Service{
			{Name: "php-fpm", UnitName: "php-fpm.service", CgroupMatch: "/system.slice/php-fpm.service",
				BinaryPath: binary, ServiceType: appregistry.ServicePhpFpm},
		},
	}
}

// TestDeployFlow_SignSnapshotDriftDiff proves the P7 deploy-review chain:
// sign a version (snapshot stored), then a "deploy" drifts the declaration,
// and the diff vs the signed baseline (loaded back through JSON) shows it.
func TestDeployFlow_SignSnapshotDriftDiff(t *testing.T) {
	pub, priv := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		p, k, _ := ed25519.GenerateKey(nil); return p, k
	}()
	store, err := contractsign.Open(filepath.Join(t.TempDir(), "sig.db"),
		map[string]ed25519.PublicKey{"ci": pub})
	if err != nil { t.Fatal(err) }
	defer store.Close()

	// v1: compile + sign + snapshot.
	v1 := contractcompiler.Compile(appV("/usr/sbin/php-fpm8.2"), nil)
	snap, _ := json.Marshal(v1)
	sig := base64.StdEncoding.EncodeToString(contractsign.Sign(v1.App, v1.ArtifactSHA, priv))
	if _, err := store.AddWithSnapshot(v1.App, v1.ArtifactSHA, "ci", sig, snap); err != nil {
		t.Fatalf("sign v1: %v", err)
	}

	// "Deploy" → declaration drifts (new php-fpm binary). Recompile = v2.
	v2 := contractcompiler.Compile(appV("/usr/sbin/php-fpm9.9"), nil)
	if v2.ArtifactSHA == v1.ArtifactSHA {
		t.Fatal("drift must change the artifact hash")
	}
	// Sealed gate: v2 is unsigned → HasValid false → arming would be blocked.
	if ok, _ := store.HasValid(v2.App, v2.ArtifactSHA); ok {
		t.Fatal("drifted version must read as unsigned")
	}

	// Load the signed baseline back through JSON and diff vs current.
	js, ok := store.SnapshotJSON(v1.App, v1.ArtifactSHA)
	if !ok { t.Fatal("snapshot missing") }
	var baseline contractcompiler.CompiledContract
	if err := json.Unmarshal(js, &baseline); err != nil { t.Fatal(err) }

	d := contractdiff.Compute(&baseline, &v2)
	if d.Empty() { t.Fatal("diff should show the drifted binary") }
	var sawAdd, sawRemove bool
	for _, c := range d.Changes {
		if c.Kind == contractdiff.KindExecAllow && c.Value == "/usr/sbin/php-fpm9.9" && c.Op == contractdiff.OpAdded { sawAdd = true }
		if c.Kind == contractdiff.KindExecAllow && c.Value == "/usr/sbin/php-fpm8.2" && c.Op == contractdiff.OpRemoved { sawRemove = true }
	}
	if !sawAdd || !sawRemove {
		t.Errorf("diff should show new binary added + old removed; got %+v", d.Changes)
	}
}
