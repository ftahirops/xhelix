package contractarm_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/contractarm"
	"github.com/xhelix/xhelix/pkg/contractcompiler"
)

// TestE2E_DeclareCompileDecideArm exercises the full P5a/P5a.2 chain
// against the REAL packages (SQLite registry, compiler manager, armorer
// with a temp systemd dir + fake systemctl) — no root, no fanotify.
func TestE2E_DeclareCompileDecideArm(t *testing.T) {
	// 1. Real registry (temp SQLite).
	reg, err := appregistry.Open(filepath.Join(t.TempDir(), "apps.db"))
	if err != nil { t.Fatal(err) }
	defer reg.Close()

	app := appregistry.App{
		Name: "wordpress", DisplayName: "WordPress", Mode: appregistry.ModeLocked,
		Services: []appregistry.Service{
			{Name: "php-fpm", UnitName: "php-fpm.service", CgroupMatch: "/system.slice/php-fpm.service", BinaryPath: "/usr/sbin/php-fpm8.2", ServiceType: appregistry.ServicePhpFpm},
			{Name: "nginx", UnitName: "nginx.service", CgroupMatch: "/system.slice/nginx.service", BinaryPath: "/usr/sbin/nginx", ServiceType: appregistry.ServiceNginx},
		},
	}
	if err := reg.Create(app); err != nil { t.Fatalf("declare: %v", err) }
	t.Logf("[1] declared app %q (locked) with %d services", app.Name, len(app.Services))

	// 2. Real compiler manager — compile from the registry.
	artifactDir := t.TempDir()
	mgr := contractcompiler.NewManager(nil, artifactDir, nil)
	got, _ := reg.Get("wordpress")
	cc := mgr.Recompile(*got)
	t.Logf("[2] compiled: source=%s services=%d", cc.Source, len(cc.Services))
	for _, s := range cc.Services {
		t.Logf("    svc=%s exec_allow=%v deny_syscalls=%d seccomp_directive=%q",
			s.Unit, s.ExecAllow, len(s.DenySyscalls), truncate(s.SeccompSystemdDirective, 60))
	}

	// 3. Live exec decision (what execguard's hook calls per-exec).
	dAllow, _ := mgr.ExecDecisionFor("/usr/sbin/nginx", "/system.slice/nginx.service")
	dDeny, reason := mgr.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service")
	t.Logf("[3] exec /usr/sbin/nginx -> %v (want Allow)", dAllow)
	t.Logf("    exec /bin/sh        -> %v  reason=%q", dDeny, reason)
	if dAllow != contractcompiler.DecisionAllow { t.Errorf("nginx should be allowed, got %v", dAllow) }
	if dDeny != contractcompiler.DecisionDeny { t.Errorf("/bin/sh should be denied, got %v", dDeny) }

	// 4. Staged artifacts on disk.
	staged := filepath.Join(artifactDir, "wordpress", "STAGED")
	if _, err := os.Stat(staged); err != nil { t.Errorf("STAGED marker missing: %v", err) }
	t.Logf("[4] staged artifacts written under %s/wordpress/", artifactDir)

	// 5. Arm via real Armorer (temp systemd dir + fake systemctl).
	var systemctl []string
	arm := &contractarm.Armorer{
		SystemdDir: t.TempDir(), ApparmorDir: t.TempDir(), Apparmor: false,
		Runner: func(a ...string) error { systemctl = append(systemctl, strings.Join(a, " ")); return nil },
		Now:    func() time.Time { return time.Unix(1700000000, 0) },
	}
	specs := []contractarm.ServiceSpec{}
	for _, s := range cc.Services {
		specs = append(specs, contractarm.ServiceSpec{Unit: s.Unit, SeccompDirective: s.SeccompSystemdDirective})
	}
	res, err := arm.Arm("wordpress", "locked", specs)
	if err != nil { t.Fatalf("arm: %v", err) }
	t.Logf("[5] armed: pending_restart=%v systemctl_calls=%v", res.PendingRestart, systemctl)

	// Show the REAL drop-in systemd would load.
	dropin := filepath.Join(arm.SystemdDir, "nginx.service.d", contractarm.DropInName("wordpress"))
	body, err := os.ReadFile(dropin)
	if err != nil { t.Fatalf("read drop-in: %v", err) }
	t.Logf("[6] generated systemd drop-in (%s):\n%s", dropin, string(body))
	if !strings.Contains(string(body), "SystemCallFilter=") { t.Error("drop-in missing SystemCallFilter") }
}

func truncate(s string, n int) string { if len(s) > n { return s[:n] + "…" }; return s }
