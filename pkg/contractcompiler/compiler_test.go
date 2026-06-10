package contractcompiler

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/redzones"
)

func init() {
	nowFunc = func() time.Time { return time.Unix(1700000000, 0) }
}

func sampleApp(mode appregistry.EnforcementMode) appregistry.App {
	return appregistry.App{
		Name: "wordpress",
		Mode: mode,
		Services: []appregistry.Service{
			{
				Name:        "php-fpm",
				CgroupMatch: "/system.slice/php-fpm.service",
				BinaryPath:  "/usr/sbin/php-fpm8.2",
				ServiceType: appregistry.ServicePhpFpm,
				UnitName:    "php-fpm.service",
			},
			{
				Name:        "nginx",
				CgroupMatch: "/system.slice/nginx.service",
				BinaryPath:  "/usr/sbin/nginx",
				ServiceType: appregistry.ServiceNginx,
				UnitName:    "nginx.service",
			},
		},
	}
}

func TestCompile_Deterministic(t *testing.T) {
	app := sampleApp(appregistry.ModeLocked)
	a := Compile(app, nil)
	b := Compile(app, nil)
	if a.CompiledAt != b.CompiledAt {
		t.Fatal("CompiledAt should be deterministic under fixed clock")
	}
	if len(a.Services) != 2 {
		t.Fatalf("want 2 services, got %d", len(a.Services))
	}
	if a.Source != "declaration" {
		t.Errorf("Source = %q, want declaration", a.Source)
	}
}

func TestCompile_ExecAllowIsDeclaredBinaries(t *testing.T) {
	cc := Compile(sampleApp(appregistry.ModeLocked), nil)
	for _, svc := range cc.Services {
		if !contains(svc.ExecAllow, "/usr/sbin/php-fpm8.2") {
			t.Errorf("ExecAllow missing php-fpm binary: %v", svc.ExecAllow)
		}
		if !contains(svc.ExecAllow, "/usr/sbin/nginx") {
			t.Errorf("ExecAllow missing nginx binary: %v", svc.ExecAllow)
		}
	}
}

func TestCompile_RedzoneFloorAlwaysPresent(t *testing.T) {
	cc := Compile(sampleApp(appregistry.ModeObserve), nil)
	floor := redzones.Default()
	for _, svc := range cc.Services {
		// ExecDeny must contain the red-zone exec floor.
		for _, p := range floor.ExecPaths {
			if !contains(svc.ExecDeny, p) {
				t.Errorf("ExecDeny missing red-zone path %q", p)
			}
		}
		// DenySyscalls must contain the red-zone syscall floor.
		for _, s := range floor.DenySyscalls {
			if !contains(svc.DenySyscalls, s) {
				t.Errorf("service %s DenySyscalls missing red-zone syscall %q", svc.Unit, s)
			}
		}
	}
}

func TestExecDecision_LockedDeniesUndeclared(t *testing.T) {
	m := NewManager(nil, "", nil)
	m.Recompile(sampleApp(appregistry.ModeLocked))

	// Declared binary inside the cgroup → allow.
	d, _ := m.ExecDecisionFor("/usr/sbin/nginx", "/system.slice/nginx.service")
	if d != DecisionAllow {
		t.Errorf("declared binary: got %v, want Allow", d)
	}
	// Undeclared binary inside the cgroup → deny.
	d, reason := m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service")
	if d != DecisionDeny {
		t.Errorf("undeclared binary: got %v, want Deny", d)
	}
	if reason == "" {
		t.Error("deny should carry a reason")
	}
	// Child cgroup of a declared service → still scoped.
	d, _ = m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service/worker.0")
	if d != DecisionDeny {
		t.Errorf("child cgroup undeclared: got %v, want Deny", d)
	}
}

func TestExecDecision_ObserveAndGuardedPass(t *testing.T) {
	for _, mode := range []appregistry.EnforcementMode{
		appregistry.ModeObserve, appregistry.ModeGuarded,
	} {
		m := NewManager(nil, "", nil)
		m.Recompile(sampleApp(mode))
		d, _ := m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service")
		if d != DecisionPass {
			t.Errorf("mode %s: got %v, want Pass (floor handles it)", mode, d)
		}
	}
}

func TestExecDecision_ShadowNeverDeniesButTallies(t *testing.T) {
	m := NewManager(nil, "", nil)
	m.Recompile(sampleApp(appregistry.ModeShadow))
	d, _ := m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service")
	if d != DecisionPass {
		t.Errorf("shadow must not deny: got %v", d)
	}
	if m.ShadowCount("wordpress") != 1 {
		t.Errorf("shadow would-block not tallied: %d", m.ShadowCount("wordpress"))
	}
	// Declared binary should not tally.
	_, _ = m.ExecDecisionFor("/usr/sbin/nginx", "/system.slice/nginx.service")
	if m.ShadowCount("wordpress") != 1 {
		t.Errorf("declared binary should not tally: %d", m.ShadowCount("wordpress"))
	}
}

func TestExecDecision_UnclaimedCgroupPasses(t *testing.T) {
	m := NewManager(nil, "", nil)
	m.Recompile(sampleApp(appregistry.ModeLocked))
	d, _ := m.ExecDecisionFor("/bin/sh", "/system.slice/other.service")
	if d != DecisionPass {
		t.Errorf("unclaimed cgroup: got %v, want Pass", d)
	}
}

func TestExecDecision_NoUnanchoredPrefixBypass(t *testing.T) {
	m := NewManager(nil, "", nil)
	m.Recompile(sampleApp(appregistry.ModeLocked))
	// php-fpm-evil must NOT match php-fpm.service.
	d, _ := m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service-evil")
	if d != DecisionPass {
		t.Errorf("unanchored prefix must not match: got %v, want Pass", d)
	}
}

func TestRemove(t *testing.T) {
	m := NewManager(nil, "", nil)
	m.Recompile(sampleApp(appregistry.ModeLocked))
	m.Remove("wordpress")
	if m.Get("wordpress") != nil {
		t.Error("Get after Remove should be nil")
	}
	d, _ := m.ExecDecisionFor("/bin/sh", "/system.slice/nginx.service")
	if d != DecisionPass {
		t.Errorf("after remove: got %v, want Pass", d)
	}
}
