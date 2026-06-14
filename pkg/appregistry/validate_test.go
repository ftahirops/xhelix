package appregistry

import "testing"

func TestValidateApp_RejectsPathTraversalName(t *testing.T) {
	bad := []string{"../../etc/cron.d", "../evil", "a/b", ".hidden", "-flag", "x..y", ""}
	for _, name := range bad {
		if err := validateApp(App{Name: name}); err == nil {
			t.Errorf("expected rejection for app name %q", name)
		}
	}
	good := []string{"wordpress", "my-app_1", "App.2"}
	for _, name := range good {
		if err := validateApp(App{Name: name}); err != nil {
			t.Errorf("expected accept for %q, got %v", name, err)
		}
	}
}

func TestValidateApp_RejectsBadUnitAndCgroup(t *testing.T) {
	base := App{Name: "ok"}
	// Traversal / flag-smuggling unit names.
	for _, u := range []string{"../../x", "-q", "a/b", "x y"} {
		a := base
		a.Services = []Service{{Name: "s", UnitName: u, CgroupMatch: "/system.slice/x"}}
		if err := validateApp(a); err == nil {
			t.Errorf("expected rejection for unit_name %q", u)
		}
	}
	// Non-absolute or traversal cgroup.
	for _, cg := range []string{"system.slice/x", "/a/../b", "/a b"} {
		a := base
		a.Services = []Service{{Name: "s", CgroupMatch: cg}}
		if err := validateApp(a); err == nil {
			t.Errorf("expected rejection for cgroup_match %q", cg)
		}
	}
}

func TestSetMode_RejectsInvalidMode(t *testing.T) {
	r, _ := Open(":memory:")
	defer r.Close()
	_ = r.Create(App{Name: "app", Services: []Service{{Name: "s", CgroupMatch: "/system.slice/x"}}})
	if err := r.SetMode("app", EnforcementMode("observe2")); err == nil {
		t.Error("expected rejection of bogus mode (would silently disable enforcement)")
	}
	if err := r.SetMode("app", ModeLocked); err != nil {
		t.Errorf("valid mode rejected: %v", err)
	}
}
