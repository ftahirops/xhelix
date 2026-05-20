package protectedsvc

import (
	"strings"
	"testing"
)

func uid(u uint32) *uint32 { return &u }

func TestRegistry_LoadAndLookup(t *testing.T) {
	r := NewRegistry()
	err := r.Load([]ProtectedService{
		{
			Name: "nginx-main", Kind: KindNginx, Role: RoleReverseProxy,
			Unit: "nginx.service", ExecPath: "/usr/sbin/nginx",
			CgroupPrefix: "/system.slice/nginx.service",
		},
		{
			Name: "apache-php", Kind: KindApache, Role: RolePHPModule,
			Unit: "apache2.service", ExecPath: "/usr/sbin/apache2",
			CgroupPrefix: "/system.slice/apache2.service",
		},
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if r.Count() != 2 {
		t.Fatalf("Count=%d want 2", r.Count())
	}
	if r.ByName("nginx-main") == nil {
		t.Fatal("ByName(nginx-main) nil")
	}
	if u := r.ByUnit("nginx.service"); len(u) != 1 || u[0].Name != "nginx-main" {
		t.Fatalf("ByUnit nginx.service = %v", u)
	}
}

func TestRegistry_RejectsInvalid(t *testing.T) {
	r := NewRegistry()
	cases := []struct {
		name string
		svcs []ProtectedService
		want string
	}{
		{"missing name", []ProtectedService{{Kind: KindNginx, Role: RoleStatic, ExecPath: "/x", CgroupPrefix: "/x"}}, "name is required"},
		{"unknown kind", []ProtectedService{{Name: "n", Kind: "iis", Role: RoleStatic, ExecPath: "/x", CgroupPrefix: "/x"}}, "unknown kind"},
		{"unknown role", []ProtectedService{{Name: "n", Kind: KindNginx, Role: "weird", ExecPath: "/x", CgroupPrefix: "/x"}}, "unknown role"},
		{"missing exec_path", []ProtectedService{{Name: "n", Kind: KindNginx, Role: RoleStatic, CgroupPrefix: "/x"}}, "exec_path is required"},
		{"missing both unit and cgroup", []ProtectedService{{Name: "n", Kind: KindNginx, Role: RoleStatic, ExecPath: "/x"}}, "cgroup_prefix or unit"},
		{"bad sha length", []ProtectedService{{Name: "n", Kind: KindNginx, Role: RoleStatic, ExecPath: "/x", CgroupPrefix: "/x", ExeSHA256: "abc"}}, "64 hex"},
		{"duplicate name", []ProtectedService{
			{Name: "n", Kind: KindNginx, Role: RoleStatic, ExecPath: "/x", CgroupPrefix: "/x"},
			{Name: "n", Kind: KindApache, Role: RoleStatic, ExecPath: "/y", CgroupPrefix: "/y"},
		}, "duplicate name"},
	}
	for _, tc := range cases {
		err := r.Load(tc.svcs)
		if err == nil {
			t.Errorf("%s: expected error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not contain %q", tc.name, err.Error(), tc.want)
		}
	}
}

func TestRegistry_MatchCgroup_LongestPrefix(t *testing.T) {
	r := NewRegistry()
	_ = r.Load([]ProtectedService{
		{
			Name: "system", Kind: KindNginx, Role: RoleStatic,
			ExecPath: "/usr/sbin/nginx", CgroupPrefix: "/system.slice",
		},
		{
			Name: "nginx-specific", Kind: KindNginx, Role: RoleReverseProxy,
			ExecPath: "/usr/sbin/nginx", CgroupPrefix: "/system.slice/nginx.service",
		},
	})

	if got := r.MatchCgroup("/system.slice/nginx.service/worker-1"); got == nil || got.Name != "nginx-specific" {
		t.Fatalf("expected nginx-specific to win on longer prefix; got %+v", got)
	}
	if got := r.MatchCgroup("/system.slice/apache2.service"); got == nil || got.Name != "system" {
		t.Fatalf("expected system fallback; got %+v", got)
	}
	if got := r.MatchCgroup("/user.slice/u1.scope"); got != nil {
		t.Fatalf("non-system cgroup should not match: %+v", got)
	}
}

func TestRegistry_LoadFailurePreservesOldState(t *testing.T) {
	r := NewRegistry()
	good := []ProtectedService{
		{Name: "ok", Kind: KindNginx, Role: RoleStatic,
			ExecPath: "/x", CgroupPrefix: "/x"},
	}
	if err := r.Load(good); err != nil {
		t.Fatal(err)
	}

	bad := []ProtectedService{
		{Name: "bad", Kind: "huh", Role: RoleStatic, ExecPath: "/y", CgroupPrefix: "/y"},
	}
	if err := r.Load(bad); err == nil {
		t.Fatal("bad config should fail")
	}
	if r.ByName("ok") == nil {
		t.Fatal("previous good config should be preserved on bad reload")
	}
}

func TestAllOnAllOff(t *testing.T) {
	on := AllOn()
	if !on.Enabled || !on.FakeExec || !on.Sinkhole || !on.DecoyFS || !on.PoisonDNS {
		t.Fatalf("AllOn missing flags: %+v", on)
	}
	off := AllOff()
	if off.Enabled || off.FakeExec || off.Sinkhole || off.DecoyFS || off.PoisonDNS {
		t.Fatalf("AllOff has set flags: %+v", off)
	}
}

func TestUIDHelper(t *testing.T) {
	u := uid(33)
	if u == nil || *u != 33 {
		t.Fatal("uid helper broken")
	}
}
