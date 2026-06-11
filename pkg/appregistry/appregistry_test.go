package appregistry

import (
	"testing"
)

func TestCgroupMatchesPrefix(t *testing.T) {
	cases := []struct {
		path, prefix string
		want         bool
	}{
		// Exact match
		{"/system.slice/nginx.service", "/system.slice/nginx.service", true},
		// Child of prefix
		{"/system.slice/nginx.service/worker", "/system.slice/nginx.service", true},
		// Prefix is not a path boundary — the critical security case
		{"/system.slice/nginx.service-evil", "/system.slice/nginx.service", false},
		{"/system.slice/php-fpm-malicious.service", "/system.slice/php-fpm.service", false},
		// Root slash
		{"/", "/system.slice", false},
		// Empty prefix always false
		{"", "/system.slice/nginx.service", false},
		{"/system.slice/nginx.service", "", false},
		// Both empty — empty prefix never matches (security invariant).
		{"", "", false},
	}
	for _, c := range cases {
		got := cgroupMatchesPrefix(c.path, c.prefix)
		if got != c.want {
			t.Errorf("cgroupMatchesPrefix(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
		}
	}
}

func TestRegistryCRUD(t *testing.T) {
	r, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	app := App{
		Name:        "wordpress",
		DisplayName: "WordPress",
		Mode:        ModeObserve,
		Services: []Service{
			{
				Name:        "php-fpm",
				CgroupMatch: "/system.slice/php-fpm.service",
				BinaryPath:  "/usr/sbin/php-fpm8.2",
				ServiceType: ServicePhpFpm,
				UnitName:    "php-fpm.service",
			},
			{
				Name:        "nginx",
				CgroupMatch: "/system.slice/nginx.service",
				BinaryPath:  "/usr/sbin/nginx",
				ServiceType: ServiceNginx,
				UnitName:    "nginx.service",
			},
		},
	}

	if err := r.Create(app); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Get
	got, err := r.Get("wordpress")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get: returned nil")
	}
	if got.Name != "wordpress" || got.DisplayName != "WordPress" {
		t.Errorf("wrong app: %+v", got)
	}
	if len(got.Services) != 2 {
		t.Errorf("want 2 services, got %d", len(got.Services))
	}

	// List
	apps, err := r.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(apps) != 1 {
		t.Errorf("want 1 app in list, got %d", len(apps))
	}

	// SetMode
	if err := r.SetMode("wordpress", ModeGuarded); err != nil {
		t.Fatalf("SetMode: %v", err)
	}
	got, _ = r.Get("wordpress")
	if got.Mode != ModeGuarded {
		t.Errorf("mode after SetMode = %v, want guarded", got.Mode)
	}

	// AppForCgroup — exact match
	if name := r.AppForCgroup("/system.slice/nginx.service"); name != "wordpress" {
		t.Errorf("AppForCgroup exact: got %q, want wordpress", name)
	}

	// AppForCgroup — child path
	if name := r.AppForCgroup("/system.slice/nginx.service/worker.0"); name != "wordpress" {
		t.Errorf("AppForCgroup child: got %q, want wordpress", name)
	}

	// AppForCgroup — non-matching evil prefix
	if name := r.AppForCgroup("/system.slice/nginx.service-evil"); name != "" {
		t.Errorf("AppForCgroup evil prefix: got %q, want empty", name)
	}

	// Delete
	if err := r.Delete("wordpress"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ = r.Get("wordpress")
	if got != nil {
		t.Error("Get after Delete: expected nil")
	}
	if name := r.AppForCgroup("/system.slice/nginx.service"); name != "" {
		t.Errorf("AppForCgroup after delete: got %q, want empty", name)
	}
}

func TestRegistryCreate_NameRequired(t *testing.T) {
	r, _ := Open(":memory:")
	defer r.Close()
	if err := r.Create(App{}); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestRegistryCreate_DefaultMode(t *testing.T) {
	r, _ := Open(":memory:")
	defer r.Close()
	_ = r.Create(App{Name: "testapp"})
	got, _ := r.Get("testapp")
	if got.Mode != ModeObserve {
		t.Errorf("default mode = %v, want observe", got.Mode)
	}
}

func TestRegistrySetMode_NotFound(t *testing.T) {
	r, _ := Open(":memory:")
	defer r.Close()
	if err := r.SetMode("nonexistent", ModeLocked); err == nil {
		t.Error("expected error for missing app")
	}
}

func TestRegistryDelete_NotFound(t *testing.T) {
	r, _ := Open(":memory:")
	defer r.Close()
	if err := r.Delete("ghost"); err == nil {
		t.Error("expected error for missing app")
	}
}

func TestRegistryIndexRebuild(t *testing.T) {
	// Open, create, close, re-open — index must rebuild from SQLite.
	path := t.TempDir() + "/apps.db"
	r, _ := Open(path)
	_ = r.Create(App{
		Name: "myapp",
		Services: []Service{
			{Name: "web", CgroupMatch: "/system.slice/myapp.service"},
		},
	})
	r.Close()

	r2, err := Open(path)
	if err != nil {
		t.Fatalf("re-open: %v", err)
	}
	defer r2.Close()
	if name := r2.AppForCgroup("/system.slice/myapp.service"); name != "myapp" {
		t.Errorf("index not rebuilt: AppForCgroup = %q", name)
	}
}

func TestDetectServiceType(t *testing.T) {
	cases := []struct {
		binary, comm string
		want         ServiceType
	}{
		{"/usr/sbin/nginx", "nginx", ServiceNginx},
		{"/usr/sbin/php-fpm8.2", "php-fpm8.2", ServicePhpFpm},
		{"/usr/bin/mysqld", "mysqld", ServiceMySQL},
		{"/usr/bin/redis-server", "redis-server", ServiceRedis},
		{"/usr/lib/postgresql/14/bin/postgres", "postgres", ServicePostgres},
		{"/usr/bin/node", "node", ServiceNode},
		{"/usr/bin/python3", "python3", ServicePython},
		{"/usr/bin/gunicorn", "gunicorn", ServicePython},
		{"/usr/local/bin/myapp", "myapp", ServiceCustom},
		{"", "unknown", ServiceCustom},
	}
	for _, c := range cases {
		got := detectServiceType(c.binary, c.comm)
		if got != c.want {
			t.Errorf("detectServiceType(%q, %q) = %v, want %v", c.binary, c.comm, got, c.want)
		}
	}
}
