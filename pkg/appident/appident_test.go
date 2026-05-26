package appident

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHeuristicNginxVhost(t *testing.T) {
	i := New(nil)
	a := i.Identify(Signals{
		LineageID:  1,
		ExePath:    "/usr/sbin/nginx",
		ArgvJoined: "nginx -c /etc/nginx/sites-enabled/site-a.conf",
	})
	if a.Name != "nginx" || a.Vhost != "site-a" || a.Kind != KindWeb {
		t.Errorf("nginx vhost id wrong: %+v", a)
	}
}

func TestHeuristicPHPFPMPool(t *testing.T) {
	i := New(nil)
	a := i.Identify(Signals{
		LineageID:  2,
		CgroupPath: "/system.slice/php-fpm@site-a.service",
		ExePath:    "/usr/sbin/php-fpm8.2",
	})
	if a.Name != "php-fpm" || a.Vhost != "site-a" {
		t.Errorf("php-fpm vhost id wrong: %+v", a)
	}
}

func TestHeuristicSystemdUnit(t *testing.T) {
	i := New(nil)
	a := i.Identify(Signals{
		LineageID:  3,
		CgroupPath: "/system.slice/redis.service",
		ExePath:    "/usr/bin/redis-server",
	})
	if a.Name != "redis" || a.Kind != KindService {
		t.Errorf("redis id wrong: %+v", a)
	}
}

func TestHeuristicContainer(t *testing.T) {
	i := New(nil)
	a := i.Identify(Signals{
		LineageID:  4,
		CgroupPath: "/docker/abcdef012345abcd/etc",
		ExePath:    "/usr/bin/myapp",
	})
	if a.Name != "docker" || a.Kind != KindContainer || len(a.Vhost) != 12 {
		t.Errorf("docker id wrong: %+v", a)
	}
}

func TestHeuristicBasenameStripsVersion(t *testing.T) {
	i := New(nil)
	a := i.Identify(Signals{LineageID: 5, ExePath: "/usr/bin/python3.11"})
	if a.Name != "python" {
		t.Errorf("python version-strip wrong: %+v", a)
	}
}

func TestHeuristicCommServerApp_Recognized(t *testing.T) {
	cases := map[string]string{
		"nginx":        "nginx",
		"mysqld":       "mysql",
		"postgres":     "postgres",
		"sshd":         "sshd",
		"redis-server": "redis",
		"dockerd":      "docker",
	}
	for comm, wantName := range cases {
		a := New(nil).Identify(Signals{LineageID: 0, Comm: comm})
		if a.Name != wantName {
			t.Errorf("comm=%q: got Name=%q, want %q", comm, a.Name, wantName)
		}
		if a.Source != "heuristic:comm" {
			t.Errorf("comm=%q: source=%q, want heuristic:comm", comm, a.Source)
		}
	}
}

func TestHeuristicCommServerApp_UnknownComm(t *testing.T) {
	// Unknown comm + no other signals → empty identification.
	a := New(nil).Identify(Signals{Comm: "totally_made_up_proc"})
	if !a.Empty() {
		t.Errorf("unknown comm with no other signals should be empty, got %+v", a)
	}
}

func TestHeuristicCommServerApp_ExeWins(t *testing.T) {
	// When ExePath gives us a clear answer (basename heuristic), comm
	// fallback should NOT override it. Order: exe-based → comm.
	a := New(nil).Identify(Signals{
		ExePath: "/usr/sbin/sshd",
		Comm:    "nginx", // bogus comm — must not be used
	})
	if a.Name != "sshd" {
		t.Errorf("exe-basename should win over comm, got Name=%q", a.Name)
	}
}

func TestDeclarationOverridesHeuristics(t *testing.T) {
	i := New([]Declaration{
		{
			App:   "my-wordpress-a",
			Kind:  KindWeb,
			Vhost: "site-a.com",
			Match: MatchRules{
				CgroupSubstring: []string{"php-fpm@site-a"},
			},
		},
	})
	a := i.Identify(Signals{
		LineageID:  6,
		CgroupPath: "/system.slice/php-fpm@site-a.service",
		ExePath:    "/usr/sbin/php-fpm8.2",
	})
	if a.Name != "my-wordpress-a" {
		t.Errorf("operator decl should override heuristic; got %+v", a)
	}
}

func TestIdentityIsCached(t *testing.T) {
	i := New(nil)
	a1 := i.Identify(Signals{LineageID: 7, ExePath: "/usr/bin/redis-server"})
	// Now call with empty signals — should hit cache.
	a2 := i.Identify(Signals{LineageID: 7})
	if a1 != a2 {
		t.Errorf("cache miss: %+v vs %+v", a1, a2)
	}
}

func TestLoadDeclsMissingDirIsSilent(t *testing.T) {
	d, errs := LoadDecls("/nonexistent/path/here")
	if errs != nil {
		t.Errorf("missing dir should be silent, got: %v", errs)
	}
	if d != nil {
		t.Errorf("expected nil decls")
	}
}

func TestLoadDeclsFromDir(t *testing.T) {
	dir := t.TempDir()
	body := `app: my-site
kind: web
vhost: site-a.com
match:
  cgroup_substring:
    - "php-fpm@site-a"
  argv_substring:
    - "/etc/nginx/sites-enabled/site-a"
`
	if err := os.WriteFile(filepath.Join(dir, "site-a.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	d, errs := LoadDecls(dir)
	if len(errs) > 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(d) != 1 || d[0].App != "my-site" {
		t.Errorf("decl load wrong: %+v", d)
	}
}

func TestForgetEvictsCache(t *testing.T) {
	i := New(nil)
	_ = i.Identify(Signals{LineageID: 99, ExePath: "/usr/bin/redis-server"})
	i.Forget(99)
	a := i.Identify(Signals{LineageID: 99}) // empty signals
	if !a.Empty() {
		t.Errorf("forget didn't evict; got %+v", a)
	}
}
