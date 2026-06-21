package servicerole

import "testing"

func TestDenyExec(t *testing.T) {
	cases := []struct {
		name     string
		cgroup   string
		binary   string
		wantDeny bool
	}{
		{"mysql execs sh -> deny", "/system.slice/mysql.service", "/bin/sh", true},
		{"mysql execs python3 (wildcard) -> deny", "/system.slice/mysql.service", "/usr/bin/python3", true},
		{"redis execs curl -> deny", "/system.slice/redis-server.service", "/usr/bin/curl", true},
		{"mysql execs its own daemon -> allow", "/system.slice/mysql.service", "/usr/sbin/mysqld", false},
		{"unclassified cgroup -> allow (no floor)", "/system.slice/cron.service", "/bin/sh", false},
		{"php-fpm intentionally unprotected here -> allow", "/system.slice/php8.1-fpm.service", "/bin/sh", false},
		{"empty cgroup -> allow", "", "/bin/sh", false},
	}
	for _, c := range cases {
		deny, reason := DenyExec(c.cgroup, c.binary)
		if deny != c.wantDeny {
			t.Errorf("%s: DenyExec(%q,%q)=%v (reason %q); want %v",
				c.name, c.cgroup, c.binary, deny, reason, c.wantDeny)
		}
		if deny && reason == "" {
			t.Errorf("%s: deny must carry a non-empty reason", c.name)
		}
	}
}

func TestMatchExecPath(t *testing.T) {
	if !matchExecPath("/usr/bin/python*", "/usr/bin/python3.11") {
		t.Error("wildcard prefix should match python3.11")
	}
	if matchExecPath("/bin/sh", "/bin/bash") {
		t.Error("exact match should not match a different path")
	}
	if !matchExecPath("/bin/sh", "/bin/sh") {
		t.Error("exact match should match identical path")
	}
}
