package servicerole

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

func TestClassifyByCgroup(t *testing.T) {
	cases := []struct {
		cgroup   string
		wantKind protectedsvc.ServiceKind
		wantRole protectedsvc.ServiceRole
		wantOK   bool
	}{
		{"/system.slice/nginx.service", protectedsvc.KindNginx, protectedsvc.RoleReverseProxy, true},
		{"/system.slice/apache2.service", protectedsvc.KindApache, protectedsvc.RoleReverseProxy, true},
		{"/system.slice/httpd.service", protectedsvc.KindApache, protectedsvc.RoleReverseProxy, true},
		{"/system.slice/mysql.service", protectedsvc.KindMysql, protectedsvc.RoleDatabase, true},
		{"/system.slice/mariadb.service", protectedsvc.KindMysql, protectedsvc.RoleDatabase, true},
		{"/system.slice/postgresql.service", protectedsvc.KindPostgres, protectedsvc.RoleDatabase, true},
		{"/system.slice/postgresql@14-main.service", protectedsvc.KindPostgres, protectedsvc.RoleDatabase, true},
		{"/system.slice/redis-server.service", protectedsvc.KindRedis, protectedsvc.RoleCache, true},
		// Not a protected service — must NOT classify.
		{"/system.slice/cron.service", "", "", false},
		{"/system.slice/ssh.service", "", "", false},
		{"/system.slice/php8.1-fpm.service", "", "", false},
		{"/user.slice/user-1000.slice/session-3.scope", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		k, r, ok := ClassifyByCgroup(c.cgroup)
		if ok != c.wantOK || k != c.wantKind || r != c.wantRole {
			t.Errorf("ClassifyByCgroup(%q) = (%q,%q,%v); want (%q,%q,%v)",
				c.cgroup, k, r, ok, c.wantKind, c.wantRole, c.wantOK)
		}
	}
}
