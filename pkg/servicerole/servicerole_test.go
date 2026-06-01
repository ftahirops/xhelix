package servicerole

import "testing"

func TestClassify_KnownBinaries(t *testing.T) {
	cases := []struct {
		bin, comm, appKind string
		listenPort         uint16
		want               Role
	}{
		{"/usr/sbin/nginx", "nginx", "", 0, RoleWeb},
		{"/usr/sbin/apache2", "apache2", "", 0, RoleWeb},
		{"/usr/bin/caddy", "caddy", "", 0, RoleWeb},
		{"/usr/sbin/mysqld", "mysqld", "", 0, RoleDatabase},
		{"/usr/lib/postgresql/16/bin/postgres", "postgres", "", 0, RoleDatabase},
		{"/usr/bin/mongod", "mongod", "", 0, RoleDatabase},
		{"/usr/bin/redis-server", "redis-server", "", 0, RoleCache},
		{"/usr/bin/memcached", "memcached", "", 0, RoleCache},
		{"/usr/sbin/rabbitmq-server", "beam.smp", "", 0, RoleBroker},
		{"/usr/sbin/haproxy", "haproxy", "", 0, RoleProxy},
		{"/usr/sbin/sshd", "sshd", "", 0, RoleSSH},
		{"/usr/lib/postfix/sbin/master", "master", "", 0, RoleMail},
		{"/usr/sbin/named", "named", "", 0, RoleDNS},
		{"/opt/app/server", "server", "web", 0, RoleWeb},
		{"/usr/bin/python3", "python3", "service", 0, RoleOther},
		{"/usr/bin/curl", "curl", "", 0, RoleOther},
	}
	for _, c := range cases {
		if got := Classify(c.bin, c.comm, c.appKind, c.listenPort); got != c.want {
			t.Errorf("Classify(%q,%q,%q,%d)=%q want %q", c.bin, c.comm, c.appKind, c.listenPort, got, c.want)
		}
	}
}

func TestClassify_PortFallback(t *testing.T) {
	if got := Classify("/opt/x/db", "db", "", 3306); got != RoleDatabase {
		t.Errorf("port 3306 fallback = %q want database", got)
	}
	if got := Classify("/opt/x/srv", "srv", "", 6379); got != RoleCache {
		t.Errorf("port 6379 fallback = %q want cache", got)
	}
}
