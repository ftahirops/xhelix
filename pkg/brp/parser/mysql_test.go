package brpparser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMySQL_Defaults(t *testing.T) {
	// Minimal config — should still produce default port 3306 + sensible roots.
	path := writeTmp(t, "my.cnf", "[mysqld]\n")
	b, k, err := ParseMySQL(path)
	if err != nil {
		t.Fatalf("ParseMySQL: %v", err)
	}
	if !containsInt(b.ListenPorts, 3306) {
		t.Errorf("default port 3306 expected: %v", b.ListenPorts)
	}
	if b.Role != "mysql-default" {
		t.Errorf("Role = %q, want mysql-default", b.Role)
	}
	if k.App != "mysql" {
		t.Errorf("App = %q, want mysql", k.App)
	}
}

func TestMySQL_FullConfig(t *testing.T) {
	conf := `
[client]
port = 3306

[mysqld]
port = 3307
bind-address = 127.0.0.1
socket = /var/run/mysqld/mysqld.sock
datadir = /var/lib/mysql
log_error = /var/log/mysql/error.log
slow_query_log_file = /var/log/mysql/slow.log
plugin_dir = /usr/lib/mysql/plugin
plugin_load = audit_log=audit_log.so;keyring=keyring.so
ssl-cert = /etc/mysql/certs/server.crt
ssl-key = /etc/mysql/certs/server.key
log_bin = /var/log/mysql/binlog
server-id = 1
tmpdir = /tmp
`
	path := writeTmp(t, "my.cnf", conf)
	b, _, _ := ParseMySQL(path)
	if !containsInt(b.ListenPorts, 3307) {
		t.Errorf("port 3307 expected: %v", b.ListenPorts)
	}
	if !contains(b.ListenSockets, "/var/run/mysqld/mysqld.sock") {
		t.Errorf("socket missing: %v", b.ListenSockets)
	}
	if !contains(b.ReadRoots, "/var/lib/mysql/") {
		t.Errorf("datadir missing from ReadRoots: %v", b.ReadRoots)
	}
	if !contains(b.WriteRoots, "/var/lib/mysql/") {
		t.Errorf("datadir missing from WriteRoots: %v", b.WriteRoots)
	}
	if !contains(b.WriteRoots, "/var/log/mysql/") {
		t.Errorf("error log dir missing: %v", b.WriteRoots)
	}
	if !contains(b.ReadRoots, "/usr/lib/mysql/plugin/") {
		t.Errorf("plugin_dir missing: %v", b.ReadRoots)
	}
	if !contains(b.Modules, "audit_log") || !contains(b.Modules, "keyring") {
		t.Errorf("plugin_load not parsed: %v", b.Modules)
	}
	if !contains(b.Features, "tls") {
		t.Errorf("tls feature expected from ssl-cert: %v", b.Features)
	}
	if !contains(b.Features, "binary_log") {
		t.Errorf("binary_log feature expected: %v", b.Features)
	}
	if b.Role != "mysql-primary" {
		t.Errorf("Role = %q, want mysql-primary (has server_id + binary_log)", b.Role)
	}
}

func TestMySQL_Replica(t *testing.T) {
	conf := `
[mysqld]
relay_log = /var/log/mysql/relay
server-id = 2
`
	path := writeTmp(t, "my.cnf", conf)
	b, _, _ := ParseMySQL(path)
	if b.Role != "mysql-replica" {
		t.Errorf("Role = %q, want mysql-replica", b.Role)
	}
	if !contains(b.Features, "replication_replica") {
		t.Errorf("replication_replica feature expected: %v", b.Features)
	}
}

func TestMySQL_Galera(t *testing.T) {
	conf := `
[mysqld]
wsrep_provider = /usr/lib/galera/libgalera_smm.so
wsrep_cluster_address = gcomm://node1,node2,node3
`
	path := writeTmp(t, "my.cnf", conf)
	b, _, _ := ParseMySQL(path)
	if b.Role != "mysql-galera" {
		t.Errorf("Role = %q, want mysql-galera", b.Role)
	}
}

func TestMySQL_UnixOnly(t *testing.T) {
	conf := `
[mysqld]
skip-networking = 1
socket = /run/mysqld/mysqld.sock
`
	path := writeTmp(t, "my.cnf", conf)
	b, _, _ := ParseMySQL(path)
	if b.Role != "mysql-unix-only" {
		t.Errorf("Role = %q, want mysql-unix-only", b.Role)
	}
	if containsInt(b.ListenPorts, 3306) {
		t.Errorf("skip_networking should suppress default port: %v", b.ListenPorts)
	}
}

func TestMySQL_IncludeDir(t *testing.T) {
	tmp := t.TempDir()
	subdir := filepath.Join(tmp, "conf.d")
	_ = os.MkdirAll(subdir, 0o755)
	_ = os.WriteFile(filepath.Join(subdir, "extra.cnf"),
		[]byte("[mysqld]\nport = 5555\n"), 0o644)
	main := filepath.Join(tmp, "my.cnf")
	_ = os.WriteFile(main,
		[]byte("[mysqld]\nport = 3306\n!includedir "+subdir+"\n"), 0o644)
	b, _, err := ParseMySQL(main)
	if err != nil {
		t.Fatalf("ParseMySQL: %v", err)
	}
	if !containsInt(b.ListenPorts, 5555) {
		t.Errorf("included port 5555 missing: %v", b.ListenPorts)
	}
}

func TestMySQL_DashUnderscoreEquivalence(t *testing.T) {
	conf := `
[mysqld]
bind-address = 127.0.0.1
bind_address = 0.0.0.0:3308
log-bin = /tmp/binlog
`
	path := writeTmp(t, "my.cnf", conf)
	b, _, _ := ParseMySQL(path)
	if !containsInt(b.ListenPorts, 3308) {
		t.Errorf("bind_address port 3308 missing: %v", b.ListenPorts)
	}
	if !contains(b.Features, "binary_log") {
		t.Errorf("log-bin (dash form) should set binary_log: %v", b.Features)
	}
}

func TestMySQL_NonExistentFileError(t *testing.T) {
	_, _, err := ParseMySQL("/nonexistent/my.cnf")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}
