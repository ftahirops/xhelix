package brpparser

import (
	"testing"
)

func TestPHPFPM_DefaultPool(t *testing.T) {
	conf := `
[global]
pid = /run/php/php8.1-fpm.pid
error_log = /var/log/php8.1-fpm.log

[www]
user = www-data
group = www-data
listen = /run/php/php8.1-fpm.sock
pm = dynamic
pm.max_children = 50
`
	path := writeTmp(t, "phpfpm.conf", conf)
	b, k, err := ParsePHPFPM(path)
	if err != nil {
		t.Fatalf("ParsePHPFPM: %v", err)
	}
	if !contains(b.ListenSockets, "/run/php/php8.1-fpm.sock") {
		t.Errorf("socket missing: %v", b.ListenSockets)
	}
	if !contains(b.Features, "pool_www") {
		t.Errorf("pool_www feature expected: %v", b.Features)
	}
	if !contains(b.Features, "pm_dynamic") {
		t.Errorf("pm_dynamic expected: %v", b.Features)
	}
	if !contains(b.Features, "runas_www-data") {
		t.Errorf("runas_www-data expected: %v", b.Features)
	}
	if b.Role != "phpfpm-unix-pool" {
		t.Errorf("Role = %q, want phpfpm-unix-pool", b.Role)
	}
	if k.App != "phpfpm" {
		t.Errorf("App = %q, want phpfpm", k.App)
	}
}

func TestPHPFPM_TCPPool(t *testing.T) {
	conf := `
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 20
`
	path := writeTmp(t, "phpfpm.conf", conf)
	b, _, _ := ParsePHPFPM(path)
	if !containsInt(b.ListenPorts, 9000) {
		t.Errorf("port 9000 expected: %v", b.ListenPorts)
	}
	if b.Role != "phpfpm-tcp-pool" {
		t.Errorf("Role = %q, want phpfpm-tcp-pool", b.Role)
	}
}

func TestPHPFPM_Hardened(t *testing.T) {
	conf := `
[www]
listen = /run/php/fpm.sock
user = www-data
chroot = /var/www/jail
php_admin_value[open_basedir] = /var/www/site:/tmp
php_admin_value[disable_functions] = exec,system,shell_exec,passthru,popen,proc_open
php_admin_value[upload_tmp_dir] = /var/www/site/tmp
security.limit_extensions = .php
`
	path := writeTmp(t, "phpfpm.conf", conf)
	b, _, _ := ParsePHPFPM(path)
	if !contains(b.Features, "chroot") {
		t.Errorf("chroot feature expected: %v", b.Features)
	}
	if !contains(b.Features, "open_basedir") {
		t.Errorf("open_basedir expected: %v", b.Features)
	}
	if !contains(b.Features, "disable_functions") {
		t.Errorf("disable_functions expected: %v", b.Features)
	}
	if !contains(b.Features, "limit_extensions") {
		t.Errorf("limit_extensions expected: %v", b.Features)
	}
	if !contains(b.ReadRoots, "/var/www/jail/") {
		t.Errorf("chroot dir missing from ReadRoots: %v", b.ReadRoots)
	}
	if !contains(b.ReadRoots, "/var/www/site/") {
		t.Errorf("open_basedir path missing from ReadRoots: %v", b.ReadRoots)
	}
	if !contains(b.WriteRoots, "/var/www/site/tmp/") {
		t.Errorf("upload_tmp_dir missing: %v", b.WriteRoots)
	}
	if b.Role != "phpfpm-hardened" {
		t.Errorf("Role = %q, want phpfpm-hardened", b.Role)
	}
}

func TestPHPFPM_DangerousFlags(t *testing.T) {
	conf := `
[www]
listen = /sock
php_admin_flag[allow_url_include] = on
`
	path := writeTmp(t, "phpfpm.conf", conf)
	b, _, _ := ParsePHPFPM(path)
	if !contains(b.Features, "allow_url_include") {
		t.Errorf("allow_url_include feature expected: %v", b.Features)
	}
	if len(b.ParseWarnings) == 0 {
		t.Error("allow_url_include=on should produce a warning")
	}
}

func TestPHPFPM_NoPoolWarning(t *testing.T) {
	conf := `
[global]
pid = /run/php-fpm.pid
error_log = /var/log/php-fpm.log
`
	path := writeTmp(t, "phpfpm.conf", conf)
	b, _, _ := ParsePHPFPM(path)
	if len(b.ParseWarnings) == 0 {
		t.Error("no [pool] section should produce a warning")
	}
}

func TestPHPFPM_MultiplePools(t *testing.T) {
	conf := `
[www]
listen = /run/www.sock
user = www-data

[admin]
listen = 127.0.0.1:9001
user = admin
`
	path := writeTmp(t, "phpfpm.conf", conf)
	b, _, _ := ParsePHPFPM(path)
	if !contains(b.Features, "pool_www") || !contains(b.Features, "pool_admin") {
		t.Errorf("expected both pool_www and pool_admin: %v", b.Features)
	}
	if !contains(b.ListenSockets, "/run/www.sock") {
		t.Errorf("www pool socket missing: %v", b.ListenSockets)
	}
	if !containsInt(b.ListenPorts, 9001) {
		t.Errorf("admin pool port 9001 missing: %v", b.ListenPorts)
	}
}

func TestPHPFPM_NonExistentFileError(t *testing.T) {
	_, _, err := ParsePHPFPM("/nonexistent/phpfpm.conf")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}
