package pipeline

import "testing"

func TestDestServiceName(t *testing.T) {
	cases := map[[3]string]string{
		{"3306", "", ""}:                        "mysql",
		{"6379", "", ""}:                        "redis",
		{"5432", "", ""}:                        "postgres",
		{"9000", "", ""}:                        "php-fpm",
		{"9101", "", ""}:                        "php-fpm", // docker-mapped FastCGI band
		{"443", "", ""}:                         "",        // web is the actor, not a backing service
		{"", "/run/php/php-fpm.sock", ""}:       "php-fpm",
		{"", "/var/run/mysqld/mysqld.sock", ""}: "mysql",
	}
	for in, want := range cases {
		if got := destServiceName(in[0], in[1], in[2]); got != want {
			t.Errorf("destServiceName(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestCrossAppActorName(t *testing.T) {
	cases := map[[2]string]string{
		{"nginx", "/usr/sbin/nginx"}:           "nginx",
		{"php-fpm7.4", "/usr/sbin/php-fpm7.4"}: "php-fpm",
		{"mysqld", "/usr/sbin/mysqld"}:         "mysql",
		{"redis-server", ""}:                   "redis",
		{"bash", "/bin/bash"}:                  "",
	}
	for in, want := range cases {
		if got := crossAppActorName(in[0], in[1]); got != want {
			t.Errorf("crossAppActorName(%v) = %q, want %q", in, got, want)
		}
	}
}
