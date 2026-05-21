package vhostdiscovery

import (
	"testing"
)

func TestDedupRemovesDuplicateRoots(t *testing.T) {
	r := Result{Vhosts: []Vhost{
		{Source: "nginx", Root: "/srv/app"},
		{Source: "apache", Root: "/srv/app"},     // dup
		{Source: "nginx", Root: "/srv/app/"},     // dup (trailing slash)
		{Source: "plesk", Root: "/var/www/html"},
	}}
	r.dedup()
	if len(r.Vhosts) != 2 {
		t.Fatalf("expected 2 unique roots, got %d: %+v", len(r.Vhosts), r.Vhosts)
	}
}

func TestFIMWatchPatternsIncludesSentinels(t *testing.T) {
	r := Result{Vhosts: []Vhost{{Source: "nginx", Root: "/srv/app"}}}
	pats := FIMWatchPatterns(r)
	if len(pats) == 0 {
		t.Fatal("expected sentinel patterns")
	}
	want := []string{
		"/srv/app/wp-config.php",
		"/srv/app/.htaccess",
		"/srv/app/configuration.php",
		"/srv/app/.env",
		"/srv/app/wp-content/mu-plugins",
	}
	got := map[string]bool{}
	for _, p := range pats {
		got[p] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing sentinel %q", w)
		}
	}
}

func TestPortFromURL(t *testing.T) {
	cases := map[string]int{
		"http://127.0.0.1:9000":    9000,
		"http://127.0.0.1:9000/":   9000,
		"127.0.0.1:8080":           8080,
		"http://nope":              0,
		"unix:/run/php-fpm.sock":   0,
	}
	for in, want := range cases {
		if got := portFromURL(in); got != want {
			t.Errorf("portFromURL(%q) = %d, want %d", in, got, want)
		}
	}
}
