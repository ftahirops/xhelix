package edgeobserve

import (
	"testing"
	"time"
)

func TestObserveAggregatesDestsAndDedups(t *testing.T) {
	o := New()
	t0 := time.Unix(1700000000, 0)
	o.Observe(t0, "php-fpm", "mysql", "net_connect", "10.0.0.5:3306", -1.5, "known edge")
	o.Observe(t0, "php-fpm", "mysql", "net_connect", "10.0.0.6:3306", -1.5, "known edge")
	o.Observe(t0, "php-fpm", "mysql", "net_connect", "10.0.0.5:3306", -1.5, "known edge") // dup dest
	o.Observe(t0, "nginx", "php-fpm", "net_connect", "127.0.0.1:9101", -1.5, "known edge")
	snap := o.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("edges = %d, want 2", len(snap))
	}
	// nginx sorts before php-fpm.
	if snap[0].FromApp != "nginx" || snap[1].FromApp != "php-fpm" {
		t.Fatalf("sort order wrong: %+v", snap)
	}
	fpm := snap[1]
	if fpm.ToApp != "mysql" || fpm.Count != 3 || len(fpm.Dests) != 2 {
		t.Errorf("php-fpm→mysql = count %d dests %v, want count 3, 2 dests", fpm.Count, fpm.Dests)
	}
}

func TestObserveIgnoresUnattributed(t *testing.T) {
	o := New()
	t0 := time.Unix(1700000000, 0)
	o.Observe(t0, "", "mysql", "net_connect", "x", 0, "")
	o.Observe(t0, "php-fpm", "", "net_connect", "x", 0, "")
	if len(o.Snapshot()) != 0 {
		t.Error("unattributed edges must be ignored")
	}
}
