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

func TestObserveOpFusesOntoConnectEdge(t *testing.T) {
	o := New()
	t0 := time.Unix(1700000000, 0)
	// A plain connect creates the php-fpm→mysql edge...
	o.Observe(t0, "php-fpm", "mysql", "net_connect", "10.0.0.5:3306", -1.5, "known edge")
	// ...and DB-query ops fuse onto the SAME edge (same key), deduped + sorted.
	o.ObserveOp(t0, "php-fpm", "mysql", "net_connect", "SELECT wp_posts")
	o.ObserveOp(t0, "php-fpm", "mysql", "net_connect", "SELECT wp_options")
	o.ObserveOp(t0, "php-fpm", "mysql", "net_connect", "SELECT wp_posts") // dup op
	snap := o.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("edges = %d, want 1 (ops must fuse, not fork)", len(snap))
	}
	e := snap[0]
	if e.FromApp != "php-fpm" || e.ToApp != "mysql" {
		t.Fatalf("wrong edge: %+v", e)
	}
	if e.Count != 1 {
		t.Errorf("count = %d, want 1 (ObserveOp must not inflate connect count)", e.Count)
	}
	want := []string{"SELECT wp_options", "SELECT wp_posts"}
	if len(e.Ops) != len(want) || e.Ops[0] != want[0] || e.Ops[1] != want[1] {
		t.Errorf("ops = %v, want %v (deduped, sorted)", e.Ops, want)
	}
}

func TestObserveOpUpsertsWhenConnectUnseen(t *testing.T) {
	o := New()
	t0 := time.Unix(1700000000, 0)
	// No prior connect: ObserveOp alone must materialize the edge.
	o.ObserveOp(t0, "php-fpm", "redis", "net_connect", "PING")
	snap := o.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("edges = %d, want 1", len(snap))
	}
	if snap[0].ToApp != "redis" || len(snap[0].Ops) != 1 || snap[0].Ops[0] != "PING" {
		t.Errorf("edge = %+v, want redis with op PING", snap[0])
	}
}

func TestObserveOpIgnoresUnattributed(t *testing.T) {
	o := New()
	t0 := time.Unix(1700000000, 0)
	o.ObserveOp(t0, "", "mysql", "net_connect", "SELECT x")
	o.ObserveOp(t0, "php-fpm", "", "net_connect", "SELECT x")
	o.ObserveOp(t0, "php-fpm", "mysql", "net_connect", "") // empty op
	o.ObserveOp(t0, "redis", "redis", "net_connect", "PING") // self-edge (redis-server's own PING)
	if len(o.Snapshot()) != 0 {
		t.Error("unattributed / empty-op / self edges must be ignored")
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
