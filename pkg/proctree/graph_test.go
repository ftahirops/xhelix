package proctree

import (
	"testing"
)

func TestGraphAncestors(t *testing.T) {
	g := New(0)
	// init -> sshd -> bash -> curl
	g.OnSpawn(Node{PID: 1, PPID: 0, Comm: "init"})
	g.OnSpawn(Node{PID: 100, PPID: 1, Comm: "sshd"})
	g.OnSpawn(Node{PID: 200, PPID: 100, Comm: "bash"})
	g.OnSpawn(Node{PID: 300, PPID: 200, Comm: "curl"})

	chain := g.Ancestors(300, 0)
	if len(chain) != 4 {
		t.Fatalf("ancestors len = %d, want 4", len(chain))
	}
	want := []string{"curl", "bash", "sshd", "init"}
	for i, w := range want {
		if chain[i].Comm != w {
			t.Errorf("ancestors[%d] = %q, want %q", i, chain[i].Comm, w)
		}
	}
}

func TestGraphExitReparentsChildren(t *testing.T) {
	g := New(0)
	g.OnSpawn(Node{PID: 1, PPID: 0, Comm: "init"})
	g.OnSpawn(Node{PID: 100, PPID: 1, Comm: "sshd"})
	g.OnSpawn(Node{PID: 200, PPID: 100, Comm: "bash"})

	g.OnExit(100)

	// bash's PPID should now be 1
	chain := g.Ancestors(200, 0)
	if len(chain) != 2 {
		t.Fatalf("after exit, ancestors len = %d, want 2", len(chain))
	}
	if chain[1].Comm != "init" {
		t.Errorf("after reparent, parent = %q, want init", chain[1].Comm)
	}
}

func TestGraphEviction(t *testing.T) {
	g := New(10)
	for i := uint32(1); i <= 20; i++ {
		g.OnSpawn(Node{PID: i, PPID: 0, Comm: "x"})
	}
	if g.Count() > 10 {
		t.Errorf("count = %d, want <= 10 after eviction", g.Count())
	}
}
