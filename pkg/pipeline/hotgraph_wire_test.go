package pipeline

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/canonical"
	"github.com/xhelix/xhelix/pkg/hotgraph"
	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
)

// TestPopulateHotGraph_InsertAndInherit proves a proc spawn lands in the
// hot graph with its parent edge, and inherits lineage + origin IP from
// the parent node — so ancestry/lineage/origin queries return live data.
func TestPopulateHotGraph_InsertAndInherit(t *testing.T) {
	hg := hotgraph.New(hotgraph.Options{MaxNodes: 1024})
	cache := canonical.NewProcKeyCache(canonical.CacheOptions{})
	// Pre-seed keys so Resolve hits cache (no /proc read in the test).
	parentKey := canonical.ProcKey{PID: 1000, StartTicks: 5000}
	childKey := canonical.ProcKey{PID: 1001, StartTicks: 6000}
	cache.Put(parentKey)
	cache.Put(childKey)

	// Parent node already in the graph, carrying a root lineage + origin IP.
	hg.Insert(hotgraph.ProcessNode{
		Key: parentKey, Comm: "sshd", LineageID: lineage.LineageID(42),
		OriginIP: "203.0.113.5", SpawnedAt: time.Unix(1700000000, 0),
	})

	p := &Pipeline{HotGraph: hg, ProcKeys: cache}
	child := model.Event{
		PID: 1001, ParentPID: 1000, Comm: "bash", UID: 0,
		Time: time.Unix(1700000005, 0),
		Tags: map[string]string{"image": "/bin/bash"},
	}
	p.populateHotGraph(child, 0) // explicitSource 0 → must inherit from parent

	got, ok := hg.Get(childKey)
	if !ok {
		t.Fatal("child node not inserted into hot graph")
	}
	if got.Parent != parentKey {
		t.Errorf("parent edge wrong: %+v", got.Parent)
	}
	if got.LineageID != 42 {
		t.Errorf("lineage not inherited from parent: got %d want 42", got.LineageID)
	}
	if got.OriginIP != "203.0.113.5" {
		t.Errorf("origin IP not inherited: got %q", got.OriginIP)
	}
	// Ancestors query (the LocalAPI surface) now walks up to the sshd root.
	anc := hg.Ancestors(childKey, -1)
	foundSSHD := false
	for _, n := range anc {
		if n.Comm == "sshd" {
			foundSSHD = true
		}
	}
	if !foundSSHD {
		t.Errorf("Ancestors should include the sshd root, got %+v", anc)
	}
	// ByLineage / ByOriginIP now resolve the child too.
	if len(hg.ByLineage(42)) != 2 {
		t.Errorf("ByLineage should list parent+child, got %d", len(hg.ByLineage(42)))
	}
	if len(hg.ByOriginIP("203.0.113.5")) != 2 {
		t.Errorf("ByOriginIP should list parent+child, got %d", len(hg.ByOriginIP("203.0.113.5")))
	}
}
