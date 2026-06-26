package pipeline

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/proctree"
)

// Compile-time + zero-value guard: the Pipeline carries the workflowchain
// wiring fields and a zero Pipeline neither panics nor enables learning.
func TestPipeline_HasWorkflowChainFields(t *testing.T) {
	var p Pipeline
	if p.Origins != nil {
		t.Error("zero Pipeline.Origins must be nil")
	}
	if p.RecordWindowOpen {
		t.Error("record window must default closed")
	}
}

func TestStampWorkflowChain_WebRoot_Learnable(t *testing.T) {
	pt := proctree.New(1000)
	pt.OnSpawn(proctree.Node{PID: 42, PrimarySource: lineage.LineageID(7)})

	origins := lineage.NewStore()
	origins.Put(lineage.Origin{ID: 7, Type: lineage.RootWeb})

	p := &Pipeline{ProcTree: pt, Origins: origins, RecordWindowOpen: true}

	ev := &model.Event{
		PID:  42,
		Tags: map[string]string{"app_id": "shop:site-a.com"},
	}
	p.stampWorkflowChain(ev)

	if ev.Tags["root_type"] != "web" {
		t.Errorf("root_type = %q, want \"web\"", ev.Tags["root_type"])
	}
	if ev.Tags["chain_id"] == "" {
		t.Error("chain_id must be stamped")
	}
	if ev.Tags["learnable"] != "true" {
		t.Errorf("learnable = %q, want \"true\"", ev.Tags["learnable"])
	}
}

func TestStampWorkflowChain_RecordClosed_NotLearnable(t *testing.T) {
	pt := proctree.New(1000)
	pt.OnSpawn(proctree.Node{PID: 42, PrimarySource: lineage.LineageID(7)})
	origins := lineage.NewStore()
	origins.Put(lineage.Origin{ID: 7, Type: lineage.RootWeb})

	p := &Pipeline{ProcTree: pt, Origins: origins, RecordWindowOpen: false}
	ev := &model.Event{PID: 42, Tags: map[string]string{"app_id": "shop"}}
	p.stampWorkflowChain(ev)

	if ev.Tags["learnable"] != "false" {
		t.Errorf("learnable = %q, want \"false\" (record window closed)", ev.Tags["learnable"])
	}
}

func TestStampWorkflowChain_NilDeps_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("stamp must be nil-safe: %v", r)
		}
	}()
	p := &Pipeline{} // no ProcTree, no Origins
	ev := &model.Event{PID: 1, Tags: map[string]string{}}
	p.stampWorkflowChain(ev)
	if ev.Tags["chain_id"] == "" {
		t.Error("chain_id should still be stamped (root 0, unknown type)")
	}
}

func TestStampWorkflowChain_AdminShell_NotLearnable(t *testing.T) {
	pt := proctree.New(1000)
	pt.OnSpawn(proctree.Node{PID: 9, PrimarySource: lineage.LineageID(3)})
	origins := lineage.NewStore()
	origins.Put(lineage.Origin{ID: 3, Type: lineage.RootSSH}) // interactive admin

	p := &Pipeline{ProcTree: pt, Origins: origins, RecordWindowOpen: true}
	ev := &model.Event{PID: 9, Tags: map[string]string{"app_id": "shop"}}
	p.stampWorkflowChain(ev)

	if ev.Tags["learnable"] != "false" {
		t.Errorf("learnable = %q, want \"false\" (admin shell is noise)", ev.Tags["learnable"])
	}
	if ev.Tags["phase"] != "admin" {
		t.Errorf("phase = %q, want \"admin\"", ev.Tags["phase"])
	}
}

func TestPipeline_HasRecorderField(t *testing.T) {
	var p Pipeline
	if p.Recorder != nil {
		t.Error("zero Pipeline.Recorder must be nil (recording disabled by default)")
	}
}
