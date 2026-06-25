package pipeline

import "testing"

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
