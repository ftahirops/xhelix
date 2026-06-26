package main

import (
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/contractpropose"
)

func TestRenderProposalList_ShowsIDStatusReason(t *testing.T) {
	out := renderProposalList([]contractpropose.Proposal{
		{ID: "p1", App: "shop", Status: contractpropose.StatusPending, Reason: "synthesized from 42 observations", CreatedAt: time.Unix(1_700_000_000, 0)},
	})
	for _, want := range []string{"p1", "shop", "pending", "42 observations"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered list missing %q\n%s", want, out)
		}
	}
}
