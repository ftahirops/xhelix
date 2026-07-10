package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/source"
	"github.com/xhelix/xhelix/pkg/webroot"
)

// TestAttributeFcgiRoot_MintsPerRequestAppRoot exercises the Root Emitters "B"
// (app tier) wire end-to-end through Handle:
//
//  1. A fcgi_request event carrying the serving php-fpm worker PID + http_host
//     (but no request_id) flows through Handle.
//  2. attributeFcgiRoot synthesizes an "f"-prefixed app-tier request_id.
//  3. WebRoots.MintRequest mints a KindWeb anchor carrying that request id.
//  4. ProcTree attributes the worker PID to the minted anchor, so the worker's
//     later DB/file events inherit the originating request as their root.
func TestAttributeFcgiRoot_MintsPerRequestAppRoot(t *testing.T) {
	ctx := context.Background()

	pt := proctree.New(0)
	srcStore, err := source.Open(":memory:")
	if err != nil {
		t.Fatalf("source.Open: %v", err)
	}
	defer srcStore.Close()

	minter := source.NewMinter(srcStore, lineage.NewMinter(), lineage.NewStore(), "test-host")
	p := &Pipeline{
		ProcTree:     pt,
		SourceMinter: minter,
		WebRoots:     webroot.New(),
	}

	const workerPID uint32 = 9001
	pt.OnSpawn(proctree.Node{PID: workerPID, PPID: 1, Comm: "php-fpm"})

	ev := model.NewEvent("ebpf", model.SeverityInfo)
	ev.PID = workerPID
	ev.Comm = "php-fpm"
	ev.Tags = map[string]string{
		"kind":            "fcgi_request",
		"http_host":       "site-a.com",
		"http_uri":        "/wp-login.php",
		"fcgi_request_id": "1",
	}
	p.Handle(ctx, ev)

	// 1. request_id synthesized + app-tier "f" prefix.
	rid := ev.Tags["request_id"]
	if rid == "" {
		t.Fatal("request_id not synthesized for app-tier fcgi root")
	}
	if !strings.HasPrefix(rid, "f") {
		t.Errorf("app-tier request_id = %q, want an \"f\"-prefixed id (distinct from nginx \"n\")", rid)
	}

	// 2. worker PID attributed to a source root.
	primary, _ := pt.SourceOf(workerPID)
	if primary == 0 {
		t.Fatal("worker PID 9001 not attributed to a source root")
	}

	// 3. the minted anchor is a web root persisting the request id.
	a, err := srcStore.Get(ctx, primary)
	if err != nil {
		t.Fatalf("store.Get(minted anchor): %v", err)
	}
	if a.Kind != source.KindWeb {
		t.Errorf("anchor kind = %v, want source.KindWeb", a.Kind)
	}
	if a.HTTPRequestID == "" {
		t.Error("minted anchor HTTPRequestID is empty")
	}
	if a.HTTPRequestID != rid {
		t.Errorf("anchor HTTPRequestID = %q, want synthesized rid %q", a.HTTPRequestID, rid)
	}
}
