package recorder

import (
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func evChain(sensor, comm, chainID, app string, tags map[string]string, ts time.Time) model.Event {
	m := map[string]string{"chain_id": chainID, "app_id": app, "root_type": "web", "phase": "request"}
	for k, v := range tags {
		m[k] = v
	}
	return model.Event{Sensor: sensor, Comm: comm, Tags: m, Time: ts}
}

func TestAccumulator_GroupsAndDedupsByChain(t *testing.T) {
	a := NewAccumulator(30 * time.Second)
	t0 := time.Unix(1_700_000_000, 0)
	a.Observe(evChain("ebpf.spawn", "curl", "c1", "shop", nil, t0))
	a.Observe(evChain("net_connect", "", "c1", "shop", map[string]string{"sni": "api.stripe.com", "dst_port": "443"}, t0.Add(time.Second)))
	a.Observe(evChain("ebpf.spawn", "curl", "c1", "shop", nil, t0.Add(2*time.Second))) // dup exec edge

	got := a.FlushAll()
	if len(got) != 1 {
		t.Fatalf("want 1 chain, got %d", len(got))
	}
	if got[0].AppID != "shop" || got[0].ChainID != "c1" {
		t.Errorf("chain identity wrong: %+v", got[0])
	}
	if len(got[0].Edges) != 2 {
		t.Errorf("want 2 deduped edges (exec curl + egress), got %d: %+v", len(got[0].Edges), got[0].Edges)
	}
}

func TestAccumulator_FlushIdleOnlyExpired(t *testing.T) {
	a := NewAccumulator(30 * time.Second)
	t0 := time.Unix(1_700_000_000, 0)
	a.Observe(evChain("ebpf.spawn", "curl", "old", "shop", nil, t0))
	a.Observe(evChain("ebpf.spawn", "wget", "fresh", "shop", nil, t0.Add(40*time.Second)))

	flushed := a.FlushIdle(t0.Add(45 * time.Second)) // "old" idle 45s>30s; "fresh" idle 5s
	if len(flushed) != 1 || flushed[0].ChainID != "old" {
		t.Fatalf("want only 'old' flushed, got %+v", flushed)
	}
	// "fresh" still resident.
	if rest := a.FlushAll(); len(rest) != 1 || rest[0].ChainID != "fresh" {
		t.Fatalf("want 'fresh' still resident, got %+v", rest)
	}
}

func TestAccumulator_SkipsEmptyChainID(t *testing.T) {
	a := NewAccumulator(time.Second)
	a.Observe(model.Event{Sensor: "ebpf.spawn", Comm: "curl", Tags: map[string]string{"app_id": "shop"}}) // no chain_id
	if got := a.FlushAll(); len(got) != 0 {
		t.Errorf("event with no chain_id must be skipped, got %+v", got)
	}
}

func TestAccumulator_SkipsNonEdgeEvents(t *testing.T) {
	a := NewAccumulator(time.Second)
	a.Observe(evChain("heartbeat", "", "c1", "shop", nil, time.Unix(1, 0)))
	if got := a.FlushAll(); len(got) != 0 {
		t.Errorf("non-edge event must not create a chain, got %+v", got)
	}
}
