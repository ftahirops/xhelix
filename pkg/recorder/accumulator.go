package recorder

import (
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Chain is one accumulated workflow instance: all deduped edges seen for a
// single (app_id, chain_id), with timing.
type Chain struct {
	AppID     string
	ChainID   string
	RootType  string
	Phase     string
	Edges     []Edge
	FirstSeen time.Time
	LastSeen  time.Time
}

type chainState struct {
	c    Chain
	keys map[string]struct{} // edgeID set, for dedup within the chain
}

// Accumulator folds learnable events into per-(app_id,chain_id) chains and
// flushes them after an idle gap. Safe for concurrent Observe/Flush (the
// pipeline hook calls Observe on the dispatch goroutine; a ticker calls
// FlushIdle on another).
type Accumulator struct {
	idle time.Duration
	mu   sync.Mutex
	m    map[string]*chainState // key: app_id + "\x00" + chain_id
}

func NewAccumulator(idle time.Duration) *Accumulator {
	return &Accumulator{idle: idle, m: make(map[string]*chainState)}
}

func (a *Accumulator) Observe(e model.Event) {
	chainID := e.Tags["chain_id"]
	if chainID == "" {
		return
	}
	edge, ok := EdgeFromEvent(e)
	if !ok {
		return
	}
	app := e.Tags["app_id"]
	key := app + "\x00" + chainID
	id := edgeID(edge)

	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.m[key]
	if st == nil {
		st = &chainState{
			c: Chain{
				AppID: app, ChainID: chainID,
				RootType: e.Tags["root_type"], Phase: e.Tags["phase"],
				FirstSeen: e.Time, LastSeen: e.Time,
			},
			keys: make(map[string]struct{}),
		}
		a.m[key] = st
	}
	if _, dup := st.keys[id]; !dup {
		st.keys[id] = struct{}{}
		st.c.Edges = append(st.c.Edges, edge)
	}
	if e.Time.After(st.c.LastSeen) {
		st.c.LastSeen = e.Time
	}
}

func (a *Accumulator) FlushIdle(now time.Time) []Chain {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Chain
	for k, st := range a.m {
		if now.Sub(st.c.LastSeen) >= a.idle {
			out = append(out, st.c)
			delete(a.m, k)
		}
	}
	return out
}

func (a *Accumulator) FlushAll() []Chain {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Chain, 0, len(a.m))
	for k, st := range a.m {
		out = append(out, st.c)
		delete(a.m, k)
	}
	return out
}
