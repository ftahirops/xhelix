package longwindow

import (
	"log/slog"
	"sync"
	"time"
)

// Mode determines whether a threshold rule uses raw counts or
// distinct-value counts.
type Mode string

const (
	ModeCount         Mode = "count"
	ModeDistinctValue Mode = "distinct"
)

// Rule is a long-window threshold. Evaluated by Poller every Tick.
type Rule struct {
	ID        string        // unique rule id
	Tag       string        // event tag to count
	Mode      Mode          // count vs distinct
	Window    time.Duration // sliding window length
	Threshold int           // fire when count >= Threshold
	Severity  string        // emitted alert severity
	Desc      string        // human description
}

// Hit describes one threshold breach.
type Hit struct {
	Rule  Rule
	Group string
	Count int
	At    time.Time
}

// EmitFn is invoked for each new Hit. Caller wires to the alert bus.
type EmitFn func(Hit)

// Poller periodically evaluates a set of Rules against a Store and
// emits Hits via EmitFn. Suppresses repeat hits per (rule, group)
// within Cooldown to avoid alert storms when a threshold stays
// breached.
type Poller struct {
	Store    *Store
	Rules    []Rule
	Emit     EmitFn
	Tick     time.Duration // evaluation interval; default 1m
	Cooldown time.Duration // per (rule,group) emit suppression; default = Rule.Window
	Log      *slog.Logger

	mu          sync.Mutex
	lastEmitted map[string]time.Time // key = ruleID|group
}

// Run blocks until stop is closed. Spawn as a goroutine from the
// daemon.
func (p *Poller) Run(stop <-chan struct{}) {
	if p.Tick <= 0 {
		p.Tick = time.Minute
	}
	if p.lastEmitted == nil {
		p.lastEmitted = map[string]time.Time{}
	}
	t := time.NewTicker(p.Tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			p.evaluate(now)
		}
	}
}

// evaluate runs one pass over every rule.
func (p *Poller) evaluate(now time.Time) {
	for _, r := range p.Rules {
		groups, err := p.Store.Groups(r.Tag, r.Window, now)
		if err != nil {
			if p.Log != nil {
				p.Log.Warn("longwindow: groups query failed", "rule", r.ID, "err", err)
			}
			continue
		}
		for _, g := range groups {
			var n int
			switch r.Mode {
			case ModeDistinctValue:
				n, err = p.Store.DistinctCount(r.Tag, g, r.Window, now)
			default:
				n, err = p.Store.Count(r.Tag, g, r.Window, now)
			}
			if err != nil {
				if p.Log != nil {
					p.Log.Warn("longwindow: count failed", "rule", r.ID, "group", g, "err", err)
				}
				continue
			}
			if n < r.Threshold {
				continue
			}
			if p.suppressed(r, g, now) {
				continue
			}
			p.markEmitted(r, g, now)
			if p.Emit != nil {
				p.Emit(Hit{Rule: r, Group: g, Count: n, At: now})
			}
		}
	}
}

func (p *Poller) suppressed(r Rule, group string, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := r.ID + "|" + group
	cd := p.Cooldown
	if cd <= 0 {
		cd = r.Window
	}
	if last, ok := p.lastEmitted[key]; ok && now.Sub(last) < cd {
		return true
	}
	return false
}

func (p *Poller) markEmitted(r Rule, group string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastEmitted == nil {
		p.lastEmitted = map[string]time.Time{}
	}
	p.lastEmitted[r.ID+"|"+group] = now
}
