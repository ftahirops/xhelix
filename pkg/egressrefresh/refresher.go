package egressrefresh

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/xhelix/xhelix/pkg/egressresolve"
)

// Unit is one opted-in service to refresh.
type Unit struct {
	Name        string
	StaticCIDRs []string
	FQDNs       []string
}

// UnitSource yields the units to refresh on each pass.
type UnitSource interface {
	Units() []Unit
}

// Applier installs a computed allow-set for a unit. The shadow LogApplier
// is the default; the real systemd applier is a separate (deferred) slice.
type Applier interface {
	Apply(unit string, allowCIDRs []string) error
	// Commit is called once per RefreshOnce pass after all Apply calls, so
	// implementations can batch expensive operations (e.g. daemon-reload).
	Commit() error
}

// LogApplier logs the would-be allow-set and applies nothing (shadow mode).
type LogApplier struct{ Log *slog.Logger }

func (l LogApplier) Apply(unit string, allowCIDRs []string) error {
	lg := l.Log
	if lg == nil {
		lg = slog.Default()
	}
	lg.Info("egress refresh (shadow): would set allow-set",
		"unit", unit, "allow", allowCIDRs)
	return nil
}

func (l LogApplier) Commit() error { return nil }

// Refresher periodically recomputes each unit's egress allow-set.
type Refresher struct {
	src     UnitSource
	res     egressresolve.Resolver
	applier Applier
	grace   time.Duration
	tracker *Tracker
	lastSet map[string]string // unit -> last-applied joined set (change detection)
}

// New builds a Refresher.
func New(src UnitSource, res egressresolve.Resolver, applier Applier, grace time.Duration) *Refresher {
	return &Refresher{
		src: src, res: res, applier: applier, grace: grace,
		tracker: NewTracker(), lastSet: map[string]string{},
	}
}

// RefreshOnce performs one resolve+compute+apply pass. Resolution failures
// are tolerated: a failed FQDN is simply not observed, so its prior IPs
// persist in the grace window (never shrink on a transient failure).
func (r *Refresher) RefreshOnce(ctx context.Context, now time.Time) {
	for _, u := range r.src.Units() {
		for _, fqdn := range u.FQDNs {
			cidrs, err := egressresolve.ResolveCIDRs(ctx, r.res, []string{fqdn})
			if err != nil {
				continue // tolerate — grace window keeps prior IPs
			}
			r.tracker.Observe(u.Name, cidrs, now)
		}
		allow := append([]string(nil), u.StaticCIDRs...)
		allow = append(allow, r.tracker.WithinGrace(u.Name, now, r.grace)...)
		allow = dedupeSorted(allow)
		key := joinKey(allow)
		if r.lastSet[u.Name] == key {
			continue // unchanged — don't re-apply
		}
		if err := r.applier.Apply(u.Name, allow); err != nil {
			slog.Default().Warn("egress refresh apply failed", "unit", u.Name, "err", err)
			continue
		}
		r.lastSet[u.Name] = key
	}
	if err := r.applier.Commit(); err != nil {
		slog.Default().Warn("egress refresh commit failed", "err", err)
	}
}

// Start runs RefreshOnce on an interval until ctx is cancelled.
func (r *Refresher) Start(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	r.RefreshOnce(ctx, time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.RefreshOnce(ctx, now)
		}
	}
}

func dedupeSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func joinKey(sorted []string) string {
	key := ""
	for _, s := range sorted {
		key += s + ","
	}
	return key
}
