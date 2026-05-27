package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/xhelix/xhelix/pkg/config"
	"github.com/xhelix/xhelix/pkg/containment"
	"github.com/xhelix/xhelix/pkg/endpointscore"
)

// buildContainmentPolicy maps the YAML config into a containment.Policy.
// Missing fields fall back to DefaultPolicy values; max_step parses
// case-insensitively and falls back to "alert" (observe-only) on
// unknown values.
func buildContainmentPolicy(c config.ContainmentConfig) containment.Policy {
	p := containment.DefaultPolicy()
	if c.MinAlert > 0 {
		p.MinAlert = c.MinAlert
	}
	if c.MinThrottle > 0 {
		p.MinThrottle = c.MinThrottle
	}
	if c.MinBlockNet > 0 {
		p.MinBlockNet = c.MinBlockNet
	}
	if c.MinKillProc > 0 {
		p.MinKillProc = c.MinKillProc
	}
	if c.MinQuarantineFile > 0 {
		p.MinQuarantineFile = c.MinQuarantineFile
	}
	if c.MinQuarantineDir > 0 {
		p.MinQuarantineDir = c.MinQuarantineDir
	}
	if c.MinHostIsolate > 0 {
		p.MinHostIsolate = c.MinHostIsolate
	}
	if c.MinPanicSwitch > 0 {
		p.MinPanicSwitch = c.MinPanicSwitch
	}
	if c.MaxStep != "" {
		if step, ok := containment.ParseStep(c.MaxStep); ok {
			p.MaxStep = step
		}
	}
	return p
}

// runContainmentEvaluator periodically pulls the endpoint score from
// the incidentgraph's per-source TTP tracker and hands it to the
// ladder. Suppression + escalation semantics live in the Ladder
// itself; this loop is intentionally thin.
func runContainmentEvaluator(
	ctx context.Context,
	ladder *containment.Ladder,
	fc *foundationContext,
	interval time.Duration,
	log *slog.Logger,
) {
	if ladder == nil || fc == nil {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if fc.IncidentGraph == nil {
				continue
			}
			tracker := fc.IncidentGraph.SourceScoreTracker()
			if tracker == nil {
				continue
			}
			engine := endpointscore.NewEngine(tracker, nil)
			es := engine.Evaluate(now)
			if es.Score == 0 {
				continue
			}
			step, err := ladder.Handle(containment.Verdict{
				Score:    es.Score,
				Chain:    es.Chain,
				SourceID: "endpoint", // host-wide rollup; not per-source
				At:       now,
			})
			if err != nil && log != nil {
				log.Warn("containment.ladder action failed",
					"step", step.String(), "err", err)
			}
		}
	}
}
