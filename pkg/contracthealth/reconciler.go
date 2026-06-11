package contracthealth

import (
	"context"
	"log/slog"
	"sort"
	"time"
)

// AppDesired describes one app's intended enforcement state, as derived
// from the registry mode + the compiled contract's units.
type AppDesired struct {
	App       string
	ShouldArm bool     // true when mode is locked or sealed
	Units     []string // units the compiled contract would arm
}

// AppUnit is an (app, unit) pair in a reconcile report.
type AppUnit struct {
	App  string `json:"app"`
	Unit string `json:"unit"`
}

// ReconcileReport is the outcome of one reconcile pass.
type ReconcileReport struct {
	At              time.Time `json:"at"`
	OrphansDisarmed []AppUnit `json:"orphans_disarmed"` // armed but shouldn't be (deleted/downgraded)
	MissingArm      []AppUnit `json:"missing_arm"`      // should be armed but isn't (drift; alert only)
	Errors          []string  `json:"errors,omitempty"`
}

// Changed reports whether the pass found anything worth surfacing.
func (r ReconcileReport) Changed() bool {
	return len(r.OrphansDisarmed) > 0 || len(r.MissingArm) > 0 || len(r.Errors) > 0
}

// Reconciler converges on-disk armed drop-ins with declared intent. It
// auto-disarms orphans (apps that were deleted or downgraded out of
// locked/sealed) and ALERTS on drift (an app that should be armed but
// isn't, or out-of-band drop-in removal). It never auto-ARMS — arming is
// operator-initiated because it requires a restart to take effect.
type Reconciler struct {
	desired   func() []AppDesired
	scanArmed func() (map[string][]string, error)
	disarm    func(app string, units []string) (int, error)
	onReport  func(ReconcileReport)
	log       *slog.Logger
	now       func() time.Time
}

// NewReconciler wires the reconciler. desired returns intended state;
// scanArmed reports on-disk armed (app→units); disarm removes drop-ins;
// onReport is called after each pass that Changed() (may be nil).
func NewReconciler(
	desired func() []AppDesired,
	scanArmed func() (map[string][]string, error),
	disarm func(app string, units []string) (int, error),
	onReport func(ReconcileReport),
	log *slog.Logger,
) *Reconciler {
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{
		desired:   desired,
		scanArmed: scanArmed,
		disarm:    disarm,
		onReport:  onReport,
		log:       log,
		now:       time.Now,
	}
}

// ReconcileOnce runs a single pass and returns the report.
func (r *Reconciler) ReconcileOnce() ReconcileReport {
	rep := ReconcileReport{At: r.now()}

	desired := r.desired()
	desiredByApp := make(map[string]AppDesired, len(desired))
	for _, d := range desired {
		desiredByApp[d.App] = d
	}

	armed, err := r.scanArmed()
	if err != nil {
		rep.Errors = append(rep.Errors, "scan armed: "+err.Error())
		r.emit(rep)
		return rep
	}

	// 1. Orphans: armed on disk but not desired-armed.
	for app, units := range armed {
		d, known := desiredByApp[app]
		if known && d.ShouldArm {
			continue // legitimately armed
		}
		// Either the app is gone (deleted) or no longer locked/sealed
		// (downgraded). Disarm every armed unit for it.
		sort.Strings(units)
		n, derr := r.disarm(app, units)
		if derr != nil {
			rep.Errors = append(rep.Errors, "disarm "+app+": "+derr.Error())
			continue
		}
		if n > 0 {
			reason := "deleted"
			if known {
				reason = "downgraded"
			}
			r.log.Warn("contracthealth: reconciler disarmed orphan",
				"app", app, "units", units, "reason", reason)
			for _, u := range units {
				rep.OrphansDisarmed = append(rep.OrphansDisarmed, AppUnit{App: app, Unit: u})
			}
		}
	}

	// 2. Drift: desired-armed but not present on disk (alert only).
	for _, d := range desired {
		if !d.ShouldArm {
			continue
		}
		have := armed[d.App]
		for _, u := range d.Units {
			if !contains(have, u) {
				rep.MissingArm = append(rep.MissingArm, AppUnit{App: d.App, Unit: u})
			}
		}
	}

	r.emit(rep)
	return rep
}

// Run reconciles every interval until ctx is cancelled. Runs once
// immediately so a freshly-started daemon converges without waiting.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	r.ReconcileOnce()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.ReconcileOnce()
		}
	}
}

func (r *Reconciler) emit(rep ReconcileReport) {
	if rep.Changed() && r.onReport != nil {
		r.onReport(rep)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
