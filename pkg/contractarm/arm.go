package contractarm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/prevent/apparmor"
)

// ServiceSpec is the minimal per-service input the Armorer needs. The
// caller maps a compiled service into this shape — contractarm stays
// decoupled from contractcompiler.
type ServiceSpec struct {
	Unit             string
	SeccompDirective string            // "SystemCallFilter=~…" or ""
	AppArmor         *apparmor.Profile // nil = no AppArmor for this service
}

// ServiceStatus is the per-service arm result/state.
type ServiceStatus struct {
	Unit       string `json:"unit"`
	Armed      bool   `json:"armed"`
	DropInPath string `json:"drop_in_path,omitempty"`
	Seccomp    bool   `json:"seccomp"`
	AppArmor   bool   `json:"apparmor"`
	Warning    string `json:"warning,omitempty"`
}

// ArmResult is returned by Arm/Disarm.
type ArmResult struct {
	App            string          `json:"app"`
	Services       []ServiceStatus `json:"services"`
	PendingRestart bool            `json:"pending_restart"`
}

// Armorer installs/removes systemd unit drop-ins to arm or disarm a
// compiled contract. All systemd interaction goes through Runner so the
// flow is unit-testable and the destructive op is isolated.
type Armorer struct {
	SystemdDir  string                   // default /etc/systemd/system
	ApparmorDir string                   // default apparmor.DefaultProfileDir
	Apparmor    bool                     // attempt AppArmor arming
	Runner      func(args ...string) error
	Now         func() time.Time
	// SettleDelay is how long to wait between is-active polls after a
	// restart before declaring a service failed. Default 1s; set 0 in tests.
	SettleDelay time.Duration
	// SettleTries is how many times is-active is polled. Default 3.
	SettleTries int
	// sleep is injectable so tests don't actually wait. Defaults to time.Sleep.
	sleep func(time.Duration)
}

// New returns an Armorer with production defaults. AppArmor arming is
// enabled only when the host actually supports it.
func New() *Armorer {
	return &Armorer{
		SystemdDir:  "/etc/systemd/system",
		ApparmorDir: apparmor.DefaultProfileDir,
		Apparmor:    apparmor.Available(),
		Runner:      defaultRunner,
		Now:         time.Now,
		SettleDelay: time.Second,
		SettleTries: 3,
	}
}

// Arm writes a unit drop-in for each service, loads AppArmor profiles
// (best-effort), and runs `systemctl daemon-reload`. It does NOT restart
// any service — enforcement applies on the next (re)start. Returns the
// per-service status with PendingRestart=true when anything was armed.
// Arm is transactional: if any write fails mid-loop, every drop-in
// written in THIS call is removed (and loaded AppArmor profiles unloaded)
// before the error is returned, so a partial failure never leaves the
// system in a split state (files present, systemd unaware).
func (a *Armorer) Arm(app, mode string, svcs []ServiceSpec) (ArmResult, error) {
	res := ArmResult{App: app}
	var written []string          // drop-in paths written this call
	var loadedAA []string         // apparmor profile names loaded this call

	rollback := func() {
		for _, p := range written {
			_ = os.Remove(p)
		}
		for _, name := range loadedAA {
			_ = apparmor.Unload(a.ApparmorDir, name)
		}
		if len(written) > 0 {
			_ = a.Runner("daemon-reload") // best-effort resync after cleanup
		}
	}

	for _, svc := range svcs {
		st := ServiceStatus{Unit: svc.Unit}

		apparmorName := ""
		if a.Apparmor && svc.AppArmor != nil && svc.AppArmor.Body != "" {
			if installed, err := svc.AppArmor.Install(a.ApparmorDir, false); err == nil {
				apparmorName = installed.Name
				loadedAA = append(loadedAA, installed.Name)
				st.AppArmor = true
			} else {
				st.Warning = "apparmor load failed: " + err.Error()
			}
		}

		text := RenderDropIn(app, mode, svc.Unit, svc.SeccompDirective, apparmorName, a.now())
		if text == "" {
			// Nothing to enforce for this service.
			res.Services = append(res.Services, st)
			continue
		}
		st.Seccomp = svc.SeccompDirective != ""

		dir := a.dropInDir(svc.Unit)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			rollback()
			return ArmResult{App: app}, fmt.Errorf("contractarm: mkdir %s: %w (rolled back)", dir, err)
		}
		path := filepath.Join(dir, DropInName(app))
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			rollback()
			return ArmResult{App: app}, fmt.Errorf("contractarm: write %s: %w (rolled back)", path, err)
		}
		written = append(written, path)
		st.Armed = true
		st.DropInPath = path
		res.Services = append(res.Services, st)
	}

	if len(written) > 0 {
		if err := a.Runner("daemon-reload"); err != nil {
			rollback()
			return ArmResult{App: app}, fmt.Errorf("contractarm: daemon-reload: %w (rolled back)", err)
		}
		res.PendingRestart = true
	}
	return res, nil
}

// Disarm removes the drop-in for each unit, unloads AppArmor profiles,
// and runs daemon-reload. Enforcement fully clears on the next restart;
// removing the drop-in means a future start is unconstrained.
func (a *Armorer) Disarm(app string, svcs []ServiceSpec) (ArmResult, error) {
	res := ArmResult{App: app}
	changed := false
	for _, svc := range svcs {
		st := ServiceStatus{Unit: svc.Unit}
		path := filepath.Join(a.dropInDir(svc.Unit), DropInName(app))
		if err := os.Remove(path); err == nil {
			changed = true
		} else if !os.IsNotExist(err) {
			st.Warning = "remove drop-in: " + err.Error()
		}
		if a.Apparmor && svc.AppArmor != nil && svc.AppArmor.Name != "" {
			_ = apparmor.Unload(a.ApparmorDir, svc.AppArmor.Name)
		}
		res.Services = append(res.Services, st)
	}
	if changed {
		if err := a.Runner("daemon-reload"); err != nil {
			return res, fmt.Errorf("contractarm: daemon-reload: %w", err)
		}
		res.PendingRestart = true // a running service still has the old filter until restart
	}
	return res, nil
}

// Restart issues `systemctl try-restart` for each unit — the disruptive
// step that makes an armed (or disarmed) policy take effect on the live
// process. try-restart only restarts units that are currently running.
func (a *Armorer) Restart(units []string) error {
	for _, u := range units {
		// "--" terminates option parsing so a unit name can never be
		// interpreted as a systemctl flag (registry validation already
		// forbids a leading dash; this is defense in depth).
		if err := a.Runner("try-restart", "--", safeUnit(u)); err != nil {
			return fmt.Errorf("contractarm: try-restart %s: %w", u, err)
		}
	}
	return nil
}

// DisarmUnits removes the xhelix drop-in for each of the named units of
// an app and runs daemon-reload if anything changed. Used by the
// reconciler to clean up orphaned arms (deleted/downgraded apps) where
// only the unit names are known, not the full ServiceSpecs.
func (a *Armorer) DisarmUnits(app string, units []string) (int, error) {
	removed := 0
	for _, u := range units {
		path := filepath.Join(a.dropInDir(u), DropInName(app))
		if err := os.Remove(path); err == nil {
			removed++
		} else if !os.IsNotExist(err) {
			return removed, fmt.Errorf("contractarm: remove %s: %w", path, err)
		}
	}
	if removed > 0 {
		if err := a.Runner("daemon-reload"); err != nil {
			return removed, fmt.Errorf("contractarm: daemon-reload: %w", err)
		}
	}
	return removed, nil
}

// RolledBack names a unit whose arm was auto-reverted after it failed to
// come back active post-restart, with the failure detail.
type RolledBack struct {
	Unit   string `json:"unit"`
	Reason string `json:"reason"`
}

// RestartAndVerify restarts each unit, then verifies it became active.
// Any unit that does NOT return to active is treated as bricked-by-policy:
// its drop-in is removed, systemd reloaded, and the unit restarted again
// UNCONSTRAINED so availability is restored. The auto-rollback fires ONLY
// on this unambiguous availability failure — never on deny volume, which
// is attacker-controllable.
//
// Returns the list of units that were rolled back (empty = all healthy).
func (a *Armorer) RestartAndVerify(app string, units []string) ([]RolledBack, error) {
	for _, u := range units {
		if err := a.Runner("try-restart", "--", safeUnit(u)); err != nil {
			return nil, fmt.Errorf("contractarm: try-restart %s: %w", u, err)
		}
	}
	var rolled []RolledBack
	for _, u := range units {
		if a.isActive(u) {
			continue
		}
		// Bricked by the armed policy — revert this unit and restore it.
		if err := a.disarmUnit(app, u); err != nil {
			rolled = append(rolled, RolledBack{Unit: u,
				Reason: "failed to start after arm AND auto-rollback failed: " + err.Error()})
			continue
		}
		_ = a.Runner("daemon-reload")
		_ = a.Runner("try-restart", "--", safeUnit(u))
		rolled = append(rolled, RolledBack{Unit: u,
			Reason: "failed to become active after arm; drop-in removed and unit restored unconstrained"})
	}
	return rolled, nil
}

// isActive polls `systemctl is-active <unit>` up to SettleTries times,
// giving a slow-starting service time to come up. Returns true if the
// unit is active on any poll. The Runner returns nil exactly when
// is-active exits 0 (active).
func (a *Armorer) isActive(unit string) bool {
	tries := a.SettleTries
	if tries <= 0 {
		tries = 1
	}
	for i := 0; i < tries; i++ {
		if a.Runner("is-active", "--", safeUnit(unit)) == nil {
			return true
		}
		if i < tries-1 {
			a.napOnce()
		}
	}
	return false
}

func (a *Armorer) napOnce() {
	if a.SettleDelay <= 0 {
		return
	}
	if a.sleep != nil {
		a.sleep(a.SettleDelay)
		return
	}
	time.Sleep(a.SettleDelay)
}

// disarmUnit removes the xhelix drop-in for one (app, unit) pair.
func (a *Armorer) disarmUnit(app, unit string) error {
	path := filepath.Join(a.dropInDir(unit), DropInName(app))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ScanArmed walks SystemdDir for xhelix-managed drop-ins and returns a
// map of app name → units currently armed on disk. Used by the reconciler
// to find orphaned arms (e.g. for deleted or downgraded apps) without
// needing the original declaration. Drop-ins are named
// <SystemdDir>/<unit>.d/50-xhelix-<app>.conf.
func (a *Armorer) ScanArmed() (map[string][]string, error) {
	base := a.SystemdDir
	if base == "" {
		base = "/etc/systemd/system"
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string][]string{}, nil
		}
		return nil, err
	}
	out := map[string][]string{}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasSuffix(e.Name(), ".d") {
			continue
		}
		unit := strings.TrimSuffix(e.Name(), ".d")
		dropIns, err := os.ReadDir(filepath.Join(base, e.Name()))
		if err != nil {
			continue
		}
		for _, d := range dropIns {
			app, ok := appFromDropIn(d.Name())
			if !ok {
				continue
			}
			out[app] = append(out[app], unit)
		}
	}
	return out, nil
}

// appFromDropIn extracts the app name from "50-xhelix-<app>.conf".
func appFromDropIn(filename string) (string, bool) {
	const prefix, suffix = "50-xhelix-", ".conf"
	if !strings.HasPrefix(filename, prefix) || !strings.HasSuffix(filename, suffix) {
		return "", false
	}
	app := filename[len(prefix) : len(filename)-len(suffix)]
	if app == "" {
		return "", false
	}
	return app, true
}

// Status reports whether each unit currently carries an xhelix drop-in.
func (a *Armorer) Status(app string, units []string) []ServiceStatus {
	out := make([]ServiceStatus, 0, len(units))
	for _, u := range units {
		st := ServiceStatus{Unit: u}
		path := filepath.Join(a.dropInDir(u), DropInName(app))
		if data, err := os.ReadFile(path); err == nil {
			st.Armed = true
			st.DropInPath = path
			st.Seccomp = strings.Contains(string(data), "SystemCallFilter=")
			st.AppArmor = strings.Contains(string(data), "AppArmorProfile=")
		}
		out = append(out, st)
	}
	return out
}

// dropInDir returns /etc/systemd/system/<unit>.d. The unit name is
// reduced to its base component so a traversal value like
// "../../etc/cron.d/x" can never escape the systemd dir, even though the
// registry already validates unit names — defense in depth for a write
// performed as root.
func (a *Armorer) dropInDir(unit string) string {
	base := a.SystemdDir
	if base == "" {
		base = "/etc/systemd/system"
	}
	return filepath.Join(base, safeUnit(unit)+".d")
}

// safeUnit strips any path component and rejects traversal tokens.
func safeUnit(unit string) string {
	unit = filepath.Base(unit)
	if unit == "" || unit == "." || unit == ".." ||
		unit == string(filepath.Separator) || unit[0] == '-' {
		return "invalid-unit"
	}
	return unit
}

func (a *Armorer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func defaultRunner(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w (%s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
