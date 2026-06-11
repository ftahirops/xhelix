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
	}
}

// Arm writes a unit drop-in for each service, loads AppArmor profiles
// (best-effort), and runs `systemctl daemon-reload`. It does NOT restart
// any service — enforcement applies on the next (re)start. Returns the
// per-service status with PendingRestart=true when anything was armed.
func (a *Armorer) Arm(app, mode string, svcs []ServiceSpec) (ArmResult, error) {
	res := ArmResult{App: app}
	wroteAny := false
	for _, svc := range svcs {
		st := ServiceStatus{Unit: svc.Unit}

		apparmorName := ""
		if a.Apparmor && svc.AppArmor != nil && svc.AppArmor.Body != "" {
			if installed, err := svc.AppArmor.Install(a.ApparmorDir, false); err == nil {
				apparmorName = installed.Name
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
			return res, fmt.Errorf("contractarm: mkdir %s: %w", dir, err)
		}
		path := filepath.Join(dir, DropInName(app))
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			return res, fmt.Errorf("contractarm: write %s: %w", path, err)
		}
		st.Armed = true
		st.DropInPath = path
		wroteAny = true
		res.Services = append(res.Services, st)
	}

	if wroteAny {
		if err := a.Runner("daemon-reload"); err != nil {
			return res, fmt.Errorf("contractarm: daemon-reload: %w", err)
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
		if err := a.Runner("try-restart", u); err != nil {
			return fmt.Errorf("contractarm: try-restart %s: %w", u, err)
		}
	}
	return nil
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

func (a *Armorer) dropInDir(unit string) string {
	base := a.SystemdDir
	if base == "" {
		base = "/etc/systemd/system"
	}
	return filepath.Join(base, unit+".d")
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
