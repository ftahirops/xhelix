package contractcompiler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/redzones"
)

// ExecDecision is the verdict the execguard policy hook consults.
type ExecDecision int

const (
	// DecisionPass means "no compiled policy applies — fall through to
	// the global execguard rules" (the red-zone floor still applies).
	DecisionPass ExecDecision = iota
	// DecisionAllow means a locked/sealed app explicitly permits this exec.
	DecisionAllow
	// DecisionDeny means a locked/sealed app forbids this exec (path not
	// in the app's ExecAllow set).
	DecisionDeny
)

// Manager holds the live compiled contracts and answers the per-app
// exec decision used by the execguard policy hook. Safe for concurrent
// use. The compile inputs are the app registry + the red-zone policy;
// staged seccomp/AppArmor artifacts are written under ArtifactDir.
type Manager struct {
	policy      *redzones.Policy
	artifactDir string
	log         *slog.Logger

	mu       sync.RWMutex
	compiled map[string]*CompiledContract // by app name
	// shadowCount tallies would-blocks per app while in shadow mode.
	shadowCount map[string]uint64
}

// NewManager creates a compiler manager. artifactDir is where staged
// seccomp/AppArmor profiles are written (e.g. /etc/xhelix/compiled).
func NewManager(policy *redzones.Policy, artifactDir string, log *slog.Logger) *Manager {
	if policy == nil {
		policy = redzones.Default()
	}
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		policy:      policy,
		artifactDir: artifactDir,
		log:         log,
		compiled:    make(map[string]*CompiledContract),
		shadowCount: make(map[string]uint64),
	}
}

// Recompile compiles the given app and caches the result. When the app
// is in locked/sealed mode it also writes the staged artifacts to disk.
// Returns the compiled contract.
func (m *Manager) Recompile(app appregistry.App) *CompiledContract {
	cc := Compile(app, m.policy)
	m.mu.Lock()
	m.compiled[app.Name] = &cc
	m.shadowCount[app.Name] = 0
	m.mu.Unlock()

	if cc.Mode == appregistry.ModeLocked || cc.Mode == appregistry.ModeSealed {
		if err := m.writeArtifacts(&cc); err != nil {
			m.log.Warn("contractcompiler: write staged artifacts failed",
				"app", app.Name, "err", err)
		}
	}
	m.log.Info("contractcompiler: recompiled",
		"app", app.Name, "mode", string(cc.Mode),
		"services", len(cc.Services))
	return &cc
}

// RecompileAll compiles every app in the registry. Called at startup.
func (m *Manager) RecompileAll(apps []appregistry.App) {
	for _, a := range apps {
		m.Recompile(a)
	}
}

// Remove drops an app's compiled contract (on app delete).
func (m *Manager) Remove(appName string) {
	m.mu.Lock()
	delete(m.compiled, appName)
	delete(m.shadowCount, appName)
	m.mu.Unlock()
}

// Get returns the cached compiled contract for an app, or nil.
func (m *Manager) Get(appName string) *CompiledContract {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.compiled[appName]
}

// ExecDecisionFor is the hot path consulted by the execguard policy hook
// on every exec. It resolves the exec'ing process's cgroup to a compiled
// app contract and decides:
//
//   - locked/sealed: Allow if binaryPath ∈ ExecAllow, else Deny.
//   - shadow:        compute would-deny, log + tally, but return Pass
//                    (shadow never actually denies).
//   - observe/guarded or no match: Pass (global red-zone floor applies).
//
// Returns (DecisionPass, "") when no compiled contract claims this cgroup.
func (m *Manager) ExecDecisionFor(binaryPath, cgroupPath string) (ExecDecision, string) {
	if cgroupPath == "" {
		return DecisionPass, ""
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, cc := range m.compiled {
		switch cc.Mode {
		case appregistry.ModeLocked, appregistry.ModeSealed, appregistry.ModeShadow:
		default:
			continue
		}
		for _, svc := range cc.Services {
			if !cgroupCovers(cgroupPath, svc.CgroupMatch) {
				continue
			}
			allowed := contains(svc.ExecAllow, binaryPath)
			if cc.Mode == appregistry.ModeShadow {
				if !allowed {
					m.shadowCount[cc.App]++
					m.log.Warn("contractcompiler: shadow would-deny exec",
						"app", cc.App, "binary", binaryPath, "cgroup", cgroupPath)
				}
				return DecisionPass, ""
			}
			if allowed {
				return DecisionAllow, ""
			}
			return DecisionDeny, fmt.Sprintf("compiled-policy: undeclared exec (%s)", cc.App)
		}
	}
	return DecisionPass, ""
}

// ShadowCount returns the number of would-blocks tallied for an app while
// in shadow mode (resets on each Recompile).
func (m *Manager) ShadowCount(appName string) uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.shadowCount[appName]
}

// writeArtifacts persists the staged seccomp + AppArmor renders to
// ArtifactDir/<app>/. A STAGED marker file makes it explicit that these
// are NOT armed. Best-effort — never blocks compilation.
func (m *Manager) writeArtifacts(cc *CompiledContract) error {
	if m.artifactDir == "" {
		return nil
	}
	dir := filepath.Join(m.artifactDir, cc.App)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	marker := "# STAGED — NOT ENFORCED.\n" +
		"# These profiles are generated for review. Arming them requires a\n" +
		"# service restart and is deferred to P5a.2. They do nothing yet.\n" +
		fmt.Sprintf("# app=%s mode=%s compiled=%s\n",
			cc.App, cc.Mode, cc.CompiledAt.UTC().Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dir, "STAGED"), []byte(marker), 0o640); err != nil {
		return err
	}
	for _, svc := range cc.Services {
		base := sanitizeUnit(svc.Unit)
		if svc.SeccompText != "" {
			_ = os.WriteFile(filepath.Join(dir, base+".seccomp.txt"),
				[]byte(svc.SeccompText), 0o640)
		}
		if svc.AppArmorText != "" {
			_ = os.WriteFile(filepath.Join(dir, base+".apparmor"),
				[]byte(svc.AppArmorText), 0o640)
		}
	}
	// Machine-readable summary for tooling.
	if data, err := json.MarshalIndent(cc, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "contract.json"), data, 0o640)
	}
	return nil
}

// cgroupCovers reports whether cgroupPath equals prefix or is a child of
// it (slash-anchored — prevents /…/php-fpm matching /…/php-fpm-evil).
func cgroupCovers(cgroupPath, prefix string) bool {
	if prefix == "" {
		return false
	}
	if cgroupPath == prefix {
		return true
	}
	return strings.HasPrefix(cgroupPath, prefix+"/")
}

func sanitizeUnit(u string) string {
	u = strings.TrimSuffix(u, ".service")
	u = strings.ReplaceAll(u, "/", "_")
	if u == "" {
		return "service"
	}
	return u
}
