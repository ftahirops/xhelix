// Package contractcompiler turns a declared App (from pkg/appregistry)
// plus the never-learnable red zones into a CompiledContract: a unified,
// per-service allow/deny policy.
//
// P5a scope (first cut):
//   - Compile is DECLARATION + RED ZONE driven. Fully deterministic,
//     zero false positives by construction — every output traces to
//     either the operator's declared services or the universal red-zone
//     floor (pkg/redzones).
//   - The only LIVE enforcement is per-app exec allowlisting via the
//     execguard policy hook (no restart). Seccomp + AppArmor profiles
//     are GENERATED and written to disk for review, but NOT armed —
//     arming them needs a service restart and is deferred to P5a.2.
//   - Baseline-driven refinement (widening allowlists from observed
//     behaviour) is the documented next step; it needs a baseline query
//     layer that does not exist yet, so it is not wired here.
package contractcompiler

import (
	"time"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/execguard"
	"github.com/xhelix/xhelix/pkg/prevent/apparmor"
	"github.com/xhelix/xhelix/pkg/prevent/seccomp"
)

// CompiledContract is the full compiled policy for one app.
type CompiledContract struct {
	App        string                      `json:"app"`
	Mode       appregistry.EnforcementMode `json:"mode"`
	CompiledAt time.Time                   `json:"compiled_at"`
	// Source records what fed the compile. "declaration" today;
	// "declaration+baseline" once baseline refinement lands.
	Source   string             `json:"source"`
	Services []CompiledService  `json:"services"`
	Warnings []string           `json:"warnings,omitempty"`
}

// CompiledService is the compiled policy for one service within an app.
type CompiledService struct {
	Unit        string `json:"unit"`
	Kind        string `json:"kind"`
	CgroupMatch string `json:"cgroup_match"`

	// ExecAllow is the set of binary paths permitted to exec inside this
	// service's cgroup when the app is in locked/sealed mode. Derived
	// from the declared service binaries (P5a). The execguard policy hook
	// denies any exec of a path NOT in this set, scoped to CgroupMatch.
	ExecAllow []string `json:"exec_allow"`
	// ExecDeny is the red-zone exec floor (always present, never weakened).
	ExecDeny []string `json:"exec_deny"`
	// DenySyscalls / WriteDeny are compiled but only ENFORCED once the
	// staged seccomp/AppArmor artifacts are armed (P5a.2). Shown in the UI
	// as "staged".
	DenySyscalls []string `json:"deny_syscalls"`
	WriteDeny    []string `json:"write_deny"`

	// Staged kernel artifacts — generated, written to disk, NOT armed.
	Seccomp  seccomp.Profile  `json:"-"`
	AppArmor apparmor.Profile `json:"-"`

	// SeccompText / AppArmorText are the human-readable renders surfaced
	// in the UI and written to /etc/xhelix/compiled/<app>/.
	SeccompText  string `json:"seccomp_text,omitempty"`
	AppArmorText string `json:"apparmor_text,omitempty"`

	// ExecguardRules are the fanotify deny rules for this service's
	// red-zone exec floor. These ARE installable at runtime (no restart)
	// but in P5a the live enforcement path is the cgroup-scoped policy
	// hook, not these global path rules.
	ExecguardRules []execguard.Rule `json:"-"`
}
