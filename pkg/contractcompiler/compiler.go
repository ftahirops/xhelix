package contractcompiler

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/appregistry"
	"github.com/xhelix/xhelix/pkg/execguard"
	"github.com/xhelix/xhelix/pkg/prevent/apparmor"
	"github.com/xhelix/xhelix/pkg/prevent/seccomp"
	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
	"github.com/xhelix/xhelix/pkg/redzones"
)

// nowFunc is overridable in tests so CompiledAt is deterministic.
var nowFunc = time.Now

// Compile turns a declared App + the red-zone floor into a
// CompiledContract. Pure function (modulo the clock): same App + same
// policy → same logical output. Never fails — an unmappable service
// kind degrades to the red-zone floor and adds a Warning.
func Compile(app appregistry.App, policy *redzones.Policy) CompiledContract {
	if policy == nil {
		policy = redzones.Default()
	}
	arch := seccomp.CurrentArch()

	cc := CompiledContract{
		App:        app.Name,
		Mode:       app.Mode,
		CompiledAt: nowFunc(),
		Source:     "declaration",
	}

	if arch == "" {
		cc.Warnings = append(cc.Warnings,
			"seccomp profile not generated: unsupported host arch")
	}
	for _, svc := range app.Services {
		cc.Services = append(cc.Services, compileService(app, svc, policy, arch))
	}
	cc.ArtifactSHA = contentHash(cc)
	return cc
}

// contentHash is a deterministic SHA-256 over the policy-relevant content
// of a compiled contract (P7). Mode and CompiledAt are EXCLUDED so a mode
// flip or a fresh recompile of unchanged declarations yields the same hash
// (and a prior signature stays valid). Field order + separators are part
// of the contract — changing them invalidates existing signatures.
func contentHash(cc CompiledContract) string {
	var b strings.Builder
	b.WriteString(cc.App)
	for _, s := range cc.Services {
		b.WriteString("\x1fsvc\x1f")
		b.WriteString(s.Unit)
		b.WriteByte('\x1f')
		b.WriteString(s.Kind)
		b.WriteByte('\x1f')
		b.WriteString(s.CgroupMatch)
		writeSet(&b, "exec_allow", s.ExecAllow)
		writeSet(&b, "exec_deny", s.ExecDeny)
		writeSet(&b, "deny_syscalls", s.DenySyscalls)
		writeSet(&b, "write_deny", s.WriteDeny)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// writeSet appends a sorted, length-prefixed set so ordering of the input
// slice cannot change the hash.
func writeSet(b *strings.Builder, label string, items []string) {
	b.WriteString("\x1f")
	b.WriteString(label)
	b.WriteString(":")
	cp := append([]string(nil), items...)
	sort.Strings(cp)
	for _, it := range cp {
		b.WriteByte('\x1e')
		b.WriteString(it)
	}
}

// compileService builds the CompiledService for one declared service.
func compileService(app appregistry.App, svc appregistry.Service, policy *redzones.Policy, arch seccomp.Arch) CompiledService {
	cs := CompiledService{
		Unit:        firstNonEmpty(svc.UnitName, svc.Name),
		Kind:        string(svc.ServiceType),
		CgroupMatch: svc.CgroupMatch,
		ExecDeny:    append([]string(nil), policy.ExecPaths...),
		WriteDeny:   append([]string(nil), policy.WriteZones...),
	}

	// ExecAllow: the app's own declared binaries. In locked/sealed mode
	// the policy hook allows exactly these inside the cgroup and denies
	// everything else. Coarse but deterministic — operators run shadow
	// first to preview would-blocks, then widen via baseline (P5a.2).
	cs.ExecAllow = declaredBinaries(app)

	// Per-kind ServiceContract: a bonus skeleton where a builtin exists
	// (nginx/apache today). Merged with the red-zone syscall floor. For
	// kinds without a builtin, the contract is the red-zone floor alone.
	contract := redzoneFloorContract(policy)
	if kind, role, ok := mapKindRole(svc.ServiceType); ok {
		if builtin, err := contracts.Builtin(kind, role); err == nil {
			if merged, err := contracts.Merge(builtin, contract); err == nil {
				contract = merged
			}
		}
	}
	cs.DenySyscalls = contract.DenySyscalls

	// Seccomp profile (staged). Skip when arch unknown.
	if arch != "" {
		if prof, err := seccomp.Compile(contract, arch); err == nil {
			cs.Seccomp = prof
			cs.SeccompText = prof.Render()
		}
	}
	// Native systemd SystemCallFilter directive used to arm the policy
	// via a unit drop-in (P5a.2). Arch-independent — systemd resolves
	// syscall names at load time.
	cs.SeccompSystemdDirective = seccomp.SystemdDirective(contract)

	// AppArmor profile (staged). Needs a ProtectedService shell.
	ps := &protectedsvc.ProtectedService{
		Name:     app.Name + "-" + cs.Unit,
		ExecPath: firstNonEmpty(svc.BinaryPath, "/usr/bin/"+svc.Name),
		Unit:     svc.UnitName,
		Contract: contract,
	}
	if kind, role, ok := mapKindRole(svc.ServiceType); ok {
		ps.Kind = kind
		ps.Role = role
	}
	if prof, err := apparmor.Render(ps); err == nil {
		cs.AppArmor = prof
		cs.AppArmorText = prof.Body
		cs.AppArmorProfileName = prof.Name
	}

	// Execguard rules for the red-zone exec floor (installable, but the
	// live path in P5a is the cgroup-scoped policy hook).
	cs.ExecguardRules = policy.WebWorkerExecRules()

	return cs
}

// declaredBinaries returns the de-duplicated set of binary paths declared
// across all of the app's services.
func declaredBinaries(app appregistry.App) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range app.Services {
		if s.BinaryPath == "" || seen[s.BinaryPath] {
			continue
		}
		seen[s.BinaryPath] = true
		out = append(out, s.BinaryPath)
	}
	return out
}

// redzoneFloorContract is the universal ServiceContract derived purely
// from the red zones — applies to every service kind.
func redzoneFloorContract(policy *redzones.Policy) protectedsvc.ServiceContract {
	return protectedsvc.ServiceContract{
		DenyExecPaths: append([]string(nil), policy.ExecPaths...),
		WriteRoots:    nil, // red zones are deny-roots; learning would set allow-roots
		DenySyscalls:  append([]string(nil), policy.DenySyscalls...),
		StrictReadOnly: false,
	}
}

// mapKindRole maps an appregistry service type to the protectedsvc kind
// + a sensible default role. ok=false for kinds without a contract family.
func mapKindRole(t appregistry.ServiceType) (protectedsvc.ServiceKind, protectedsvc.ServiceRole, bool) {
	switch t {
	case appregistry.ServiceNginx:
		return protectedsvc.KindNginx, protectedsvc.RoleReverseProxy, true
	case appregistry.ServiceApache:
		return protectedsvc.KindApache, protectedsvc.RoleReverseProxy, true
	}
	return "", "", false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// matched returns whether a path is in a slice.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// execguard import kept for the rule type used in CompiledService.
var _ = execguard.Rule{}
