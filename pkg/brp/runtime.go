package brp

import (
	"fmt"
	"strings"
)

// Decision is the runtime tier verdict on a single event.
//
// The four-tier model from the BRP architecture doc:
//
//   Tier 1 — DecisionHardDeny: immediate block + freeze + alert.
//             Hard invariant breach (always-suspicious action, role-invariant
//             violation, attributed protected-path exec). Class=1 alert.
//
//   Tier 2 — DecisionVerify: known-sensitive deviation that MUST enter
//             the verification engine (pkg/verify / T07). The runtime
//             tags the event but does NOT decide finality — the verifier
//             scores the event against 8 domains (path, lineage, integrity,
//             cross-app, behavior history, network novelty, hash baseline,
//             phase) and produces a final BENIGN / SUSPICIOUS / PROMOTE
//             outcome. Class=3 alert when surfaced.
//
//   Tier 3 — DecisionAllow: silently pass (cheapest path). Profile matched
//             and action is inside the envelope.
//
//   N/A   — DecisionUnknown: no profile matched, so there IS no envelope.
//             This is distinct from Verify: Unknown means "we have no
//             baseline to compare against", Verify means "we have a
//             baseline and this deviated from it." Operators triage these
//             differently — Unknown is for AppIdent + profile coverage
//             work, Verify is for verifier triage.
type Decision uint8

const (
	DecisionUnknown  Decision = iota // no profile match → no envelope; informational only
	DecisionAllow                     // Tier 3 — profile matched + inside envelope
	DecisionVerify                    // Tier 2 — profile matched + deviation; routes to verifier
	DecisionHardDeny                  // Tier 1 — hard invariant breach; immediate alert
)

// String returns the canonical short token used in event tags and logs.
func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionVerify:
		return "verify"
	case DecisionHardDeny:
		return "hard_deny"
	case DecisionUnknown:
		return "unknown"
	}
	return "invalid"
}

// TrustedSystemWriters is the set of process comms that legitimately
// write to ProtectedSystemPaths as part of normal system administration
// (package install/upgrade, service unit registration, kernel updates).
//
// When an event's actor comm matches this set, the protected-paths
// invariant does NOT fire — instead the decision falls through to the
// normal envelope check. The list is intentionally narrow: only the
// well-known administrative writers shipped by major distros.
//
// Rationale per entry:
//
//	snapd, snap-update-ns        — Canonical snap package mgr writes
//	                                /etc/systemd/system/snap-*.mount units
//	dpkg, apt, apt-get, dpkg-divert — Debian package operations
//	rpm, dnf, yum, microdnf      — RH-family package operations
//	systemctl, systemd-tmpfiles  — service registration / tmpfs setup
//	update-rc.d, update-alternatives — Debian helper scripts
//	depmod                        — kernel-module index regen
//	ldconfig                      — dynamic-linker cache regen
var TrustedSystemWriters = map[string]bool{
	"snapd":                true,
	"snap-update-ns":       true,
	"snap":                 true,
	"snap-confine":         true,
	"dpkg":                 true,
	"dpkg-divert":          true,
	"dpkg-deb":             true,
	"apt":                  true,
	"apt-get":              true,
	"apt-config":           true,
	"unattended-upgrade":   true,
	"unattended-upgr":      true, // truncated comm (TASK_COMM_LEN=16)
	"rpm":                  true,
	"dnf":                  true,
	"yum":                  true,
	"microdnf":             true,
	"systemctl":            true,
	"systemd-tmpfiles":     true,
	"systemd-sysctl":       true,
	"update-rc.d":          true,
	"update-alternatives":  true,
	"depmod":               true,
	"ldconfig":             true,
	"ldconfig.real":        true,
	"updatedb":             true,
	"update-grub":          true,
	"update-initramfs":     true,
	"mkinitramfs":          true,
}

// EventFacts is the subset of an event's identity that the BRP runtime
// evaluates. It is deliberately decoupled from pkg/model.Event so this
// package doesn't depend on the rest of the pipeline — keeps tests fast
// and makes the runtime reusable.
//
// Action is one of:
//
//	"process_spawn"        — a new process started
//	"exec"                 — execve into a different image
//	"file_open"            — file opened for read/write/exec
//	"file_write"           — file write/create/truncate
//	"net_connect"          — outbound network connection
//	"net_listen"           — bind+listen on a port
//	"ptrace_attach"        — ptrace attached to another process
//	"memfd_exec"           — execveat on a memfd handle
//	"process_vm_writev"    — cross-process memory write
//	"unshare"              — namespace creation
//	"setuid"               — uid transition
type EventFacts struct {
	PID     uint32
	Comm    string // actor's comm (TASK_COMM_LEN=16). Used by trusted-writer allowlist.
	ExePath string // actor's executable path (from /proc/<pid>/exe or ev.Image). Required
	// for the trusted-writer check — comm alone is spoofable via prctl(PR_SET_NAME)
	// or argv[0] manipulation. The check requires (Comm in allowlist) AND
	// (ExePath under a known system binary directory).
	Action      string
	Path        string // for file ops + exec
	Mode        string // "read" / "write" / "create" / "exec" / "append"
	DestHost    string // for net_connect — "host:port" or "host"
	DestPort    uint16 // for net_connect / net_listen
	DestSocket  string // for net_connect to unix socket
	TargetImage string // for exec — the binary being execved
	Role        string // the actor's resolved role (passed in by caller)

	// Trust populates corroborating signals beyond Comm+ExePath. When the
	// target is a protected path, the trusted-writer bypass requires
	// MULTIPLE signals to corroborate, not just the comm allowlist.
	Trust TrustSignals
}

// trustedExePrefixes lists the directories under which a system-binary
// must live for the TrustedSystemWriters comm allowlist to apply.
// Required because an attacker can trivially set a process's comm to
// "dpkg" via prctl(PR_SET_NAME) but cannot easily move their binary
// under /usr/sbin or /snap.
var trustedExePrefixes = []string{
	"/usr/bin/",
	"/usr/sbin/",
	"/bin/",
	"/sbin/",
	"/usr/lib/",          // dpkg-divert lives here
	"/usr/libexec/",      // helper scripts
	"/snap/snapd/",       // canonical snap mgr
	"/snap/core/",        // snap core helpers
	"/lib/systemd/",      // systemd binaries
	"/usr/lib/systemd/",  // systemd binaries
	"/lib/apt/",          // apt helpers
	"/usr/lib/apt/",      // apt helpers
}

// trustScore counts corroborating signals that the actor is a real
// administrative writer rather than a comm-spoofing impostor. Used by
// isTrustedSystemWriterMulti.
//
// Signals (each adds 1):
//
//	S1: Comm in TrustedSystemWriters
//	S2: ExePath under trustedExePrefixes
//	S3: pkg/integrity verdict says Authentic (real package transaction)
//	S4: Parent actor was trusted (helper scripts that change their own comm)
//	S5: CGroupRole == "system" (process is in a system-scope cgroup)
//
// Score interpretation:
//
//	0   — not trusted (probably suspicious)
//	1   — weakly trusted (one signal; was the old behavior)
//	2-3 — moderately trusted (current default threshold)
//	4-5 — strongly trusted (verifier engine can use to auto-allow)
func trustScore(comm, exePath string, ts TrustSignals) int {
	n := 0
	if TrustedSystemWriters[comm] {
		n++
	}
	if exePath != "" {
		for _, p := range trustedExePrefixes {
			if strings.HasPrefix(exePath, p) {
				n++
				break
			}
		}
	}
	if ts.IntegrityAuthentic {
		n++
	}
	if ts.ParentTrusted {
		n++
	}
	if ts.CGroupRole == "system" {
		n++
	}
	return n
}

// MinTrustScoreForBypass is the score required to bypass the
// protected-path check via TrustedSystemWriters. Default 2 (comm + exe).
// Higher values are stricter; lower values weaken trust.
//
// The default of 2 reflects: comm-allowlist match alone is too weak
// (spoofable), but requiring all 5 signals would block legitimate
// distros that don't surface every signal yet (e.g. integrity tester
// isn't wired in some configs).
const MinTrustScoreForBypass = 2

// isTrustedSystemWriterMulti returns true when the multi-signal trust
// score meets the bypass threshold. Replaces the old comm+exe boolean
// gate.
func isTrustedSystemWriterMulti(comm, exePath string, ts TrustSignals) bool {
	return trustScore(comm, exePath, ts) >= MinTrustScoreForBypass
}

// isTrustedSystemWriter is preserved for callers that don't have
// TrustSignals available (tests, the old comm+exe surface). It delegates
// to the multi-signal version with zero TrustSignals.
func isTrustedSystemWriter(comm, exePath string) bool {
	return isTrustedSystemWriterMulti(comm, exePath, TrustSignals{})
}

// TrustSignals carries the multi-source corroborating evidence a Runtime
// needs to make high-confidence trust decisions about a writer. It is
// distinct from EventFacts so the pipeline can populate it once per
// event and the Runtime does not depend on package layout.
//
// Wiring guide:
//
//	IntegrityAuthentic — set true when pkg/integrity.Tester.Verify returns
//	                     Authentic for the (writerPID, path, sha). Strong
//	                     positive signal that the write is part of a real
//	                     package-manager transaction.
//	ParentTrusted      — set true when the actor's parent comm is in
//	                     TrustedSystemWriters. Useful for helper scripts
//	                     spawned by dpkg/apt that change their own comm.
//	CGroupRole         — "system" / "user" / "app" / "" — used to gate
//	                     the trusted-writer bypass to system-managed
//	                     processes only.
//
// At least 2 of the 3 signals must corroborate the comm+exe pair for
// the trusted-writer bypass to apply when the target is a protected
// path. This is the upgrade from the single-signal Comm allowlist.
type TrustSignals struct {
	IntegrityAuthentic bool
	ParentTrusted      bool
	CGroupRole         string
}

// Runtime evaluates EventFacts against a resolved BRP MatchResult and
// returns a Decision + reason. Stateless — safe for concurrent use.
type Runtime struct {
	inv Invariants
}

// Invariants are the forever-suspicious patterns that bypass any
// profile — they always hard-deny regardless of what a profile says is
// allowed. These come from the v2 verification + BRP architecture docs.
//
// AlwaysSuspicious is the "memory-attack" set: ptrace, memfd_exec,
// process_vm_writev. No legitimate production app does these. Even
// debuggers should be running under an explicit operator session that
// has the right anchor lineage, which the verification engine handles.
//
// DeniedExecsByRole encodes the v2 hard-deny invariants like
// "web roles must never spawn /bin/sh".
type Invariants struct {
	AlwaysSuspicious  []string
	DeniedExecsByRole map[string][]string
}

// DefaultInvariants returns the v2 canonical hard-deny invariant set.
// Operators can extend via /etc/xhelix/brp/invariants.yaml (T09).
func DefaultInvariants() Invariants {
	webDenied := []string{"/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash",
		"/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/ruby",
		"/usr/bin/nc", "/usr/bin/ncat", "/bin/nc"}
	return Invariants{
		AlwaysSuspicious: []string{
			"ptrace_attach", "memfd_exec", "process_vm_writev",
		},
		DeniedExecsByRole: map[string][]string{
			// Web-serving roles must never exec a shell or interpreter.
			"nginx-static":        webDenied,
			"nginx-reverse-proxy": webDenied,
			"nginx-fastcgi":       webDenied,
			"nginx-lua":           webDenied,
			"nginx-njs":           webDenied,
			"nginx-grpc-proxy":    webDenied,
			"apache-static":       webDenied,
			"apache-reverse-proxy": webDenied,
			"apache-cgi":          webDenied,
			"apache-fastcgi":      webDenied,
			"apache-wsgi":         webDenied,
			// DB roles must never exec a shell or interpreter.
			"mysql-default": webDenied,
			"mysql-primary": webDenied,
			"mysql-replica": webDenied,
			"mysql-galera":  webDenied,
		},
	}
}

// NewRuntime returns a Runtime with the given invariants. inv with zero
// values means no invariants — every event needs full profile evaluation.
func NewRuntime(inv Invariants) *Runtime {
	return &Runtime{inv: inv}
}

// Evaluate decides the tier for facts given a MatchResult.
//
// Decision precedence (most-deny-first):
//
//  1. Always-suspicious action (ptrace, memfd_exec, process_vm_writev) → HardDeny
//  2. Write/exec to a protected path → HardDeny
//  3. Role-invariant violation (web role + shell exec) → HardDeny
//  4. No profile match (Unprofiled confidence) → Unknown
//  5. Profile match + action is outside envelope → Verify
//  6. Profile match + action is inside envelope → Allow
func (r *Runtime) Evaluate(m MatchResult, f EventFacts) (Decision, string) {
	// (1) Forever-suspicious actions.
	for _, a := range r.inv.AlwaysSuspicious {
		if f.Action == a {
			return DecisionHardDeny, "always-suspicious action: " + f.Action
		}
	}

	// (1.5) Metadata-service access by a role with no declared cloud
	// usage. IMDS endpoints have no legitimate use outside cloud-aware
	// roles. Audited + promoted to L0 on 2026-05-24 (Phase A.3 of impl
	// plan); see docs/L0-invariants-2026-05-24.md.
	if f.Action == "net_connect" {
		if f.DestHost == "169.254.169.254" ||
			strings.HasPrefix(f.DestHost, "fd00:ec2::") {
			if !isCloudAwareRole(f.Role) {
				return DecisionHardDeny,
					"metadata-service access by non-cloud role: " + f.Role
			}
		}
	}

	// (1.6) Exec from tmpfs. Implant pattern with near-zero legitimate
	// use. Audited + promoted to L0 on 2026-05-24 (Phase A.3).
	if (f.Action == "exec" || f.Action == "process_spawn") &&
		isTmpfsLikelyPath(f.TargetImage) {
		return DecisionHardDeny, "exec from tmpfs-like path: " + f.TargetImage
	}

	// (2) Protected-paths violation. Writes + execs only — reads of
	// protected paths are handled by credbroker, not BRP.
	//
	// Three calibration rules apply here (added 2026-05-23 after live-fire
	// FP storm from snap installing AWS CLI):
	//
	//   B) Allowlist: if the actor comm is a well-known administrative
	//      writer (snapd, dpkg, apt, systemctl, ...), the protected-path
	//      write is part of normal system operation. Fall through to the
	//      envelope check instead of hard-denying.
	//   D) Attribution required: if we can't identify the writer (Comm=""
	//      AND PID=0), demote hard_deny to Verify. We will not hard-deny a
	//      write we can't attribute to a process — too easy to falsely
	//      flag legitimate kernel-thread writes or sensor blind spots.
	//   A) Tier downshift while T07 is unbuilt: protected-path writes by
	//      attributed but unknown processes become Verify, not HardDeny.
	//      Once the verification engine ships, attributed protected-path
	//      writes can re-promote to HardDeny with a verifier confirmation.
	if isWriteAction(f.Action) && IsProtectedPath(f.Path) {
		if isTrustedSystemWriterMulti(f.Comm, f.ExePath, f.Trust) {
			// Rule B: trusted writer with corroborating signals — skip
			// protected-path check. The multi-signal score must meet
			// MinTrustScoreForBypass (default 2), so comm-only spoofers
			// don't pass.
		} else if f.Comm == "" && f.PID == 0 {
			// Rule D: unattributed write — log-only.
			return DecisionVerify, "unattributed write to protected path: " + f.Path
		} else {
			// Rule A: attributed but unprofiled writer — verify, not deny.
			return DecisionVerify, "write to protected path (pending T07 verification): " + f.Path
		}
	}
	if (f.Action == "exec" || f.Action == "process_spawn") && IsProtectedPath(f.TargetImage) {
		return DecisionHardDeny, "exec of protected path: " + f.TargetImage
	}

	// (3) Role-invariant: web/DB role + shell-or-interpreter exec.
	if (f.Action == "exec" || f.Action == "process_spawn") && f.TargetImage != "" {
		role := f.Role
		if role == "" && m.Profile != nil {
			role = m.Profile.Key.Role
		}
		if denied, ok := r.inv.DeniedExecsByRole[role]; ok {
			for _, prog := range denied {
				if f.TargetImage == prog {
					return DecisionHardDeny,
						fmt.Sprintf("role-invariant: %s must never exec %s", role, prog)
				}
			}
		}
	}

	// (4) No profile to compare against. Conservative default: log-only
	// (verification engine handles via its own scoring).
	if m.Profile == nil || m.Confidence == ConfidenceUnprofiled {
		return DecisionUnknown, "no matching profile (unprofiled)"
	}

	// (5) Profile envelope check.
	if reason, inside := insideEnvelope(*m.Profile, f); inside {
		return DecisionAllow, reason
	} else {
		return DecisionVerify, reason
	}
}

// isCloudAwareRole returns true for roles whose profiles legitimately
// integrate with cloud metadata services. Conservative list — only
// roles with explicit cloud SDK / IMDS use should match. Anything else
// hitting 169.254.169.254 is treated as the canonical SSRF / token
// theft pattern.
func isCloudAwareRole(role string) bool {
	if role == "" {
		return false // unprofiled cannot legitimately claim cloud
	}
	prefixes := []string{"aws-", "gcp-", "azure-", "k8s-", "cloud-"}
	for _, p := range prefixes {
		if strings.HasPrefix(role, p) {
			return true
		}
	}
	// Specific cloud agents.
	switch role {
	case "imds-proxy", "metadata-proxy", "kubelet", "amazon-ssm-agent":
		return true
	}
	return false
}

// isTmpfsLikelyPath returns true if path is under a directory commonly
// backed by tmpfs. We do NOT verify filesystem type at L0 time (that
// requires a stat call per event and races); a path-based heuristic
// covers the canonical implant locations. False positives here just
// shift the decision from L0 to Tier-2, which is acceptable.
func isTmpfsLikelyPath(path string) bool {
	if path == "" {
		return false
	}
	prefixes := []string{
		"/dev/shm/", "/run/user/", "/tmp/.",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// isWriteAction returns true if Action represents a filesystem mutation.
func isWriteAction(action string) bool {
	switch action {
	case "file_write", "file_create", "file_unlink", "file_truncate",
		"file_chmod", "file_chown", "file_link", "file_rename":
		return true
	}
	return false
}

// insideEnvelope checks if facts fall inside the profile's declared
// behavior. Returns (reason, inside). The reason is operator-readable.
//
// Action-specific checks:
//
//   file_open / file_write: path must be under a ReadRoot or WriteRoot
//   exec / process_spawn:   target must be in ExecAllowed (if set; empty list means no restriction)
//   net_connect:            destination must match UpstreamHosts or UpstreamSockets
//   net_listen:             port must be in ListenPorts
//
// Unknown actions return inside=true (we don't have a specific check;
// the verification engine handles via its other domains).
func insideEnvelope(p Profile, f EventFacts) (string, bool) {
	switch f.Action {
	case "file_open", "file_read":
		if pathInPrefixes(f.Path, p.Behavior.ReadRoots) ||
			pathInPrefixes(f.Path, p.Behavior.WriteRoots) {
			return "read inside ReadRoots/WriteRoots", true
		}
		return "read outside declared roots: " + f.Path, false

	case "file_write", "file_create", "file_truncate", "file_append":
		if pathInPrefixes(f.Path, p.Behavior.WriteRoots) {
			return "write inside WriteRoots", true
		}
		return "write outside declared WriteRoots: " + f.Path, false

	case "exec", "process_spawn":
		if len(p.Behavior.ExecAllowed) == 0 {
			// Empty ExecAllowed = no exec restriction declared (some apps
			// like systemd legitimately exec arbitrary helpers).
			return "no ExecAllowed restriction in profile", true
		}
		if pathInPrefixes(f.TargetImage, p.Behavior.ExecAllowed) {
			return "exec target in ExecAllowed", true
		}
		return "exec outside declared ExecAllowed: " + f.TargetImage, false

	case "net_connect":
		// Unix-socket destinations.
		if f.DestSocket != "" {
			for _, s := range p.Behavior.UpstreamSockets {
				if f.DestSocket == s {
					return "outbound to declared UpstreamSocket", true
				}
			}
			return "outbound to undeclared unix socket: " + f.DestSocket, false
		}
		// Host:port destinations.
		for _, h := range p.Behavior.UpstreamHosts {
			if hostMatches(f.DestHost, f.DestPort, h) {
				return "outbound to declared UpstreamHost", true
			}
		}
		return fmt.Sprintf("outbound to undeclared destination %s:%d", f.DestHost, f.DestPort), false

	case "net_listen":
		for _, p2 := range p.Behavior.ListenPorts {
			if uint16(p2) == f.DestPort {
				return "listening on declared port", true
			}
		}
		return fmt.Sprintf("listening on undeclared port %d", f.DestPort), false
	}

	// Unknown / unhandled action: no specific check, let verification
	// engine handle via other domains.
	return "no envelope check for action " + f.Action, true
}

// pathInPrefixes returns true if path is at or under any prefix entry.
// Trailing-slash prefixes match the dir + descendants; non-slash entries
// are exact-file matches.
func pathInPrefixes(path string, prefixes []string) bool {
	if path == "" {
		return false
	}
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/") {
			if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
				return true
			}
		} else if path == p {
			return true
		}
	}
	return false
}

// hostMatches compares an observed destination against a declared
// upstream entry. Declared entry can be "host", "host:port", or
// "host:*" (no port restriction).
func hostMatches(observedHost string, observedPort uint16, declared string) bool {
	if declared == "" {
		return false
	}
	if colon := strings.LastIndex(declared, ":"); colon >= 0 {
		declaredHost := declared[:colon]
		declaredPort := declared[colon+1:]
		if declaredHost != observedHost {
			return false
		}
		if declaredPort == "*" {
			return true
		}
		return declaredPort == fmt.Sprintf("%d", observedPort)
	}
	// Declared as bare host — any port matches.
	return declared == observedHost
}
