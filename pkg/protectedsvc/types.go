// Package protectedsvc holds the type vocabulary for Protected
// Services — xhelix's web-server containment + deception layer. See
// PROTECTED_SERVICES_TRAP.md for the full design.
//
// This package has zero behavior. It declares the data shapes that
// pkg/profiles/serviceid (identity matching), pkg/profiles/contracts
// (per-service policy), pkg/prevent/* (Ring 1), and
// pkg/deception/* (Ring 2) all consume.
//
// Stable wire format — yaml tags on every field for config loading,
// json tags for LocalAPI surfaces.
package protectedsvc

import "time"

// ServiceKind names the well-known service family.
type ServiceKind string

const (
	KindNginx  ServiceKind = "nginx"
	KindApache ServiceKind = "apache"
)

// AllKinds returns every supported kind. Used by config validation.
func AllKinds() []ServiceKind { return []ServiceKind{KindNginx, KindApache} }

// ServiceRole narrows the kind to a deployment shape. Roles drive
// which built-in contract template applies.
type ServiceRole string

const (
	RoleStatic       ServiceRole = "static"
	RoleReverseProxy ServiceRole = "reverse_proxy"
	RoleFastCGI      ServiceRole = "fastcgi"
	RolePHPModule    ServiceRole = "php_module"
)

// AllRoles returns every supported role.
func AllRoles() []ServiceRole {
	return []ServiceRole{RoleStatic, RoleReverseProxy, RoleFastCGI, RolePHPModule}
}

// ProtectedService is one configured service the operator wants
// xhelix to protect. Operators declare these in config; the
// serviceid matcher resolves running processes to them.
type ProtectedService struct {
	// Operator-chosen unique name. Used in logs, evidence, UX.
	Name string `yaml:"name" json:"name"`

	Kind ServiceKind `yaml:"kind" json:"kind"`
	Role ServiceRole `yaml:"role" json:"role"`

	// Unit is the systemd unit (e.g. "nginx.service"). Used for
	// identity verification and to scope cgroup matching.
	Unit string `yaml:"unit,omitempty" json:"unit,omitempty"`

	// ExecPath is the canonical binary path (e.g. /usr/sbin/nginx).
	// Required — the matcher refuses to match by anything else
	// alone to avoid hijack via PATH manipulation.
	ExecPath string `yaml:"exec_path" json:"exec_path"`

	// ExeSHA256 is the expected SHA-256 of the binary. Verified at
	// match time; a mismatch is itself a Tier-1 signal
	// (SignalDefenseEvasion). Hex-encoded, lowercase, 64 chars.
	// Empty = skip SHA check (NOT recommended in production).
	ExeSHA256 string `yaml:"exe_sha256,omitempty" json:"exe_sha256,omitempty"`

	// UID/GID, if set, MUST match the running process. Pointer so
	// we can distinguish "not specified" from "uid 0".
	UID *uint32 `yaml:"uid,omitempty" json:"uid,omitempty"`
	GID *uint32 `yaml:"gid,omitempty" json:"gid,omitempty"`

	// CgroupPrefix is the systemd cgroup path prefix
	// (e.g. "/system.slice/nginx.service"). When the kernel reports
	// a process's cgroup, the matcher checks HasPrefix(...).
	// This is the cheapest identity check we have — cached on
	// cgroup_id → service_name in serviceid.Cache.
	CgroupPrefix string `yaml:"cgroup_prefix,omitempty" json:"cgroup_prefix,omitempty"`

	// Contract is the per-service allow/deny policy. See
	// pkg/profiles/contracts for built-ins.
	Contract ServiceContract `yaml:"contract,omitempty" json:"contract,omitempty"`

	// Learn controls bounded learning mode (Ring 1 + Ring 2 are
	// active during learning; the allowlist is the only thing being
	// expanded).
	Learn LearnConfig `yaml:"learning,omitempty" json:"learning,omitempty"`

	// Response governs Ring 3 (containment) thresholds + Ring 2
	// (deception) toggles.
	Response ResponseProfile `yaml:"response,omitempty" json:"response,omitempty"`
}

// ServiceContract is the per-service allow/deny matrix. Empty fields
// mean "use the built-in default for this Kind+Role".
type ServiceContract struct {
	// Exec — what the service can run.
	DenyExecPaths  []string `yaml:"deny_exec_paths,omitempty" json:"deny_exec_paths,omitempty"`
	AllowExecPaths []string `yaml:"allow_exec_paths,omitempty" json:"allow_exec_paths,omitempty"`

	// Filesystem — what the service can write / read.
	WriteRoots         []string `yaml:"write_roots,omitempty" json:"write_roots,omitempty"`
	ReadSensitiveRoots []string `yaml:"read_sensitive_roots,omitempty" json:"read_sensitive_roots,omitempty"`

	// Network — where the service can connect.
	UpstreamCIDRs []string `yaml:"upstream_cidrs,omitempty" json:"upstream_cidrs,omitempty"`
	DNSResolvers  []string `yaml:"dns_resolvers,omitempty" json:"dns_resolvers,omitempty"`
	UnixSockets   []string `yaml:"unix_sockets,omitempty" json:"unix_sockets,omitempty"`
	ListenPorts   []uint16 `yaml:"listen_ports,omitempty" json:"listen_ports,omitempty"`

	// Syscalls + memory — Ring 1 deny list.
	DenySyscalls         []string          `yaml:"deny_syscalls,omitempty" json:"deny_syscalls,omitempty"`
	DenyMemoryPrimitives []MemoryPrimitive `yaml:"deny_memory_primitives,omitempty" json:"deny_memory_primitives,omitempty"`

	// StrictReadOnly: if true, ALL writes outside WriteRoots are
	// denied (Ring 1) regardless of LearnConfig — i.e. learn mode
	// cannot expand write paths beyond what the operator declared.
	StrictReadOnly bool `yaml:"strict_read_only,omitempty" json:"strict_read_only,omitempty"`
}

// MemoryPrimitive enumerates exploitable memory operations Ring 1
// can deny. Wire-stable strings — adding a new value is safe.
type MemoryPrimitive string

const (
	MemAnonRWX     MemoryPrimitive = "anon_rwx"      // mmap with PROT_EXEC|PROT_WRITE
	MemMemfdExec   MemoryPrimitive = "memfd_exec"    // execveat() on memfd
	MemRWXMProtect MemoryPrimitive = "rwx_mprotect"  // mprotect adding PROT_EXEC|PROT_WRITE
	MemPtrace      MemoryPrimitive = "ptrace"        // attach to another process
	MemUserfaultfd MemoryPrimitive = "userfaultfd"   // userfault for exploit gadget
)

// LearnConfig governs bounded learning. Defaults — disabled.
type LearnConfig struct {
	Enabled             bool `yaml:"enabled" json:"enabled"`
	DurationHours       int  `yaml:"duration_hours,omitempty" json:"duration_hours,omitempty"` // default 24
	LockAfterLearning   bool `yaml:"lock_after_learning" json:"lock_after_learning"`           // default true
	LearnUpstreams      bool `yaml:"learn_upstreams,omitempty" json:"learn_upstreams,omitempty"`
	LearnUnixSockets    bool `yaml:"learn_unix_sockets,omitempty" json:"learn_unix_sockets,omitempty"`
	LearnWriteSubpaths  bool `yaml:"learn_write_subpaths,omitempty" json:"learn_write_subpaths,omitempty"`
	LearnWorkerEnvelope bool `yaml:"learn_worker_envelope,omitempty" json:"learn_worker_envelope,omitempty"`
}

// ResponseProfile governs Ring 2 (deception) toggles and Ring 3
// (containment) thresholds. Defaults are the A+ trap-mode posture.
type ResponseProfile struct {
	// Ring 1 wiring — does a deny invariant ALSO auto-emit a signal?
	AutoDenyInvariants bool `yaml:"auto_deny_invariants" json:"auto_deny_invariants"` // default true

	// Ring 3 thresholds.
	FreezeOnUnknownEgress       bool `yaml:"freeze_on_unknown_egress" json:"freeze_on_unknown_egress"` // default true
	FreezeOnRWX                 bool `yaml:"freeze_on_rwx" json:"freeze_on_rwx"`                       // default true
	SnapshotOnFreeze            bool `yaml:"snapshot_on_freeze" json:"snapshot_on_freeze"`             // default true
	MemscanOnFreeze             bool `yaml:"memscan_on_freeze" json:"memscan_on_freeze"`               // default true
	HostQuarantineOnMultiSignal bool `yaml:"host_quarantine_on_multi_signal,omitempty" json:"host_quarantine_on_multi_signal,omitempty"`

	// Ring 2 — deception layer (the A+ part). Default: all on.
	// Operators can disable per-service for compliance.
	Deception DeceptionConfig `yaml:"deception,omitempty" json:"deception,omitempty"`
}

// DeceptionConfig toggles the four Ring 2 trap mechanisms. All-true
// is the production default; all-false yields refuse-only semantics.
type DeceptionConfig struct {
	Enabled   bool `yaml:"enabled" json:"enabled"`              // master switch; default true
	FakeExec  bool `yaml:"fake_exec" json:"fake_exec"`          // honey-sh on forbidden exec
	Sinkhole  bool `yaml:"sinkhole" json:"sinkhole"`            // sinkhole socket on forbidden connect
	DecoyFS   bool `yaml:"decoy_fs" json:"decoy_fs"`            // decoy fd on sensitive read
	PoisonDNS bool `yaml:"poison_dns" json:"poison_dns"`        // resolve known-bad → sinkhole
}

// AllOn returns a DeceptionConfig with every trap active — the
// production default. Operators opt out per-flag if needed.
func AllOn() DeceptionConfig {
	return DeceptionConfig{
		Enabled: true, FakeExec: true, Sinkhole: true,
		DecoyFS: true, PoisonDNS: true,
	}
}

// AllOff returns refuse-only mode — Ring 1 still active, Ring 2
// returns -EPERM / -ECONNREFUSED / -EACCES instead of trapping.
// Useful in compliance environments where deceiving a process is
// legally restricted.
func AllOff() DeceptionConfig { return DeceptionConfig{} }

// Identity is the runtime fingerprint of a single running process
// the matcher uses to resolve it to a ProtectedService. Carries
// just enough for verification, not the full proc snapshot.
type Identity struct {
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	ExePath   string    `json:"exe_path,omitempty"`
	ExeSHA256 string    `json:"exe_sha256,omitempty"`
	CGroup    string    `json:"cgroup,omitempty"`     // resolved /proc/PID/cgroup path
	Unit      string    `json:"unit,omitempty"`        // resolved systemd unit
	StartTime time.Time `json:"start_time,omitempty"`
}

// MatchVerdict is the result of matching an Identity against a
// configured ProtectedService.
type MatchVerdict struct {
	Matched bool
	Service *ProtectedService

	// Discrepancy, if non-empty, means the Identity matched by cgroup
	// or unit but verification failed (e.g. exe SHA mismatch, uid
	// changed). The caller MUST emit SignalDefenseEvasion on
	// non-empty Discrepancy — that's how we catch binary swaps.
	Discrepancy string
}
