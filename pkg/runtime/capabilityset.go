// Package runtime exposes a CapabilitySet — xhelix's runtime
// inventory of "what can this binary actually do on this host right
// now?" The planner consults it before emitting an ActionPlan so the
// plan only contains actions that will actually execute. Missing
// capabilities convert to explicit CapabilityWarnings — never silent
// degradation.
//
// See REFACTOR_ROADMAP.md §2.2 for the type contract and §6 rule #3
// (no silent degradation) for the design motivation.
package runtime

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/decision"
)

// CapabilitySet is the runtime inventory. Zero value is "nothing
// works" — callers must Discover() before reading.
type CapabilitySet struct {
	mu sync.RWMutex

	// Discovery metadata
	DiscoveredAt time.Time `json:"discovered_at"`
	Kernel       string    `json:"kernel,omitempty"`
	GOOS         string    `json:"goos"`

	// Kernel features — gates the most powerful actions.
	EBPFLoaded      bool `json:"ebpf_loaded"`       // ebpf-progs.o loaded successfully
	BPFLSM          bool `json:"bpf_lsm"`           // kernel cmdline has lsm=...,bpf
	HasNFTables     bool `json:"has_nftables"`      // nft binary present + writable
	HasCgroupV2     bool `json:"has_cgroup_v2"`     // /sys/fs/cgroup is cgroup2
	HasUserNS       bool `json:"has_user_ns"`       // unprivileged user namespaces enabled
	BPFSendSignal   bool `json:"bpf_send_signal"`   // kernel ≥ 5.3 bpf_send_signal helper
	BPFOverrideRet  bool `json:"bpf_override_ret"`  // BPF_FUNC_override_return available

	// xhelix subsystems — gates application-layer actions.
	NetbanReady    bool `json:"netban_ready"`
	QuarantineReady bool `json:"quarantine_ready"`
	RemediateReady bool `json:"remediate_ready"`
	SnapshotReady  bool `json:"snapshot_ready"`
	MemscanReady   bool `json:"memscan_ready"`
	TarpitReady    bool `json:"tarpit_ready"`

	// Operator infrastructure
	BastionCount  int  `json:"bastion_count"`   // healthy bastion IPs reachable
	OffHostMirror bool `json:"off_host_mirror"` // evidence chain replicated off-host
	WebAuthnReady bool `json:"webauthn_ready"`

	// Configaudit — knobs that were Witnessed (i.e. wired to code).
	// Per REFACTOR_ROADMAP.md §6 rule #6: this contract is preserved
	// across the refactor. Empty means "audit not run yet".
	WitnessedKnobs map[string]bool `json:"witnessed_knobs,omitempty"`

	// Free-form notes from the discovery probes; populated by Discover().
	Notes []string `json:"notes,omitempty"`
}

// New returns an empty CapabilitySet. Caller must Discover() before
// using it for planning decisions.
func New() *CapabilitySet {
	return &CapabilitySet{
		GOOS:           runtime.GOOS,
		WitnessedKnobs: map[string]bool{},
	}
}

// Discover probes the host for capabilities. Safe to call
// concurrently with reads (uses mu). Probes are deliberately cheap
// and side-effect-free — they read /proc, stat() binaries, and check
// existing subsystem state. Anything that requires actually running a
// command (e.g. nft list ruleset) is not done here.
func (c *CapabilitySet) Discover() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.DiscoveredAt = time.Now().UTC()
	c.Notes = c.Notes[:0]

	if runtime.GOOS != "linux" {
		c.Notes = append(c.Notes, "non-linux: all linux-specific capabilities false")
		return
	}

	c.Kernel = readKernelVersion()

	// Kernel features. Each probe is best-effort.
	c.HasCgroupV2 = isCgroupV2()
	c.HasNFTables = binaryExists("/usr/sbin/nft") || binaryExists("/sbin/nft")
	c.HasUserNS = readBoolSysctl("/proc/sys/kernel/unprivileged_userns_clone", true)
	c.BPFLSM = kernelHasBPFLSM()

	// Helper availability gated by kernel version. bpf_send_signal
	// landed in 5.3; bpf_override_return is build-time CONFIG.
	if kernelAtLeast(c.Kernel, 5, 3) {
		c.BPFSendSignal = true
	}
	c.BPFOverrideRet = readBoolSysctl("/proc/sys/kernel/bpf_stats_enabled", false) // proxy probe; real check needs verifier load

	// Subsystem readiness — set by the daemon at start via Mark*.
	// Discover() doesn't flip these; they default false and become
	// true when each subsystem's constructor succeeds.
}

// Mark{Name} setters — called by the daemon as each subsystem
// initializes successfully. Keeps the discovery code simple (it
// can't know whether netban's bootstrap really worked) while still
// keeping CapabilitySet authoritative.

func (c *CapabilitySet) MarkEBPFLoaded()      { c.set(func() { c.EBPFLoaded = true }) }
func (c *CapabilitySet) MarkNetbanReady()     { c.set(func() { c.NetbanReady = true }) }
func (c *CapabilitySet) MarkQuarantineReady() { c.set(func() { c.QuarantineReady = true }) }
func (c *CapabilitySet) MarkRemediateReady()  { c.set(func() { c.RemediateReady = true }) }
func (c *CapabilitySet) MarkSnapshotReady()   { c.set(func() { c.SnapshotReady = true }) }
func (c *CapabilitySet) MarkMemscanReady()    { c.set(func() { c.MemscanReady = true }) }
func (c *CapabilitySet) MarkTarpitReady()     { c.set(func() { c.TarpitReady = true }) }
func (c *CapabilitySet) MarkWebAuthnReady()   { c.set(func() { c.WebAuthnReady = true }) }
func (c *CapabilitySet) MarkOffHostMirror()   { c.set(func() { c.OffHostMirror = true }) }
func (c *CapabilitySet) SetBastionCount(n int) {
	c.set(func() { c.BastionCount = n })
}
func (c *CapabilitySet) RecordWitness(key string) {
	c.set(func() {
		if c.WitnessedKnobs == nil {
			c.WitnessedKnobs = map[string]bool{}
		}
		c.WitnessedKnobs[key] = true
	})
}

func (c *CapabilitySet) set(f func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f()
}

// CanExecute returns the list of warnings for actions in the plan
// whose required capability is missing. An empty slice means the
// plan can execute end-to-end with the current capability set.
//
// The planner uses this BEFORE emitting a plan: warnings either
// downgrade the plan or attach as ActionPlan.CapabilityWarnings so
// the executor doesn't silently skip.
func (c *CapabilitySet) CanExecute(p *decision.ActionPlan) []string {
	if p == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	var warnings []string

	require := func(have bool, action, missing string) {
		if !have {
			warnings = append(warnings, fmt.Sprintf("%s requires %s", action, missing))
		}
	}

	if p.Snapshot {
		require(c.SnapshotReady, "snapshot", "pkg/snapshot ready")
	}
	if p.Memscan {
		require(c.MemscanReady, "memscan", "pkg/memscan ready")
	}
	if p.SuspendProcess {
		// SIGSTOP is just a syscall; only "ready" means the dispatcher
		// has a process-resolver registered.
		require(c.QuarantineReady, "suspend_process", "pkg/quarantine ready")
	}
	if p.IsolateCgroup {
		require(c.HasCgroupV2, "isolate_cgroup", "cgroup v2")
		require(c.HasNFTables, "isolate_cgroup", "nftables binary")
		require(c.QuarantineReady, "isolate_cgroup", "pkg/quarantine ready")
	}
	if p.BanRemoteIP {
		require(c.NetbanReady, "ban_remote_ip", "pkg/netban ready")
		require(c.HasNFTables, "ban_remote_ip", "nftables binary")
	}
	if p.Tarpit {
		require(c.TarpitReady, "tarpit", "pkg/tarpit ready")
		require(c.HasNFTables, "tarpit", "nftables binary")
	}
	if p.IsolateHost {
		// Host isolation is the most dangerous action — needs ALL of
		// the operator infrastructure.
		require(c.BastionCount >= 2, "isolate_host", "BastionCount>=2")
		require(c.OffHostMirror, "isolate_host", "off-host evidence mirror")
		require(c.NetbanReady, "isolate_host", "pkg/netban ready")
	}
	if p.RemediateFile {
		require(c.RemediateReady, "remediate_file", "pkg/remediate ready")
	}
	if p.RequireStepUp {
		require(c.WebAuthnReady, "require_step_up", "WebAuthn endpoint live")
	}

	return warnings
}

// AnnotatePlan attaches the missing-capability warnings to the plan
// instead of returning them. Per REFACTOR_ROADMAP.md §6 rule #3 —
// warnings must travel with the plan so the executor can surface
// them to operators.
func (c *CapabilitySet) AnnotatePlan(p *decision.ActionPlan) {
	for _, w := range c.CanExecute(p) {
		p.CapabilityWarnings = append(p.CapabilityWarnings, w)
	}
}

// ErrMissingCapability is returned when the planner refuses to emit
// a plan because critical capabilities are missing.
var ErrMissingCapability = errors.New("decision: required capability missing")

// SnapshotData is the lock-free view of a CapabilitySet — safe to
// JSON-marshal and pass across goroutines.
type SnapshotData struct {
	DiscoveredAt    time.Time       `json:"discovered_at"`
	Kernel          string          `json:"kernel,omitempty"`
	GOOS            string          `json:"goos"`
	EBPFLoaded      bool            `json:"ebpf_loaded"`
	BPFLSM          bool            `json:"bpf_lsm"`
	HasNFTables     bool            `json:"has_nftables"`
	HasCgroupV2     bool            `json:"has_cgroup_v2"`
	HasUserNS       bool            `json:"has_user_ns"`
	BPFSendSignal   bool            `json:"bpf_send_signal"`
	BPFOverrideRet  bool            `json:"bpf_override_ret"`
	NetbanReady     bool            `json:"netban_ready"`
	QuarantineReady bool            `json:"quarantine_ready"`
	RemediateReady  bool            `json:"remediate_ready"`
	SnapshotReady   bool            `json:"snapshot_ready"`
	MemscanReady    bool            `json:"memscan_ready"`
	TarpitReady     bool            `json:"tarpit_ready"`
	BastionCount    int             `json:"bastion_count"`
	OffHostMirror   bool            `json:"off_host_mirror"`
	WebAuthnReady   bool            `json:"webauthn_ready"`
	WitnessedKnobs  map[string]bool `json:"witnessed_knobs,omitempty"`
	Notes           []string        `json:"notes,omitempty"`
}

// Snapshot returns a lock-free copy safe to JSON-marshal.
func (c *CapabilitySet) Snapshot() SnapshotData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := SnapshotData{
		DiscoveredAt: c.DiscoveredAt, Kernel: c.Kernel, GOOS: c.GOOS,
		EBPFLoaded: c.EBPFLoaded, BPFLSM: c.BPFLSM,
		HasNFTables: c.HasNFTables, HasCgroupV2: c.HasCgroupV2,
		HasUserNS: c.HasUserNS, BPFSendSignal: c.BPFSendSignal,
		BPFOverrideRet:  c.BPFOverrideRet,
		NetbanReady:     c.NetbanReady,
		QuarantineReady: c.QuarantineReady,
		RemediateReady:  c.RemediateReady,
		SnapshotReady:   c.SnapshotReady,
		MemscanReady:    c.MemscanReady,
		TarpitReady:     c.TarpitReady,
		BastionCount:    c.BastionCount,
		OffHostMirror:   c.OffHostMirror,
		WebAuthnReady:   c.WebAuthnReady,
	}
	if c.WitnessedKnobs != nil {
		out.WitnessedKnobs = make(map[string]bool, len(c.WitnessedKnobs))
		for k, v := range c.WitnessedKnobs {
			out.WitnessedKnobs[k] = v
		}
	}
	if c.Notes != nil {
		out.Notes = append([]string(nil), c.Notes...)
	}
	return out
}

// --- probes ---

func binaryExists(p string) bool {
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	return st.Mode()&0111 != 0
}

func isCgroupV2() bool {
	// /sys/fs/cgroup/cgroup.controllers only exists on v2 hosts.
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

func readBoolSysctl(path string, def bool) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	s := strings.TrimSpace(string(b))
	return s != "" && s != "0"
}

func kernelHasBPFLSM() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "bpf")
}

func readKernelVersion() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// kernelAtLeast parses major.minor from a uname-style release string
// and reports whether it's >= the requested version.
func kernelAtLeast(release string, wantMajor, wantMinor int) bool {
	if release == "" {
		return false
	}
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, minor := atoi(parts[0]), atoi(parts[1])
	if major > wantMajor {
		return true
	}
	if major < wantMajor {
		return false
	}
	return minor >= wantMinor
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}
