// Package contguard classifies container runtime configuration
// for unsafe options. Privileged containers and namespace-host
// sharing are the single biggest container-escape surface, but
// they're invisible to traditional EDR because everything looks
// like a normal pid from outside.
//
// The package is pure: caller passes a Spec gathered from
// dockerd / containerd / kubelet inspection, and gets back a
// Finding with severity + reasons. No I/O, no runtime hooks.
package contguard

import "strings"

// Severity grades a Finding.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityInfo     Severity = 1
	SeverityNotice   Severity = 2
	SeverityWarn     Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityNotice:
		return "notice"
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "none"
}

// Spec is the runtime-configuration snapshot.
type Spec struct {
	// Image is "repo:tag" or "repo@sha256:...".
	Image string
	// Privileged: --privileged on docker run, or k8s
	// securityContext.privileged=true.
	Privileged bool
	// HostPID, HostIPC, HostNetwork — namespace sharing flags.
	HostPID     bool
	HostIPC     bool
	HostNetwork bool
	// CapAdd is the list of additional Linux capabilities the
	// container was granted (without the CAP_ prefix).
	CapAdd []string
	// CapDrop is the dropped set (rare).
	CapDrop []string
	// AppArmorProfile / SeccompProfile — "unconfined" is the
	// red flag; empty means default.
	AppArmorProfile string
	SeccompProfile  string
	// Mounts is the list of host paths bind-mounted into the
	// container. Sensitive hosts (root, /var/run/docker.sock,
	// /proc, /sys) trigger high-severity findings.
	Mounts []Mount
	// RunAsUser is the uid the container runs as. 0 = root.
	RunAsUser int
	// AllowPrivilegeEscalation: k8s field; missing on docker.
	AllowPrivilegeEscalation *bool
}

// Mount describes one host→container bind mount.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// Finding is the classifier output.
type Finding struct {
	Severity Severity
	Reasons  []string
}

// Classify returns a Finding for the given Spec. A green-light
// container (rootful=false, no privileged, no host ns sharing,
// no dangerous mounts, default profiles) returns {SeverityNone}.
func Classify(s Spec) Finding {
	f := Finding{}
	raise := func(to Severity, r string) {
		if to > f.Severity {
			f.Severity = to
		}
		f.Reasons = append(f.Reasons, r)
	}

	if s.Privileged {
		raise(SeverityCritical, "privileged=true — full host capability set")
	}
	if s.HostPID {
		raise(SeverityHigh, "host PID namespace shared")
	}
	if s.HostNetwork {
		raise(SeverityHigh, "host network namespace shared")
	}
	if s.HostIPC {
		raise(SeverityHigh, "host IPC namespace shared")
	}

	for _, c := range s.CapAdd {
		switch strings.ToUpper(strings.TrimPrefix(c, "CAP_")) {
		case "SYS_ADMIN":
			raise(SeverityCritical, "CAP_SYS_ADMIN granted — equivalent to root in many escapes")
		case "SYS_PTRACE":
			raise(SeverityHigh, "CAP_SYS_PTRACE granted — can attach to host pids when host PID shared")
		case "SYS_MODULE":
			raise(SeverityCritical, "CAP_SYS_MODULE granted — kernel module load")
		case "DAC_READ_SEARCH", "DAC_OVERRIDE":
			raise(SeverityHigh, "CAP_DAC_* granted — file ACL bypass")
		case "NET_ADMIN":
			raise(SeverityWarn, "CAP_NET_ADMIN granted — packet capture, iptables, route table changes")
		case "SYS_RAWIO":
			raise(SeverityHigh, "CAP_SYS_RAWIO granted — direct disk/port I/O")
		case "BPF":
			raise(SeverityHigh, "CAP_BPF granted — load eBPF programs")
		case "SYSLOG":
			raise(SeverityWarn, "CAP_SYSLOG granted — read kernel pointers via dmesg")
		}
	}

	for _, m := range s.Mounts {
		if dangerousMount(m) {
			raise(severityForMount(m.HostPath), "sensitive host path mounted: "+m.HostPath)
		}
	}

	if s.AppArmorProfile == "unconfined" {
		raise(SeverityHigh, "AppArmor unconfined")
	}
	if s.SeccompProfile == "unconfined" {
		raise(SeverityHigh, "seccomp unconfined")
	}
	if s.RunAsUser == 0 && !s.Privileged {
		// Common but worth noting at info-level — root inside
		// container is the default but not best practice.
		raise(SeverityInfo, "runs as uid 0 inside container")
	}
	if s.AllowPrivilegeEscalation != nil && *s.AllowPrivilegeEscalation {
		raise(SeverityNotice, "allowPrivilegeEscalation=true")
	}

	return f
}

// dangerousMount returns true for host paths that grant near-host
// equivalence when mounted into a container.
func dangerousMount(m Mount) bool {
	hp := m.HostPath
	// Exact-match high-impact paths.
	switch hp {
	case "/", "/etc", "/root",
		"/var/run/docker.sock", "/run/docker.sock",
		"/var/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock":
		return true
	}
	// Subtree prefixes.
	for _, prefix := range []string{
		"/proc", "/sys", "/boot", "/dev", "/var/lib/docker",
		"/var/lib/containerd", "/var/lib/kubelet",
	} {
		if hp == prefix || strings.HasPrefix(hp, prefix+"/") {
			return true
		}
	}
	return false
}

// severityForMount returns the per-path severity.
func severityForMount(hp string) Severity {
	switch hp {
	case "/", "/etc", "/var/run/docker.sock", "/run/docker.sock":
		return SeverityCritical
	case "/var/run/containerd/containerd.sock", "/var/run/crio/crio.sock":
		return SeverityCritical
	case "/root":
		return SeverityHigh
	}
	if strings.HasPrefix(hp, "/boot") {
		return SeverityHigh
	}
	if strings.HasPrefix(hp, "/proc") || strings.HasPrefix(hp, "/sys") || strings.HasPrefix(hp, "/dev") {
		return SeverityHigh
	}
	if strings.HasPrefix(hp, "/var/lib/docker") ||
		strings.HasPrefix(hp, "/var/lib/containerd") ||
		strings.HasPrefix(hp, "/var/lib/kubelet") {
		return SeverityHigh
	}
	return SeverityWarn
}
