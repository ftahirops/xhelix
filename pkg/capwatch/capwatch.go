// Package capwatch classifies Linux capability changes emitted by
// the sys_enter_capset eBPF tracepoint. Gaining CAP_SYS_ADMIN is
// near-equivalent to gaining root in many real escape chains;
// gaining CAP_BPF / CAP_PERFMON gives runtime kernel observation/
// modification surface.
//
// The package is pure: caller passes a Change record (effective
// before, effective after, optional permitted+inheritable masks)
// plus process context, and gets back a Finding with severity +
// list of gained / dropped capability names.
package capwatch

// Capability bit positions per linux/capability.h. Documented
// at https://man7.org/linux/man-pages/man7/capabilities.7.html.
// We define the subset xhelix cares about; unknown bits stay as
// "CAP_<num>" in the formatted output.
const (
	CAP_CHOWN            = 0
	CAP_DAC_OVERRIDE     = 1
	CAP_DAC_READ_SEARCH  = 2
	CAP_FOWNER           = 3
	CAP_FSETID           = 4
	CAP_KILL             = 5
	CAP_SETGID           = 6
	CAP_SETUID           = 7
	CAP_SETPCAP          = 8
	CAP_LINUX_IMMUTABLE  = 9
	CAP_NET_BIND_SERVICE = 10
	CAP_NET_BROADCAST    = 11
	CAP_NET_ADMIN        = 12
	CAP_NET_RAW          = 13
	CAP_IPC_LOCK         = 14
	CAP_IPC_OWNER        = 15
	CAP_SYS_MODULE       = 16
	CAP_SYS_RAWIO        = 17
	CAP_SYS_CHROOT       = 18
	CAP_SYS_PTRACE       = 19
	CAP_SYS_PACCT        = 20
	CAP_SYS_ADMIN        = 21
	CAP_SYS_BOOT         = 22
	CAP_SYS_NICE         = 23
	CAP_SYS_RESOURCE     = 24
	CAP_SYS_TIME         = 25
	CAP_SYS_TTY_CONFIG   = 26
	CAP_MKNOD            = 27
	CAP_LEASE            = 28
	CAP_AUDIT_WRITE      = 29
	CAP_AUDIT_CONTROL    = 30
	CAP_SETFCAP          = 31
	CAP_MAC_OVERRIDE     = 32
	CAP_MAC_ADMIN        = 33
	CAP_SYSLOG           = 34
	CAP_WAKE_ALARM       = 35
	CAP_BLOCK_SUSPEND    = 36
	CAP_AUDIT_READ       = 37
	CAP_PERFMON          = 38
	CAP_BPF              = 39
	CAP_CHECKPOINT_RESTORE = 40
)

// capName returns the human-readable name for bit b. Unknown bits
// formatted as "CAP_<num>".
func capName(b int) string {
	switch b {
	case CAP_CHOWN:
		return "CAP_CHOWN"
	case CAP_DAC_OVERRIDE:
		return "CAP_DAC_OVERRIDE"
	case CAP_DAC_READ_SEARCH:
		return "CAP_DAC_READ_SEARCH"
	case CAP_FOWNER:
		return "CAP_FOWNER"
	case CAP_FSETID:
		return "CAP_FSETID"
	case CAP_KILL:
		return "CAP_KILL"
	case CAP_SETGID:
		return "CAP_SETGID"
	case CAP_SETUID:
		return "CAP_SETUID"
	case CAP_SETPCAP:
		return "CAP_SETPCAP"
	case CAP_LINUX_IMMUTABLE:
		return "CAP_LINUX_IMMUTABLE"
	case CAP_NET_BIND_SERVICE:
		return "CAP_NET_BIND_SERVICE"
	case CAP_NET_BROADCAST:
		return "CAP_NET_BROADCAST"
	case CAP_NET_ADMIN:
		return "CAP_NET_ADMIN"
	case CAP_NET_RAW:
		return "CAP_NET_RAW"
	case CAP_IPC_LOCK:
		return "CAP_IPC_LOCK"
	case CAP_IPC_OWNER:
		return "CAP_IPC_OWNER"
	case CAP_SYS_MODULE:
		return "CAP_SYS_MODULE"
	case CAP_SYS_RAWIO:
		return "CAP_SYS_RAWIO"
	case CAP_SYS_CHROOT:
		return "CAP_SYS_CHROOT"
	case CAP_SYS_PTRACE:
		return "CAP_SYS_PTRACE"
	case CAP_SYS_PACCT:
		return "CAP_SYS_PACCT"
	case CAP_SYS_ADMIN:
		return "CAP_SYS_ADMIN"
	case CAP_SYS_BOOT:
		return "CAP_SYS_BOOT"
	case CAP_SYS_NICE:
		return "CAP_SYS_NICE"
	case CAP_SYS_RESOURCE:
		return "CAP_SYS_RESOURCE"
	case CAP_SYS_TIME:
		return "CAP_SYS_TIME"
	case CAP_SYS_TTY_CONFIG:
		return "CAP_SYS_TTY_CONFIG"
	case CAP_MKNOD:
		return "CAP_MKNOD"
	case CAP_LEASE:
		return "CAP_LEASE"
	case CAP_AUDIT_WRITE:
		return "CAP_AUDIT_WRITE"
	case CAP_AUDIT_CONTROL:
		return "CAP_AUDIT_CONTROL"
	case CAP_SETFCAP:
		return "CAP_SETFCAP"
	case CAP_MAC_OVERRIDE:
		return "CAP_MAC_OVERRIDE"
	case CAP_MAC_ADMIN:
		return "CAP_MAC_ADMIN"
	case CAP_SYSLOG:
		return "CAP_SYSLOG"
	case CAP_WAKE_ALARM:
		return "CAP_WAKE_ALARM"
	case CAP_BLOCK_SUSPEND:
		return "CAP_BLOCK_SUSPEND"
	case CAP_AUDIT_READ:
		return "CAP_AUDIT_READ"
	case CAP_PERFMON:
		return "CAP_PERFMON"
	case CAP_BPF:
		return "CAP_BPF"
	case CAP_CHECKPOINT_RESTORE:
		return "CAP_CHECKPOINT_RESTORE"
	}
	return "CAP_" + itoa(b)
}

// Severity classifies a gain.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityNotice   Severity = 2
	SeverityWarn     Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
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

// severityForCap returns the per-capability gain severity.
func severityForCap(bit int) Severity {
	switch bit {
	case CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_RAWIO,
		CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH,
		CAP_SETUID, CAP_SETPCAP,
		CAP_MAC_ADMIN, CAP_MAC_OVERRIDE:
		return SeverityCritical
	case CAP_SYS_PTRACE, CAP_NET_ADMIN, CAP_NET_RAW,
		CAP_BPF, CAP_PERFMON,
		CAP_SYS_BOOT, CAP_SYS_TIME,
		CAP_AUDIT_CONTROL, CAP_AUDIT_READ,
		CAP_LINUX_IMMUTABLE, CAP_SYSLOG,
		CAP_CHECKPOINT_RESTORE, CAP_SETFCAP:
		return SeverityHigh
	case CAP_CHOWN, CAP_FOWNER, CAP_FSETID, CAP_KILL,
		CAP_SETGID, CAP_NET_BIND_SERVICE,
		CAP_SYS_CHROOT, CAP_SYS_NICE, CAP_SYS_RESOURCE,
		CAP_IPC_LOCK, CAP_IPC_OWNER,
		CAP_MKNOD, CAP_LEASE,
		CAP_AUDIT_WRITE, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND,
		CAP_SYS_TTY_CONFIG, CAP_NET_BROADCAST, CAP_SYS_PACCT:
		return SeverityWarn
	}
	return SeverityNotice
}

// Change describes one capset(2) call from a process.
type Change struct {
	PID            uint32
	Comm           string
	Exe            string
	ParentExe      string
	EffectiveBefore uint64 // bitset before the call (caller passes 0 if unknown)
	EffectiveAfter  uint64 // bitset the kernel will apply
}

// Finding is the output.
type Finding struct {
	Severity  Severity
	Gained    []string // human-readable cap names newly set
	Dropped   []string // human-readable cap names newly cleared
	Reasons   []string
}

// Classify diffs EffectiveBefore vs EffectiveAfter and returns
// a Finding. SeverityNone means nothing meaningful changed.
//
// When EffectiveBefore is 0 (we don't know prior state), we treat
// every bit set in EffectiveAfter as a potential gain — useful for
// catching execve-of-suid-binary, where xhelix wasn't tracking
// the caller's mask but the process now has rights.
func Classify(c Change) Finding {
	gained := c.EffectiveAfter &^ c.EffectiveBefore
	dropped := c.EffectiveBefore &^ c.EffectiveAfter

	f := Finding{}
	if gained == 0 && dropped == 0 {
		return f
	}
	for b := 0; b < 64; b++ {
		mask := uint64(1) << b
		if gained&mask != 0 {
			f.Gained = append(f.Gained, capName(b))
			s := severityForCap(b)
			if s > f.Severity {
				f.Severity = s
				f.Reasons = append(f.Reasons, "gained "+capName(b))
			}
		}
	}
	for b := 0; b < 64; b++ {
		mask := uint64(1) << b
		if dropped&mask != 0 {
			f.Dropped = append(f.Dropped, capName(b))
		}
	}
	return f
}

// Has reports whether the mask has the given capability bit set.
func Has(mask uint64, bit int) bool {
	return mask&(uint64(1)<<bit) != 0
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
