// Package seccomp generates per-service seccomp BPF filters from a
// ServiceContract.DenySyscalls list, then installs them via the
// seccomp(2) syscall.
//
// Pure Go. CGO_ENABLED=0 compatible (no libseccomp). The generator
// works on any platform — only Install() requires Linux.
//
// See PROTECTED_SERVICES_TRAP.md §5 (Ring 1) and §11 (CapabilitySet
// SeccompReady marker). This is Ring 1 — fast, deterministic, kernel-
// enforced. Sub-microsecond per-syscall cost.
package seccomp

import (
	"runtime"
	"sort"
)

// Arch identifies a CPU architecture in the form expected by
// seccomp_data.arch. We only support the architectures xhelix runs
// on: x86_64 and aarch64.
type Arch string

const (
	ArchX86_64  Arch = "x86_64"
	ArchAArch64 Arch = "aarch64"
)

// AUDIT_ARCH_* values from <linux/audit.h>. seccomp_data.arch must
// equal one of these for the filter to apply.
const (
	auditArchX86_64  uint32 = 0xC000003E
	auditArchAArch64 uint32 = 0xC00000B7
)

// CurrentArch returns the running architecture, or "" if unsupported.
// Caller is expected to check; emitting a seccomp filter for an
// unsupported arch is a programming error.
func CurrentArch() Arch {
	switch runtime.GOARCH {
	case "amd64":
		return ArchX86_64
	case "arm64":
		return ArchAArch64
	}
	return ""
}

// auditArch returns the AUDIT_ARCH_* constant for the given Arch.
func auditArch(a Arch) (uint32, bool) {
	switch a {
	case ArchX86_64:
		return auditArchX86_64, true
	case ArchAArch64:
		return auditArchAArch64, true
	}
	return 0, false
}

// syscallTable holds per-arch syscall-name → NR mappings. Only
// entries we might deny appear here; adding new ones is a small
// edit. Sourced from the kernel headers
// (asm/unistd_64.h, asm-generic/unistd.h).
var syscallTable = map[Arch]map[string]uint32{
	ArchX86_64: {
		"ptrace":           101,
		"mount":            165,
		"umount2":          166,
		"swapon":           167,
		"swapoff":          168,
		"reboot":           169,
		"init_module":      175,
		"delete_module":    176,
		"kexec_load":       246,
		"unshare":          272,
		"perf_event_open":  298,
		"setns":            308,
		"finit_module":     313,
		"kexec_file_load":  320,
		"bpf":              321,
		"userfaultfd":      323,
		"pivot_root":       155,
		// Net-extras some operators add:
		"sendmmsg":         307,
		"recvmmsg":         299,
	},
	ArchAArch64: {
		"umount2":          39,
		"mount":            40,
		"pivot_root":       41,
		"unshare":          97,
		"reboot":           142,
		"kexec_load":       104,
		"init_module":      105,
		"delete_module":    106,
		"ptrace":           117,
		"swapon":           224,
		"swapoff":          225,
		"perf_event_open":  241,
		"setns":            268,
		"finit_module":     273,
		"bpf":              280,
		"userfaultfd":      282,
		"kexec_file_load":  294,
		"sendmmsg":         269,
		"recvmmsg":         243,
	},
}

// LookupSyscall returns the syscall number for the given name and
// arch, plus a "known" bool. Unknown syscalls are silently dropped
// from generated filters with a Note in the resulting Profile (so
// operators can see what got omitted).
func LookupSyscall(name string, a Arch) (uint32, bool) {
	tbl, ok := syscallTable[a]
	if !ok {
		return 0, false
	}
	nr, ok := tbl[name]
	return nr, ok
}

// KnownSyscalls returns the sorted list of syscall names that have a
// known NR for the given arch. Useful for tests + admin UIs.
func KnownSyscalls(a Arch) []string {
	tbl, ok := syscallTable[a]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(tbl))
	for name := range tbl {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
