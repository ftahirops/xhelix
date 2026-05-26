// Package selfseccomp installs a seccomp BPF allow-list filter on
// the xhelix daemon itself. Phase G.2.
//
// This is daemon SELF-protection — different shape from
// pkg/prevent/seccomp, which is per-service deny-list protection
// for managed services. The two coexist on the same kernel API but
// have opposite filter polarity:
//
//   pkg/prevent/seccomp   small DENY-list, default ALLOW (service wrapper)
//   pkg/selfseccomp       small ALLOW-list, default LOG / ERRNO / KILL (daemon)
//
// Three modes:
//
//   ModeOff      — no filter installed (default). Safest.
//   ModeAudit    — filter installed; on unknown syscall, return
//                  SECCOMP_RET_LOG (kernel logs to audit, syscall
//                  proceeds). Use to build the empirical allowlist
//                  by running 24-48h with audit mode on and
//                  collecting denied-but-logged syscalls.
//   ModeEnforce  — filter installed; on unknown syscall, return
//                  SECCOMP_RET_ERRNO with EPERM. Daemon usually
//                  dies (Go runtime cannot recover from EPERM on
//                  many syscalls). Only enable after audit-mode
//                  soak has shown ZERO unknown syscalls for
//                  sustained period.
//
// We deliberately do NOT support ModeKill (SECCOMP_RET_KILL_PROCESS)
// at first — too destructive for incremental rollout. Available in
// follow-on once the allowlist is stable.
//
// CGO_ENABLED=0 compatible — pure cBPF generated in Go, installed
// via the seccomp(2) syscall through golang.org/x/sys/unix.
package selfseccomp

import (
	"fmt"
	"log/slog"
)

// Mode is the install policy.
type Mode int

const (
	ModeOff Mode = iota
	ModeAudit
	ModeEnforce
)

// String renders the mode for logging.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeAudit:
		return "audit"
	case ModeEnforce:
		return "enforce"
	}
	return "unknown"
}

// ParseMode parses a string mode (case-insensitive).
func ParseMode(s string) Mode {
	switch s {
	case "audit", "AUDIT":
		return ModeAudit
	case "enforce", "ENFORCE":
		return ModeEnforce
	}
	return ModeOff
}

// instruction matches Linux struct sock_filter exactly. Defined
// locally so generators run on every platform; install_linux.go
// translates at the boundary.
type instruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// Filter constants. Values from <linux/bpf_common.h>, <linux/audit.h>,
// <linux/seccomp.h>.
const (
	bpfLD  uint16 = 0x00
	bpfJMP uint16 = 0x05
	bpfRET uint16 = 0x06
	bpfW   uint16 = 0x00
	bpfABS uint16 = 0x20
	bpfJEQ uint16 = 0x10
	bpfK   uint16 = 0x00

	// SECCOMP_RET_* (upper 16 bits drive the action).
	retAllow uint32 = 0x7fff0000
	retLog   uint32 = 0x7ffc0000
	retErrno uint32 = 0x00050000

	offsetNR   uint32 = 0
	offsetArch uint32 = 4

	errnoEPERM uint32 = 1

	// Architecture audit values for AUDIT_ARCH_X86_64 / _AARCH64.
	auditArchX86_64  uint32 = 0xC000003E
	auditArchAArch64 uint32 = 0xC00000B7
)

// AllowList captures the syscalls xhelix is allowed to invoke. This
// is the cBPF input; one entry = one syscall NR.
type AllowList struct {
	// Names are operator-readable labels; Numbers are the actual NRs
	// the filter compares against. They must be the same length and
	// indexed the same way.
	Names   []string
	Numbers []uint32

	// Mode is the install policy. Compile-time decision; runtime
	// installation honors this.
	Mode Mode
}

// Compile turns an AllowList + arch into a cBPF program suitable
// for SECCOMP_SET_MODE_FILTER. Filter shape:
//
//   1. Verify seccomp_data.arch == auditArchVal. Mismatch falls
//      through to the default action (ERRNO/LOG). This blocks the
//      classic 32-bit syscall bypass.
//   2. For each allowed syscall NR, JEQ → RET_ALLOW.
//   3. Default: SECCOMP_RET_LOG (audit) or SECCOMP_RET_ERRNO|EPERM
//      (enforce).
//
// On a long allowlist this is O(N) per syscall in the worst case;
// for the ~80-120 syscalls xhelix uses, that's 80-120 cBPF
// comparisons which the kernel runs in nanoseconds.
func Compile(a AllowList, arch string) ([]instruction, error) {
	if len(a.Names) != len(a.Numbers) {
		return nil, fmt.Errorf("selfseccomp.Compile: Names/Numbers length mismatch")
	}
	if a.Mode == ModeOff {
		return nil, fmt.Errorf("selfseccomp.Compile: cannot compile ModeOff")
	}

	var auditArchVal uint32
	switch arch {
	case "amd64", "x86_64":
		auditArchVal = auditArchX86_64
	case "arm64", "aarch64":
		auditArchVal = auditArchAArch64
	default:
		return nil, fmt.Errorf("selfseccomp.Compile: unsupported arch %q", arch)
	}

	defaultAction := retLog
	if a.Mode == ModeEnforce {
		defaultAction = retErrno | errnoEPERM
	}

	var prog []instruction

	// Step 1: load + check arch.
	prog = append(prog,
		instruction{Code: bpfLD | bpfW | bpfABS, K: offsetArch},
		instruction{Code: bpfJMP | bpfJEQ | bpfK, K: auditArchVal, JT: 1, JF: 0},
		// arch mismatch → default action (denied)
		instruction{Code: bpfRET | bpfK, K: defaultAction},
	)

	// Step 2: load syscall NR.
	prog = append(prog,
		instruction{Code: bpfLD | bpfW | bpfABS, K: offsetNR},
	)

	// Step 3: for each allowed NR, jump to ALLOW. Use a tail-block
	// with a single RET_ALLOW that all entries jump to. Each JEQ
	// instruction with JT=offset-to-allow-block, JF=0 (fall through).
	// We append the RET_ALLOW block at the end, then patch jump
	// offsets.
	jumpFromIdx := make([]int, len(a.Numbers))
	for i, nr := range a.Numbers {
		prog = append(prog,
			instruction{Code: bpfJMP | bpfJEQ | bpfK, K: nr, JT: 0, JF: 0},
		)
		jumpFromIdx[i] = len(prog) - 1
	}

	// Step 4: default action (after all NR checks fall through).
	prog = append(prog, instruction{Code: bpfRET | bpfK, K: defaultAction})

	// Step 5: RET_ALLOW landing pad.
	allowIdx := len(prog)
	prog = append(prog, instruction{Code: bpfRET | bpfK, K: retAllow})

	// Step 6: patch each JEQ's JT to point to allowIdx.
	for _, i := range jumpFromIdx {
		offset := allowIdx - i - 1
		if offset < 0 || offset > 255 {
			// cBPF JT is a uint8. For very long allowlists we'd need
			// a different strategy; xhelix's syscall surface is far
			// under 255 entries so this assertion is safe.
			return nil, fmt.Errorf(
				"selfseccomp.Compile: jump offset out of range (%d). "+
					"allowlist too long for single-block layout", offset)
		}
		prog[i].JT = uint8(offset)
	}

	return prog, nil
}

// Apply compiles the allowlist for the host architecture and
// installs it. Caller is the xhelix main goroutine; we install on
// the calling thread but seccomp filters propagate to all threads
// when combined with PR_SET_NO_NEW_PRIVS (which Phase G.1 already
// set unconditionally).
//
// Apply respects a.Mode:
//   - ModeOff:     no-op, returns nil
//   - ModeAudit:   installs filter with RET_LOG as default
//   - ModeEnforce: installs filter with RET_ERRNO|EPERM as default
//
// On unsupported arch or kernel without seccomp, returns an error
// without installing anything. Caller must decide whether to abort
// or continue with no filter.
func Apply(a AllowList, log *slog.Logger) error {
	if a.Mode == ModeOff {
		if log != nil {
			log.Info("selfseccomp: mode=off; no filter installed")
		}
		return nil
	}
	if log != nil {
		log.Info("selfseccomp: compiling allowlist",
			"mode", a.Mode.String(),
			"syscall_count", len(a.Numbers))
	}
	return installForHost(a, log)
}
