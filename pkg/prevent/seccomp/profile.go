package seccomp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// Instruction is one cBPF (classical BPF) seccomp filter instruction.
// Layout matches struct sock_filter from <linux/filter.h> exactly so
// we can hand the slice straight to the kernel.
//
// Defined locally (not unix.SockFilter) so this file builds on every
// platform — install_linux.go converts at the boundary.
type Instruction struct {
	Code uint16 // operation
	JT   uint8  // jump-true offset
	JF   uint8  // jump-false offset
	K    uint32 // immediate
}

// BPF opcode constants we need. Values from <linux/bpf_common.h> and
// <linux/seccomp.h>. Keeping these literal avoids dragging in unix.*
// types here.
const (
	bpfLD   uint16 = 0x00
	bpfJMP  uint16 = 0x05
	bpfRET  uint16 = 0x06
	bpfW    uint16 = 0x00
	bpfABS  uint16 = 0x20
	bpfJEQ  uint16 = 0x10
	bpfJGE  uint16 = 0x30
	bpfK    uint16 = 0x00
	bpfJUMP uint16 = bpfJMP | bpfJEQ | bpfK

	// SECCOMP_RET_*. Lower 16 bits of SECCOMP_RET_ERRNO carry errno.
	seccompRetAllow uint32 = 0x7fff0000
	seccompRetErrno uint32 = 0x00050000
	seccompRetKill  uint32 = 0x00000000

	// Offsets into struct seccomp_data — 8 bytes.
	offsetNR   uint32 = 0
	offsetArch uint32 = 4

	// errno EPERM (returned to the denied syscall).
	errnoEPERM uint32 = 1
)

// Profile is the compiled filter plus diagnostic metadata.
type Profile struct {
	Arch         Arch
	Instructions []Instruction
	// Denied is the list of syscall names that ARE in the filter.
	Denied []string
	// Skipped is the list of names from the contract that had no
	// known NR for this arch (so they couldn't be enforced).
	// Operators see this as a warning at install time — never
	// silent.
	Skipped []string
}

// Compile turns a ServiceContract.DenySyscalls list into a cBPF
// seccomp filter for the given arch. Filter semantics:
//
//  1. Verify seccomp_data.arch matches; on mismatch return EPERM
//     for every syscall (defends against 32-bit syscall bypass).
//  2. Compare seccomp_data.nr against each denied number; on match
//     return EPERM.
//  3. Default: SECCOMP_RET_ALLOW.
//
// EPERM (not KILL) is the right action for Ring 1 — the deception
// layer (Ring 2) wants the syscall to fail visibly so it can route
// the same intent to the trap. KILL would prevent that.
func Compile(c protectedsvc.ServiceContract, a Arch) (Profile, error) {
	auditArchVal, ok := auditArch(a)
	if !ok {
		return Profile{}, fmt.Errorf("seccomp: unsupported arch %q", a)
	}

	// Resolve syscall names to numbers, partition into known/unknown.
	denied := make(map[string]uint32)
	var skipped []string
	for _, name := range c.DenySyscalls {
		nr, ok := LookupSyscall(name, a)
		if !ok {
			skipped = append(skipped, name)
			continue
		}
		denied[name] = nr
	}

	// Deterministic order — same input → same filter bytes. Helps
	// caching at the kernel + reproducible install.
	deniedNames := make([]string, 0, len(denied))
	for name := range denied {
		deniedNames = append(deniedNames, name)
	}
	sort.Strings(deniedNames)

	var prog []Instruction

	// Block 1: arch check.
	//   ld  [arch_offset]
	prog = append(prog, Instruction{Code: bpfLD | bpfW | bpfABS, K: offsetArch})
	//   jne AUDIT_ARCH, deny, allow-fallthrough
	// We use JEQ with jt=skip-deny, jf=deny:
	//   jeq AUDIT_ARCH, 1, 0  ; if equal → skip the deny return
	//   ret EPERM             ; if not equal → deny
	prog = append(prog, Instruction{Code: bpfJUMP, JT: 1, JF: 0, K: auditArchVal})
	prog = append(prog, Instruction{Code: bpfRET | bpfK, K: seccompRetErrno | errnoEPERM})

	// Block 2: load syscall NR.
	prog = append(prog, Instruction{Code: bpfLD | bpfW | bpfABS, K: offsetNR})

	// Block 3: for each denied NR, jeq deny.
	for _, name := range deniedNames {
		nr := denied[name]
		// jeq NR, deny, next
		//   jeq NR, 0, 1   ; if equal → fall through to deny return
		//   ret EPERM
		//   ; next instruction
		prog = append(prog, Instruction{Code: bpfJUMP, JT: 0, JF: 1, K: nr})
		prog = append(prog, Instruction{Code: bpfRET | bpfK, K: seccompRetErrno | errnoEPERM})
	}

	// Block 4: default allow.
	prog = append(prog, Instruction{Code: bpfRET | bpfK, K: seccompRetAllow})

	return Profile{
		Arch:         a,
		Instructions: prog,
		Denied:       deniedNames,
		Skipped:      skipped,
	}, nil
}

// MaxLen is the kernel's seccomp filter length cap. Documented at
// 4096 since 3.x; values larger cause EINVAL on load.
const MaxLen = 4096

// Validate returns an error if the profile cannot be installed.
func (p Profile) Validate() error {
	if len(p.Instructions) == 0 {
		return fmt.Errorf("seccomp: empty filter")
	}
	if len(p.Instructions) > MaxLen {
		return fmt.Errorf("seccomp: filter too long (%d > %d)", len(p.Instructions), MaxLen)
	}
	if _, ok := auditArch(p.Arch); !ok {
		return fmt.Errorf("seccomp: invalid arch %q", p.Arch)
	}
	return nil
}

// SystemdDirective returns a `SystemCallFilter=` line suitable for a
// systemd unit drop-in. Useful for the production deployment path
// where xhelix installs a drop-in rather than supervising the
// service directly.
//
// Format: deny-list style (~name1 name2 ...). systemd interprets the
// leading "~" as "deny these, allow the rest".
//
// Returns "" if the contract has no DenySyscalls.
func SystemdDirective(c protectedsvc.ServiceContract) string {
	if len(c.DenySyscalls) == 0 {
		return ""
	}
	// systemd accepts syscall names regardless of arch — kernel
	// resolves at load time. We pass the names as given.
	names := make([]string, len(c.DenySyscalls))
	copy(names, c.DenySyscalls)
	sort.Strings(names)
	return "SystemCallFilter=~" + strings.Join(names, " ")
}

// Render returns a human-readable disassembly. Test-only, but cheap.
func (p Profile) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "; seccomp filter for %s (%d instr, deny %d, skipped %d)\n",
		p.Arch, len(p.Instructions), len(p.Denied), len(p.Skipped))
	for i, ins := range p.Instructions {
		fmt.Fprintf(&b, "%04d  code=%04x jt=%d jf=%d k=%08x\n", i, ins.Code, ins.JT, ins.JF, ins.K)
	}
	if len(p.Skipped) > 0 {
		fmt.Fprintf(&b, "; SKIPPED (unknown NR for arch): %s\n", strings.Join(p.Skipped, ", "))
	}
	return b.String()
}
