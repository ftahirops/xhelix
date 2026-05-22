// Package modsig inspects host-level kernel-module-load defenses.
//
// Addresses the BYOVD-equivalent class on Linux: an attacker with
// root + CAP_SYS_MODULE who loads a malicious .ko can bypass every
// userspace EDR. xhelix can DETECT the module load (eBPF kprobe on
// init_module / finit_module) but cannot PREVENT it; prevention
// lives in the kernel's own module-signing + lockdown machinery.
//
// This package surfaces the relevant host state so operators can
// see how exposed they are and what they'd need to flip on.
//
// Read-only: nothing here mutates host state. Apply is intentionally
// out of scope — turning on module-signing-enforce is invasive
// (kernel cmdline, can lock out legitimate modules, requires reboot
// to undo wrong); it should remain an operator-driven step.
package modsig

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Status is the snapshot of host module-load defenses.
type Status struct {
	// ModuleSigEnforce: /sys/module/module/parameters/sig_enforce
	// "Y" = unsigned modules can't load. "N" = anything loads.
	ModuleSigEnforce string

	// Lockdown: /sys/kernel/security/lockdown
	// "[integrity]" or "[confidentiality]" = active. "[none]" = off.
	Lockdown string

	// SecureBootEnabled: mokutil --sb-state shows secure boot is on.
	// Tristate: "enabled", "disabled", "unknown" (mokutil missing /
	// EFI vars unreadable).
	SecureBoot string

	// CapSysModuleHolders enumerates non-root PIDs that have
	// CAP_SYS_MODULE in their effective capability set. Each entry
	// is "<pid> <comm> uid=<uid>".
	CapSysModuleHolders []string

	// PIDsScanned is the count of /proc/<pid>/status files
	// actually read (some go missing during the walk).
	PIDsScanned int
}

// Summary returns a one-line operator verdict.
func (s Status) Summary() string {
	var parts []string
	if s.ModuleSigEnforce == "Y" {
		parts = append(parts, "module_sig=enforced")
	} else {
		parts = append(parts, fmt.Sprintf("module_sig=%s(weak)", strOr(s.ModuleSigEnforce, "missing")))
	}
	// Active mode is bracketed: "[none] integrity confidentiality"
	// means none. Only [integrity] or [confidentiality] = strong.
	if strings.Contains(s.Lockdown, "[integrity]") || strings.Contains(s.Lockdown, "[confidentiality]") {
		parts = append(parts, "lockdown=on")
	} else {
		parts = append(parts, "lockdown=none(weak)")
	}
	switch s.SecureBoot {
	case "enabled":
		parts = append(parts, "secureboot=on")
	case "disabled":
		parts = append(parts, "secureboot=off(weak)")
	default:
		parts = append(parts, "secureboot=unknown")
	}
	if n := len(s.CapSysModuleHolders); n > 0 {
		parts = append(parts, fmt.Sprintf("cap_sys_module_holders=%d(check)", n))
	} else {
		parts = append(parts, "cap_sys_module_holders=0")
	}
	return strings.Join(parts, " ")
}

func strOr(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// Read inspects the live host state and returns a Status.
func Read() Status {
	st := Status{
		ModuleSigEnforce: readOne("/sys/module/module/parameters/sig_enforce"),
		Lockdown:         readOne("/sys/kernel/security/lockdown"),
		SecureBoot:       readSecureBoot(),
	}
	holders, n := scanCapSysModule()
	st.CapSysModuleHolders = holders
	st.PIDsScanned = n
	return st
}

// readOne reads a small sysfs/procfs scalar, trims whitespace, and
// returns "" on any error.
func readOne(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readSecureBoot calls `mokutil --sb-state`. Tri-state result.
//
// mokutil is the canonical Debian/Ubuntu tool. On systems without
// it (RHEL, Alpine, minimal containers), the EFI variable can also
// be checked directly at /sys/firmware/efi/efivars/SecureBoot-* but
// that's distro-specific. For now we accept "unknown" when mokutil
// is missing rather than guess.
func readSecureBoot() string {
	if _, err := exec.LookPath("mokutil"); err != nil {
		return "unknown"
	}
	cmd := exec.Command("mokutil", "--sb-state")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// mokutil exits non-zero when EFI vars unreadable
		// (e.g. legacy BIOS or container). That's "unknown".
		return "unknown"
	}
	s := strings.ToLower(string(out))
	if strings.Contains(s, "secureboot enabled") {
		return "enabled"
	}
	if strings.Contains(s, "secureboot disabled") || strings.Contains(s, "this system doesn't support") {
		return "disabled"
	}
	return "unknown"
}

// scanCapSysModule walks /proc and lists every non-root PID whose
// effective capability set contains CAP_SYS_MODULE (bit 16).
//
// Returns (entries, pids_scanned). Entries are formatted strings
// for human display: "<pid> <comm> uid=<uid>".
//
// Performance: ~5-15ms for 200 PIDs. Done on operator demand only
// (xhelixctl posture modsig), not on every alert.
func scanCapSysModule() ([]string, int) {
	const capSysModule = 16
	const mask = uint64(1) << capSysModule

	var hits []string
	scanned := 0
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, 0
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		statusPath := filepath.Join("/proc", e.Name(), "status")
		f, err := os.Open(statusPath)
		if err != nil {
			continue
		}
		var capEff uint64
		var uid uint64
		var comm string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "Name:"):
				comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			case strings.HasPrefix(line, "Uid:"):
				fs := strings.Fields(line)
				if len(fs) >= 2 {
					uid, _ = strconv.ParseUint(fs[1], 10, 32)
				}
			case strings.HasPrefix(line, "CapEff:"):
				hexVal := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
				v, err := strconv.ParseUint(hexVal, 16, 64)
				if err == nil {
					capEff = v
				}
			}
		}
		f.Close()
		scanned++
		if uid == 0 {
			// Root has all caps by default — not interesting.
			continue
		}
		if capEff&mask == 0 {
			continue
		}
		hits = append(hits, fmt.Sprintf("pid=%d comm=%s uid=%d", pid, comm, uid))
	}
	return hits, scanned
}

// FormatStatus pretty-prints a Status for `xhelixctl posture modsig`.
func FormatStatus(s Status) string {
	var b bytes.Buffer
	fmt.Fprintln(&b, "kernel module-load defenses")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  module signing enforced  (sig_enforce):     %s   (want Y)\n", strOr(s.ModuleSigEnforce, "n/a"))
	fmt.Fprintf(&b, "  kernel lockdown          (security/lockdown): %s   (want integrity or confidentiality)\n", strOr(s.Lockdown, "n/a"))
	fmt.Fprintf(&b, "  secure boot              (mokutil):          %s   (want enabled)\n", s.SecureBoot)
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "  non-root CAP_SYS_MODULE holders: %d (scanned %d PIDs)\n",
		len(s.CapSysModuleHolders), s.PIDsScanned)
	for _, h := range s.CapSysModuleHolders {
		fmt.Fprintf(&b, "    ! %s\n", h)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Summary:", s.Summary())
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Honest note: xhelix DETECTS kernel module loads (eBPF kprobe on")
	fmt.Fprintln(&b, "init_module / finit_module) but does NOT PREVENT them. Prevention")
	fmt.Fprintln(&b, "lives in the kernel — enabling module signing + lockdown + secure")
	fmt.Fprintln(&b, "boot raises the BYOVD-equivalent attack cost from 'load and own'")
	fmt.Fprintln(&b, "to 'find or sign a malicious kernel module' (much higher bar).")
	return b.String()
}
