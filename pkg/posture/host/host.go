// Package host inspects host-level security posture for Phase G.5.
//
// Read-only: reads sysctls, /proc, /sys/kernel/security, and a few
// command outputs. Never modifies host state. Output is a structured
// Report that the daemon logs on startup and `xhelixctl posture host`
// renders for an operator.
//
// Each check returns one of: Pass / Warn / Fail / Unknown. "Warn" =
// the setting is not the recommended hardened value but isn't an
// immediate risk. "Fail" = a known weakening (e.g. ASLR disabled).
// "Unknown" = the source file/command isn't present on this host.
package host

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Status of a single check.
type Status string

const (
	StatusPass    Status = "PASS"
	StatusWarn    Status = "WARN"
	StatusFail    Status = "FAIL"
	StatusUnknown Status = "UNKNOWN"
)

// Check is one posture row.
type Check struct {
	Name     string // short identifier, e.g. "kernel.randomize_va_space"
	Status   Status
	Value    string // observed value or "" if unknown
	Expected string // what would PASS
	Hint     string // operator-actionable remediation
}

// Report is the full posture snapshot.
type Report struct {
	Checks []Check
}

// Counts returns PASS/WARN/FAIL/UNKNOWN tallies.
func (r Report) Counts() (pass, warn, fail, unk int) {
	for _, c := range r.Checks {
		switch c.Status {
		case StatusPass:
			pass++
		case StatusWarn:
			warn++
		case StatusFail:
			fail++
		default:
			unk++
		}
	}
	return
}

// Score returns an integer 0-100. PASS=1, WARN=0.5, FAIL=0,
// UNKNOWN excluded from denominator.
func (r Report) Score() int {
	pass, warn, fail, _ := r.Counts()
	n := pass + warn + fail
	if n == 0 {
		return 0
	}
	num := float64(pass) + 0.5*float64(warn)
	return int(num * 100.0 / float64(n))
}

// Inspect runs all G.5 checks and returns a Report.
func Inspect() Report {
	r := Report{}
	r.Checks = append(r.Checks, sysctlCheck("kernel.randomize_va_space", "2", "ASLR full"))
	r.Checks = append(r.Checks, sysctlCheck("kernel.kptr_restrict", "2", "hide kernel pointers"))
	r.Checks = append(r.Checks, sysctlCheck("kernel.dmesg_restrict", "1", "non-root cannot read dmesg"))
	r.Checks = append(r.Checks, sysctlCheck("kernel.yama.ptrace_scope", "1", "restrict ptrace to children"))
	r.Checks = append(r.Checks, sysctlCheck("kernel.unprivileged_bpf_disabled", "1", "block non-root BPF"))
	r.Checks = append(r.Checks, sysctlCheck("kernel.unprivileged_userns_clone", "0", "block unprivileged userns"))
	r.Checks = append(r.Checks, sysctlCheck("fs.protected_hardlinks", "1", "block hardlink pivots"))
	r.Checks = append(r.Checks, sysctlCheck("fs.protected_symlinks", "1", "block symlink pivots"))
	r.Checks = append(r.Checks, sysctlCheck("fs.protected_fifos", "2", "block FIFO pivots"))
	r.Checks = append(r.Checks, sysctlCheck("fs.protected_regular", "2", "block tmp-file pivots"))
	r.Checks = append(r.Checks, sysctlCheck("kernel.sysrq", "0", "disable SysRq"))
	r.Checks = append(r.Checks, sysctlCheck("kernel.core_pattern", "", "review core dump handling"))

	r.Checks = append(r.Checks, lockdownCheck())
	r.Checks = append(r.Checks, modSigEnforceCheck())
	r.Checks = append(r.Checks, secureBootCheck())
	r.Checks = append(r.Checks, bpfLSMCheck())
	r.Checks = append(r.Checks, landlockAvailableCheck())
	r.Checks = append(r.Checks, tmpfsHardenedCheck())
	return r
}

// sysctlCheck reads /proc/sys/<key> and compares to expected.
// If expected is empty, the value is reported as Warn (review).
func sysctlCheck(key, expected, hint string) Check {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	b, err := os.ReadFile(path)
	if err != nil {
		return Check{Name: key, Status: StatusUnknown, Expected: expected, Hint: hint}
	}
	val := strings.TrimSpace(string(b))
	st := StatusFail
	switch {
	case expected == "":
		st = StatusWarn
	case val == expected:
		st = StatusPass
	default:
		// For integer sysctls, accept any value ≥ expected as PASS
		// (stricter is fine). Falls back to FAIL on parse mismatch.
		if vi, e1 := strconv.Atoi(val); e1 == nil {
			if ei, e2 := strconv.Atoi(expected); e2 == nil && vi >= ei {
				st = StatusPass
			}
		}
	}
	return Check{Name: key, Status: st, Value: val, Expected: expected, Hint: hint}
}

func lockdownCheck() Check {
	b, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return Check{Name: "kernel.lockdown", Status: StatusUnknown,
			Hint: "set lockdown=integrity or =confidentiality in kernel cmdline"}
	}
	val := strings.TrimSpace(string(b))
	st := StatusFail
	switch {
	case strings.Contains(val, "[confidentiality]"):
		st = StatusPass
	case strings.Contains(val, "[integrity]"):
		st = StatusPass
	case strings.Contains(val, "[none]"):
		st = StatusWarn
	}
	return Check{Name: "kernel.lockdown", Status: st, Value: val,
		Expected: "[integrity] or [confidentiality]",
		Hint:     "add `lockdown=integrity` to GRUB_CMDLINE_LINUX"}
}

func modSigEnforceCheck() Check {
	b, err := os.ReadFile("/sys/module/module/parameters/sig_enforce")
	if err != nil {
		return Check{Name: "module.sig_enforce", Status: StatusUnknown,
			Hint: "enable CONFIG_MODULE_SIG_FORCE + module signing"}
	}
	val := strings.TrimSpace(string(b))
	st := StatusFail
	if val == "Y" {
		st = StatusPass
	}
	return Check{Name: "module.sig_enforce", Status: st, Value: val, Expected: "Y",
		Hint: "set module.sig_enforce=1 on kernel cmdline or distro kernel with CONFIG_MODULE_SIG_FORCE=y"}
}

func secureBootCheck() Check {
	out, err := exec.Command("mokutil", "--sb-state").CombinedOutput()
	if err != nil {
		return Check{Name: "uefi.secureboot", Status: StatusUnknown,
			Hint: "install mokutil; enable Secure Boot in UEFI"}
	}
	val := strings.TrimSpace(string(out))
	st := StatusFail
	if strings.Contains(val, "enabled") {
		st = StatusPass
	}
	return Check{Name: "uefi.secureboot", Status: st, Value: val, Expected: "SecureBoot enabled"}
}

func bpfLSMCheck() Check {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return Check{Name: "lsm.bpf_active", Status: StatusUnknown,
			Hint: "mount securityfs"}
	}
	val := strings.TrimSpace(string(b))
	st := StatusFail
	for _, lsm := range strings.Split(val, ",") {
		if lsm == "bpf" {
			st = StatusPass
			break
		}
	}
	return Check{Name: "lsm.bpf_active", Status: st, Value: val, Expected: "bpf in lsm list",
		Hint: "append ',bpf' to lsm= kernel cmdline (Phase I enforce prereq)"}
}

func landlockAvailableCheck() Check {
	if _, err := os.Stat("/sys/kernel/security/landlock"); err == nil {
		return Check{Name: "lsm.landlock_available", Status: StatusPass, Value: "present",
			Expected: "securityfs landlock dir present"}
	}
	// Fallback — landlock may be compiled-in but securityfs dir absent
	// on older kernels. The actual probe lives in pkg/landlock.
	return Check{Name: "lsm.landlock_available", Status: StatusWarn,
		Value: "securityfs dir missing", Expected: "/sys/kernel/security/landlock present",
		Hint: "kernel ≥ 5.13 with CONFIG_SECURITY_LANDLOCK=y"}
}

// tmpfsHardenedCheck looks at /proc/mounts for /tmp; expects
// noexec,nosuid,nodev.
func tmpfsHardenedCheck() Check {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return Check{Name: "fs.tmp_hardened", Status: StatusUnknown}
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[1] != "/tmp" {
			continue
		}
		opts := fields[3]
		ne := strings.Contains(opts, "noexec")
		ns := strings.Contains(opts, "nosuid")
		nd := strings.Contains(opts, "nodev")
		if ne && ns && nd {
			return Check{Name: "fs.tmp_hardened", Status: StatusPass, Value: opts,
				Expected: "noexec,nosuid,nodev"}
		}
		return Check{Name: "fs.tmp_hardened", Status: StatusFail, Value: opts,
			Expected: "noexec,nosuid,nodev",
			Hint:     "mount /tmp tmpfs with noexec,nosuid,nodev or use systemd PrivateTmp"}
	}
	return Check{Name: "fs.tmp_hardened", Status: StatusWarn, Value: "/tmp not a separate mount",
		Hint: "consider tmpfs /tmp with noexec,nosuid,nodev"}
}

// FormatText renders the report for terminal output.
func (r Report) FormatText() string {
	var b strings.Builder
	pass, warn, fail, unk := r.Counts()
	fmt.Fprintf(&b, "Host posture: score=%d/100  pass=%d warn=%d fail=%d unknown=%d\n\n",
		r.Score(), pass, warn, fail, unk)
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "  [%-7s] %-35s value=%q\n", c.Status, c.Name, c.Value)
		if c.Status == StatusFail || c.Status == StatusWarn {
			if c.Hint != "" {
				fmt.Fprintf(&b, "             hint: %s\n", c.Hint)
			}
		}
	}
	return b.String()
}
