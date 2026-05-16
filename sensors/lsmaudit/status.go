package lsmaudit

import (
	"os"
	"os/exec"
	"strings"
)

// Status describes the state of supported LSMs at agent startup.
//
// Returned by Detect() and surfaced on the TUI Overview page so an
// operator can see at a glance whether their host is running with
// AppArmor / SELinux / BPF LSM as expected.
type Status struct {
	Active        []string // every LSM listed in /sys/kernel/security/lsm
	HasAppArmor   bool
	AppArmorMode  string // "enforce" | "complain" | "disable" | "" if unknown
	HasSELinux    bool
	SELinuxMode   string // "Enforcing" | "Permissive" | "Disabled" | "" if unknown
	HasBPFLSM     bool
}

// Detect inspects the host's LSM state.
//
// Errors are absorbed: a partially-known status is more useful than
// a failure. Callers should always render Detect()'s output even if
// some fields remain empty.
func Detect() Status {
	st := Status{}
	if body, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		st.Active = strings.Split(strings.TrimSpace(string(body)), ",")
		for _, name := range st.Active {
			switch name {
			case "apparmor":
				st.HasAppArmor = true
			case "selinux":
				st.HasSELinux = true
			case "bpf":
				st.HasBPFLSM = true
			}
		}
	}

	if st.HasAppArmor {
		st.AppArmorMode = readAppArmorMode()
	}
	if st.HasSELinux {
		st.SELinuxMode = readSELinuxMode()
	}
	return st
}

func readAppArmorMode() string {
	if _, err := os.Stat("/sys/module/apparmor/parameters/enabled"); err != nil {
		return ""
	}
	body, _ := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	if strings.TrimSpace(string(body)) == "Y" {
		// `aa-status` gives detailed mode; fall back to a coarse
		// "enforce" if not available.
		if _, err := exec.LookPath("aa-status"); err == nil {
			out, err := exec.Command("aa-status", "--enabled").CombinedOutput()
			if err == nil {
				if strings.Contains(string(out), "complain") {
					return "complain"
				}
				return "enforce"
			}
		}
		return "enforce"
	}
	return "disable"
}

func readSELinuxMode() string {
	body, err := os.ReadFile("/sys/fs/selinux/enforce")
	if err != nil {
		// SELinux disabled at boot may not expose this file
		if _, err := os.Stat("/etc/selinux/config"); err == nil {
			cfg, _ := os.ReadFile("/etc/selinux/config")
			for _, line := range strings.Split(string(cfg), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "SELINUX=") {
					mode := strings.TrimPrefix(line, "SELINUX=")
					switch mode {
					case "enforcing":
						return "Enforcing"
					case "permissive":
						return "Permissive"
					case "disabled":
						return "Disabled"
					}
				}
			}
		}
		return ""
	}
	switch strings.TrimSpace(string(body)) {
	case "1":
		return "Enforcing"
	case "0":
		return "Permissive"
	}
	return ""
}

// Summary returns a one-line human-readable description.
func (s Status) Summary() string {
	parts := []string{}
	if s.HasBPFLSM {
		parts = append(parts, "BPF-LSM")
	}
	if s.HasAppArmor {
		mode := s.AppArmorMode
		if mode == "" {
			mode = "?"
		}
		parts = append(parts, "AppArmor="+mode)
	}
	if s.HasSELinux {
		mode := s.SELinuxMode
		if mode == "" {
			mode = "?"
		}
		parts = append(parts, "SELinux="+mode)
	}
	if len(parts) == 0 {
		return "no supported LSMs detected"
	}
	return strings.Join(parts, ", ")
}
