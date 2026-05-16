package doctor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// fsChecks audit mount options and well-known sensitive files. The
// theme: an attacker with code-exec wants somewhere writable AND
// executable AND not noticed. Hardening mount options removes those
// places.
func fsChecks() []Check {
	return []Check{
		mountOptionCheck("/tmp", "nodev,nosuid,noexec",
			SeverityHigh,
			"/tmp is the most-staged-from directory in modern Linux exploits. nodev+nosuid+noexec on it removes the easy 'drop binary, run binary' path.",
			"Without these, `cp /tmp/payload /tmp/x && /tmp/x` works. With them, /tmp can hold the file but the kernel refuses to exec it.",
		),
		mountOptionCheck("/var/tmp", "nodev,nosuid,noexec",
			SeverityHigh,
			"Same reasoning as /tmp. Some installers use /var/tmp; check noexec breaks them in your environment before applying.",
			"A common fallback once /tmp is locked down.",
		),
		mountOptionCheck("/dev/shm", "nodev,nosuid,noexec",
			SeverityHigh,
			"shared-memory tmpfs. Frequently used as an in-memory drop site (no fs trace) for malware staging.",
			"Letting code execute from /dev/shm gives attackers a 'memory-only' loader path that sidesteps FIM.",
		),
		mountOptionCheck("/home", "nodev",
			SeverityLow,
			"At least nodev — no device files in user homes. nosuid is recommended too where compatible with user workflows.",
			"Device files in user homes are an old-school escalation primitive (cp /dev/sda ~/disk).",
		),
		{
			ID:       "fs.world_writable_etc",
			Title:    "No world-writable files in /etc",
			Category: "fs",
			Severity: SeverityCritical,
			Description: "World-writable files under /etc let any local user persist or backdoor system config.",
			Impact:      "An attacker with any uid can append a NOPASSWD sudo rule, modify cron, replace systemd unit, etc. depending on which file is writable.",
			Recommendation: "`find /etc -xdev -type f -perm -0002 -print` then chmod o-w each one.",
			FixCommand:     "find /etc -xdev -type f -perm -0002 -exec chmod o-w {} +",
			Run: func(_ context.Context) Result {
				bad, err := worldWritableUnder("/etc")
				if err != nil {
					return ErrorResult(err)
				}
				if len(bad) == 0 {
					return PassResult("no world-writable files under /etc")
				}
				return FailResult(fmt.Sprintf("%d world-writable: %s",
					len(bad), strings.Join(truncate(bad, 5), ", ")))
			},
			Apply: func(_ context.Context) error {
				bad, err := worldWritableUnder("/etc")
				if err != nil {
					return err
				}
				for _, p := range bad {
					st, err := os.Stat(p)
					if err != nil {
						continue
					}
					_ = os.Chmod(p, st.Mode().Perm()&^0o002)
				}
				return nil
			},
		},
		{
			ID:       "fs.tmp_sticky",
			Title:    "/tmp has sticky bit (1777)",
			Category: "fs",
			Severity: SeverityMedium,
			Description: "Sticky bit on /tmp prevents users from deleting each other's files — basic multi-user hygiene.",
			Impact:      "Without sticky, any user can delete or replace any other user's files in /tmp, enabling file-replacement races against legit programs.",
			Recommendation: "`chmod 1777 /tmp`",
			FixCommand:     "chmod 1777 /tmp",
			Run: func(_ context.Context) Result {
				st, err := os.Stat("/tmp")
				if err != nil {
					return ErrorResult(err)
				}
				mode := st.Mode()
				if mode.Perm() == 0o777 && mode&os.ModeSticky != 0 {
					return PassResult("/tmp = 1777")
				}
				return FailResult(fmt.Sprintf("/tmp mode = %o sticky=%t", mode.Perm(), mode&os.ModeSticky != 0))
			},
			Apply: func(_ context.Context) error {
				return os.Chmod("/tmp", 0o1777)
			},
		},
		{
			ID:       "fs.ld_so_preload_absent",
			Title:    "/etc/ld.so.preload absent or empty",
			Category: "fs",
			Severity: SeverityHigh,
			Description: "ld.so.preload forces a library to load into every dynamic binary on the system. Legitimate uses are rare; rootkit uses are not.",
			Impact:      "An attacker who can write here gets code execution in every userspace binary at startup. Bashbug-class compromise.",
			Recommendation: "If you didn't set it, delete it: `rm /etc/ld.so.preload`. Audit content if your distro ships one (some don't).",
			FixCommand:     "[ -s /etc/ld.so.preload ] && cp /etc/ld.so.preload /etc/ld.so.preload.bak; : > /etc/ld.so.preload",
			Risky:          true,
			Run: func(_ context.Context) Result {
				if !pathExists("/etc/ld.so.preload") {
					return PassResult("absent")
				}
				st, err := os.Stat("/etc/ld.so.preload")
				if err != nil {
					return ErrorResult(err)
				}
				if st.Size() == 0 {
					return PassResult("present but empty")
				}
				body, _ := os.ReadFile("/etc/ld.so.preload")
				return FailResult("non-empty: " + strings.TrimSpace(string(body)))
			},
		},
		{
			ID:       "fs.core_pattern_safe",
			Title:    "core_pattern doesn't pipe to a binary",
			Category: "fs",
			Severity: SeverityHigh,
			Description: "kernel.core_pattern starting with `|` runs the named binary on every coredump. Notorious LPE primitive (Dirty Pipe variants).",
			Impact:      "If core_pattern points to a writable path, any user-triggered crash gives the kernel a binary to exec on the user's behalf.",
			Recommendation: "Set kernel.core_pattern to a static path like `/var/lib/systemd/coredump/core.%e.%p` and ensure the helper if any is owned by root.",
			Run: func(_ context.Context) Result {
				v, err := readSysctl("kernel.core_pattern")
				if err != nil {
					return ErrorResult(err)
				}
				if !strings.HasPrefix(v, "|") {
					return PassResult("core_pattern = " + v)
				}
				return WarnResult("core_pattern pipes: " + v + " (verify owner+perms of the helper)")
			},
		},
	}
}

// mountOptionCheck verifies that a mountpoint has all required options.
func mountOptionCheck(mp, want string, sev Severity, descr, impact string) Check {
	wants := strings.Split(want, ",")
	return Check{
		ID:       "fs.mount." + strings.Trim(strings.ReplaceAll(mp, "/", "."), "."),
		Title:    fmt.Sprintf("%s mounted with %s", mp, want),
		Category: "fs",
		Severity: sev,
		Description: descr,
		Impact:      impact,
		Recommendation: fmt.Sprintf("Add %s to %s in /etc/fstab and remount: `mount -o remount,%s %s`", want, mp, want, mp),
		Risky:          true, // remount can fail with EBUSY; operator should plan
		Run: func(_ context.Context) Result {
			opts, err := mountOptions(mp)
			if err != nil {
				return SkipResult("mountpoint not present or unreadable")
			}
			missing := []string{}
			for _, w := range wants {
				if !containsOpt(opts, w) {
					missing = append(missing, w)
				}
			}
			if len(missing) == 0 {
				return PassResult(mp + " options: " + strings.Join(opts, ","))
			}
			return FailResult(fmt.Sprintf("%s missing: %s (current: %s)",
				mp, strings.Join(missing, ","), strings.Join(opts, ",")))
		},
	}
}

func mountOptions(mp string) ([]string, error) {
	f, err := os.Open("/proc/self/mounts")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// dev mountpoint type opts dump pass
		if len(fields) >= 4 && fields[1] == mp {
			return strings.Split(fields[3], ","), nil
		}
	}
	return nil, fmt.Errorf("not a mountpoint: %s", mp)
}

func containsOpt(opts []string, want string) bool {
	for _, o := range opts {
		if o == want {
			return true
		}
	}
	return false
}

// worldWritableUnder lists files under root that have the world-write
// bit set. Skips symlinks (mode of the link itself, not the target).
func worldWritableUnder(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		if info.Mode().Perm()&0o002 != 0 {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

func truncate(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	out := append([]string{}, s[:n]...)
	out = append(out, fmt.Sprintf("(+%d more)", len(s)-n))
	return out
}

// _ ensures bufio is referenced even when this file's only user of it
// is in a build that elides certain blocks.
var _ = bufio.NewReader
var _ context.Context
