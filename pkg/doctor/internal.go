package doctor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// readSysctl reads a kernel sysctl by file path under /proc/sys.
// Returns trimmed value and error.
func readSysctl(key string) (string, error) {
	p := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// runOutput runs a command with a 5s timeout and returns trimmed stdout.
// stderr is ignored unless the command fails.
func runOutput(ctx context.Context, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// runCombined returns combined stdout+stderr.
func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// pathExists is fs.Stat reduced to a bool.
func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// commandExists tells whether the binary is on PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// applySysctl writes value to /proc/sys/<key> AND persists it to
// /etc/sysctl.d/99-xhelix.conf so it survives reboot.
//
// Both arguments are guarded against newline / null injection: a
// crafted value like "0\nnet.ipv4.ip_forward = 1" would inject an
// entirely new sysctl directive into the persistent file. The current
// callers are all internal Apply closures with hard-coded values, but
// the guard is defence-in-depth for any future config-driven path.
func applySysctl(key, value string) error {
	if strings.ContainsAny(key, "\n\r\x00") || strings.ContainsAny(value, "\n\r\x00") {
		return fmt.Errorf("applySysctl: invalid character in key/value")
	}
	runtime := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if err := os.WriteFile(runtime, []byte(value), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", runtime, err)
	}
	return appendSysctlConf(key, value)
}

func appendSysctlConf(key, value string) error {
	const conf = "/etc/sysctl.d/99-xhelix.conf"
	// Read existing, drop any prior line for this key, append new.
	old, _ := os.ReadFile(conf)
	var kept []string
	for _, line := range strings.Split(string(old), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			kept = append(kept, line)
			continue
		}
		if eq := strings.IndexByte(t, '='); eq > 0 {
			k := strings.TrimSpace(t[:eq])
			if k == key {
				continue
			}
		}
		kept = append(kept, line)
	}
	kept = append(kept, fmt.Sprintf("%s = %s", key, value))
	body := strings.Join(kept, "\n")
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	return os.WriteFile(conf, []byte(body), 0o644)
}
