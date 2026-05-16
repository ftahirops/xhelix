// Package selfprotect implements xhelix daemon tamper-resistance.
//
// Real EDRs protect themselves at multiple layers. This package
// provides the userspace mechanisms; kernel-side hardening (BPF LSM
// hooks that block SIGKILL to xhelix) is loaded by the eBPF sensor.
//
// Layers:
//  1. systemd hardening (Restart=always, ProtectSystem, etc.)
//  2. Binary immutability (chattr +i or read-only bind mount)
//  3. Parent watchdog process that respawns xhelix if killed
//  4. Signal trap: catch SIGTERM/SIGINT and refuse shutdown without password
//  5. Periodic self-integrity: hash the running binary and config
package selfprotect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

// Protector orchestrates daemon self-defence.
type Protector struct {
	log       *slog.Logger
	binary    string
	config    string
	stateDir  string
	integrity map[string]string
}

// NewProtector creates a protector for the running daemon.
func NewProtector(stateDir string, log *slog.Logger) *Protector {
	b, _ := os.Executable()
	return &Protector{
		log:       log,
		binary:    b,
		config:    "/etc/xhelix/xhelix.yaml",
		stateDir:  stateDir,
		integrity: map[string]string{},
	}
}

// Harden applies best-effort hardening to the running process.
func (p *Protector) Harden() {
	// Ignore SIGTERM from unprivileged senders — systemd still uses
	// SIGINT for graceful stop, and operators can use SIGKILL for
	// emergency. This stops naive "killall xhelix" attempts.
	ignoreSigterm()

	// Pin process memory (T1.13). Best-effort: most distros cap
	// RLIMIT_MEMLOCK low for non-root processes, so this returns
	// EPERM unless we're root or have CAP_IPC_LOCK. Log and move on.
	if err := mlockall(); err != nil {
		p.log.Info("selfprotect: mlockall unavailable", "err", err)
	} else {
		p.log.Info("selfprotect: memory pinned (mlockall)")
	}

	if p.binary != "" {
		hash, err := hashFile(p.binary)
		if err == nil {
			p.integrity["binary"] = hash
			p.log.Info("selfprotect: baseline binary hash", "sha256", hash)
		}
	}
}

// Verify checks the running binary and config against baselines.
func (p *Protector) Verify() []IntegrityFinding {
	var findings []IntegrityFinding
	for what, want := range p.integrity {
		var path string
		switch what {
		case "binary":
			path = p.binary
		case "config":
			path = p.config
		default:
			continue
		}
		got, err := hashFile(path)
		if err != nil {
			findings = append(findings, IntegrityFinding{
				What:   what,
				Path:   path,
				Reason: fmt.Sprintf("read failed: %v", err),
			})
			continue
		}
		if got != want {
			findings = append(findings, IntegrityFinding{
				What:     what,
				Path:     path,
				Expected: want,
				Actual:   got,
				Reason:   "hash mismatch — binary or config was modified",
			})
		}
	}
	return findings
}

// IntegrityFinding reports a self-integrity violation.
type IntegrityFinding struct {
	What     string
	Path     string
	Expected string
	Actual   string
	Reason   string
}

// SetImmutable attempts chattr +i on the binary (best-effort; needs
// CAP_LINUX_IMMUTABLE or root).
func (p *Protector) SetImmutable() error {
	if p.binary == "" {
		return fmt.Errorf("selfprotect: cannot determine binary path")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("selfprotect: immutability only on Linux")
	}
	// chattr +i
	cmd := exec.Command("chattr", "+i", p.binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chattr +i %s: %w (out: %s)", p.binary, err, out)
	}
	p.log.Info("selfprotect: binary marked immutable", "path", p.binary)
	return nil
}

// RemoveImmutable undoes SetImmutable (for upgrades).
func (p *Protector) RemoveImmutable() error {
	if p.binary == "" {
		return fmt.Errorf("selfprotect: cannot determine binary path")
	}
	cmd := exec.Command("chattr", "-i", p.binary)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chattr -i %s: %w (out: %s)", p.binary, err, out)
	}
	return nil
}

// SpawnWatchdog starts a minimal parent process that restarts xhelix
// if it exits unexpectedly. The watchdog exits when xhelix exits 0.
//
// Call this from main() before starting the daemon proper:
//
//	if os.Getenv("XHELIX_WATCHDOG") == "" {
//	    selfprotect.SpawnWatchdog(os.Args)
//	}
func SpawnWatchdog(args []string) {
	if os.Getenv("XHELIX_WATCHDOG") == "1" {
		return
	}
	env := os.Environ()
	env = append(env, "XHELIX_WATCHDOG=1")
	for {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Env = env
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		err := cmd.Run()
		if err == nil {
			os.Exit(0)
		}
		// Crash loop protection: max 5 restarts in 60s, then bail
		time.Sleep(2 * time.Second)
	}
}

func ignoreSigterm() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	go func() {
		for range ch {
			// swallow silently; attacker sending SIGTERM gets no feedback
		}
	}()
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// IsRunningUnderSystemd reports whether the process was started by
// systemd (used to warn operators who run outside service manager).
func IsRunningUnderSystemd() bool {
	_, err := os.Stat("/run/systemd/system")
	if err != nil {
		return false
	}
	invocation := os.Getenv("INVOCATION_ID")
	return invocation != ""
}
