// Package bpflsm is the Phase I (BPF-LSM synchronous deny) userspace
// loader.
//
// The kernel-side program (sensors/ebpf/progs/bpflsm.bpf.c) attaches
// to the LSM `bprm_check_security` hook and returns -EPERM when the
// execve target path is in the per-host deny map. This package owns:
//
//   - Probe — is BPF-LSM enabled in the kernel LSM chain?
//   - Load — open the compiled object via cilium/ebpf
//   - Attach — bind the program to the LSM hook
//   - Update — userspace API to add/remove deny entries
//   - Modes — off / load-only / enforce
//
// Modes:
//
//	ModeOff      no load, no attach (default — safest)
//	ModeLoad     load the program but do NOT attach. Operator
//	             preview; no kernel-side effect.
//	ModeEnforce  load + attach. Subsequent execve to any path in
//	             the deny map returns -EPERM synchronously.
//
// HARD PREREQUISITE: kernel cmdline must include `bpf` in the
// `lsm=...` list. xhelix probes at startup; if absent, refuses to
// promote past ModeOff and emits an operator-actionable error with
// the exact grub-update command.
package bpflsm

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// Mode is the install policy.
type Mode int

const (
	ModeOff Mode = iota
	ModeLoad
	ModeEnforce
)

// String for logging.
func (m Mode) String() string {
	switch m {
	case ModeOff:
		return "off"
	case ModeLoad:
		return "load-only"
	case ModeEnforce:
		return "enforce"
	}
	return "unknown"
}

// ParseMode parses an operator-supplied string. Unrecognized → ModeOff.
func ParseMode(s string) Mode {
	switch s {
	case "load", "load-only", "audit", "preview":
		return ModeLoad
	case "enforce":
		return ModeEnforce
	}
	return ModeOff
}

// Probe reports whether BPF-LSM is enabled in the kernel LSM chain.
// Reads /sys/kernel/security/lsm; returns true if "bpf" is present in
// the comma-separated list.
//
// This is the canonical pre-flight check before Load() / Attach().
// Returns false + nil error if the file exists but bpf isn't enabled
// (operator-actionable). Returns false + error if /sys/kernel/security
// isn't mounted at all (rare; usually means securityfs disabled).
func Probe() (active bool, err error) {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false, fmt.Errorf("read /sys/kernel/security/lsm: %w", err)
	}
	lsms := strings.Split(strings.TrimSpace(string(data)), ",")
	for _, l := range lsms {
		if strings.TrimSpace(l) == "bpf" {
			return true, nil
		}
	}
	return false, nil
}

// Loader is the userspace handle to the loaded + attached LSM program.
// Returned by Apply when mode != Off and the load succeeds.
type Loader struct {
	mode Mode
	log  *slog.Logger
	// closer cleans up the cilium/ebpf collection on Close.
	closer func() error
	// updater pushes a path into the deny map.
	updater func(path string) error
	// remover deletes a path from the deny map.
	remover func(path string) error
}

// Mode returns the active mode this loader was constructed with.
func (l *Loader) Mode() Mode { return l.mode }

// DenyPath adds `path` to the kernel deny map. Returns nil if the
// path is already present.
func (l *Loader) DenyPath(path string) error {
	if l.updater == nil {
		return fmt.Errorf("bpflsm: loader has no active map updater (mode=%s)", l.mode)
	}
	return l.updater(path)
}

// AllowPath removes `path` from the kernel deny map.
func (l *Loader) AllowPath(path string) error {
	if l.remover == nil {
		return fmt.Errorf("bpflsm: loader has no active map remover (mode=%s)", l.mode)
	}
	return l.remover(path)
}

// Close releases kernel resources (closes the BPF collection + the
// LSM link). Idempotent.
func (l *Loader) Close() error {
	if l.closer == nil {
		return nil
	}
	return l.closer()
}

// Apply loads + attaches the BPF-LSM program per mode. Returns the
// Loader (nil when mode==Off). On any error in pre-flight or attach,
// returns nil + error.
//
// Mode promotion path (operator):
//
//	mode=off       (default)
//	  ↓ verify kernel cmdline has lsm=...,bpf (Probe())
//	mode=load      (load only — no enforcement; verifies kernel + program compile)
//	  ↓ verify daemon survives + deny map populated correctly via xhelixctl
//	mode=enforce   (synchronous deny live)
func Apply(progPath string, mode Mode, log *slog.Logger) (*Loader, error) {
	if mode == ModeOff {
		if log != nil {
			log.Info("bpflsm: mode=off; not loading")
		}
		return nil, nil
	}
	active, err := Probe()
	if err != nil {
		return nil, fmt.Errorf("bpflsm: kernel LSM check failed: %w "+
			"(securityfs may not be mounted)", err)
	}
	if !active {
		return nil, fmt.Errorf("bpflsm: REFUSING to load — BPF-LSM is not in the active LSM chain. " +
			"Enable via: sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 lsm=lockdown,capability,landlock,yama,apparmor,bpf\"/' /etc/default/grub && sudo update-grub && reboot")
	}
	return loadAndAttach(progPath, mode, log)
}
