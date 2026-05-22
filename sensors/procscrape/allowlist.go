// Package procscrape policies and enriches kernel-emitted
// proc_scrape events.
//
// The kernel side (sensors/ebpf, XH_EV_PROC_SCRAPE) fires on any
// openat() against /proc/<pid>/{environ,maps,mem,auxv}. That feed
// is noisy — systemd, monit, ps, htop, journalctl and xhelix
// itself all read /proc legitimately. This package owns the
// allowlist that turns the raw signal into a credential-scrape
// alert.
//
// Policy lives here, not in the kernel program, so operators can
// extend the allowlist without rebuilding the BPF object.
package procscrape

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Allowlist describes the set of readers that may freely open
// /proc/<pid>/{environ,maps,mem,auxv} on PIDs other than their
// own without firing cred_proc_scrape.
//
// A reader matches when ANY of:
//   - its comm (16-char task name) equals a string in Comms
//   - its image path is in Images or matches a glob in ImageGlobs
//
// Same-PID self-reads (target_pid == reader_pid) are always
// allowed — those are the program reading its own /proc entry,
// which the kernel actually permits unconditionally.
type Allowlist struct {
	mu         sync.RWMutex
	Comms      map[string]struct{}
	Images     map[string]struct{}
	ImageGlobs []string
}

// Default returns the baked-in allowlist. Reflects what
// legitimately reads /proc on a Debian server + Plesk control
// panel. Operators can extend via LoadFile.
func Default() *Allowlist {
	a := &Allowlist{
		Comms:  map[string]struct{}{},
		Images: map[string]struct{}{},
	}
	// Comm names (16 chars, truncated kernel-side).
	for _, c := range []string{
		// xhelix's own surface — must self-allow.
		"xhelix", "xhelixctl", "xhelix-verify",
		"xhelix-watchdog", "xhelix-honeysh",
		"xhelix-sinkhole", "xhelix-dnspoiso",
		// init / service manager.
		"systemd", "init", "systemd-logind", "systemd-userdbd",
		"systemd-resolve", "systemd-network", "systemd-journal",
		// classic process inspection.
		"ps", "pgrep", "pidof", "top", "htop", "btop", "atop",
		"glances", "iotop", "nethogs",
		// monitoring agents commonly deployed.
		"monit", "telegraf", "node_exporter", "collectd", "zabbix_agentd",
		"prometheus", "consul",
		// container / cgroup tooling.
		"runc", "containerd", "containerd-shim", "docker", "dockerd",
		"crun", "podman", "kubelet",
		// gdb-class debuggers — root-only, but allowlisted to
		// avoid spurious alerts during operator debugging.
		"gdb", "strace", "ltrace",
		// kernel threads occasionally walk /proc.
		"kworker",
	} {
		a.Comms[c] = struct{}{}
	}
	// Image globs handled with filepath.Match.
	a.ImageGlobs = []string{
		"/usr/lib/xhelix/*",
		"/usr/local/bin/xhelix*",
		"/usr/lib/systemd/*",
	}
	return a
}

// LoadFile overlays YAML-like additions onto the allowlist.
// Format is intentionally minimal — one entry per line, prefixed:
//
//	comm: htop-vim
//	image: /opt/myagent/bin/agent
//	glob: /opt/security/*
//
// Comments start with '#'; blank lines ignored. Missing file is
// not an error (caller can rely on Default()).
func (a *Allowlist) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "comm":
			a.Comms[v] = struct{}{}
		case "image":
			a.Images[v] = struct{}{}
		case "glob":
			a.ImageGlobs = append(a.ImageGlobs, v)
		}
	}
	return sc.Err()
}

// IsAllowed reports whether a reader identified by (comm, image)
// is exempt from the cred_proc_scrape rule.
//
// Empty inputs are treated literally — an empty comm will not
// match an empty allowlist entry (we don't add empty keys in
// Default or LoadFile).
func (a *Allowlist) IsAllowed(comm, image string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if comm != "" {
		if _, ok := a.Comms[comm]; ok {
			return true
		}
	}
	if image != "" {
		if _, ok := a.Images[image]; ok {
			return true
		}
		for _, g := range a.ImageGlobs {
			if ok, _ := filepath.Match(g, image); ok {
				return true
			}
		}
	}
	return false
}

// Size returns the number of comm + image + glob entries. For
// Health reporting.
func (a *Allowlist) Size() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.Comms) + len(a.Images) + len(a.ImageGlobs)
}
