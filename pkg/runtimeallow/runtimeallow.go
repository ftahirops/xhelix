// Package runtimeallow holds the runtime-allowlist of well-known
// userland processes that legitimately exercise primitives xhelix
// treats as suspicious for unknown binaries — JIT compilers minting
// W+X memory pages (V8, HotSpot, .NET CoreCLR, LuaJIT, PyPy, BPF
// JIT), package managers writing to /etc/cron.d during install,
// container runtimes calling bpf() and unshare(), sudo gaining
// every capability by design.
//
// Rationale: most rules in pkg/response/policy.go cannot distinguish
// "attacker doing X" from "legitimate runtime doing X". The cheapest
// way to lower false-positive volume by orders of magnitude is to
// tag events whose parent image is a known runtime, then let rules
// branch on that tag.
//
// This is NOT a security boundary. An attacker who can rename their
// payload to /usr/bin/node bypasses the allowlist. The package_managed
// tag from the image-cache provides a stronger guarantee for that
// class. runtimeallow handles the "noise" axis; package_managed
// handles the "trust" axis. They compose.
//
// Added P-PS.25 after the mixed-traffic drill produced 242
// mem_mprotect_rwx FPs in 30s from node JIT, and 11 cap.gained FPs
// from operator sudo invocations.
package runtimeallow

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config holds the categorized glob patterns. A path matches if it
// matches any glob in any category. Categories exist for operator
// readability and per-category tuning later; matching is set-union.
type Config struct {
	JITEngines        []string `yaml:"jit_engines"`
	BuildSystems      []string `yaml:"build_systems"`
	CIRunners         []string `yaml:"ci_runners"`
	ContainerRuntimes []string `yaml:"container_runtimes"`
	CloudAgents       []string `yaml:"cloud_agents"`
	SystemTools       []string `yaml:"system_tools"`
}

// Set is a compiled allowlist. Safe for concurrent reads after
// construction; Reload swaps internal state under a mutex.
type Set struct {
	mu       sync.RWMutex
	patterns []string
	commSet  map[string]struct{}
}

// Default returns a baked-in allowlist covering the most-common
// runtimes. Operators extend via /etc/xhelix/runtime-allowlist.yaml.
func Default() Config {
	return Config{
		JITEngines: []string{
			"/usr/bin/node", "/usr/local/bin/node",
			"/root/.nvm/versions/node/*/bin/node",
			"/home/*/.nvm/versions/node/*/bin/node",
			"/usr/lib/jvm/*/bin/java",
			"/usr/bin/java", "/usr/local/bin/java",
			"/usr/bin/dotnet", "/usr/local/bin/dotnet",
			"/usr/share/dotnet/dotnet",
			"/usr/bin/lua*", "/usr/local/bin/lua*",
			"/usr/bin/python3*", "/usr/bin/python2*",
			"/usr/local/bin/python3*",
			"/opt/pypy*/bin/pypy*",
			"/usr/bin/PM2*",
			"/usr/lib/firefox/firefox",
			"/usr/lib/chromium/chromium",
			"/opt/google/chrome/chrome",
		},
		BuildSystems: []string{
			"/usr/bin/dpkg", "/usr/bin/dpkg-deb", "/usr/bin/dpkg-trigger",
			"/usr/bin/apt", "/usr/bin/apt-get", "/usr/bin/apt-cache",
			"/usr/bin/snap*", "/usr/lib/snapd/*",
			"/usr/bin/dnf", "/usr/bin/yum", "/usr/bin/rpm",
			"/usr/bin/zypper", "/usr/bin/pacman",
			"/usr/bin/pip", "/usr/bin/pip3",
			"/usr/local/bin/pip*",
			"/usr/bin/npm", "/usr/bin/yarn", "/usr/local/bin/npm",
			"/usr/bin/go", "/usr/local/go/bin/go",
			"/usr/bin/gcc*", "/usr/bin/g++*",
			"/usr/bin/make", "/usr/bin/cmake",
			"/usr/bin/ld*",
		},
		CIRunners: []string{
			"/usr/local/bin/buildkite-agent",
			"/usr/local/bin/github-runner",
			"/usr/local/bin/gitlab-runner",
			"/usr/bin/jenkins*",
		},
		ContainerRuntimes: []string{
			"/usr/bin/runc", "/usr/local/bin/runc",
			"/usr/bin/containerd*", "/usr/local/bin/containerd*",
			"/usr/bin/docker*", "/usr/local/bin/docker*",
			"/usr/bin/podman", "/usr/bin/crun",
			"/usr/sbin/dockerd",
		},
		CloudAgents: []string{
			"/usr/bin/snapd", "/usr/lib/snapd/snapd",
			"/usr/bin/amazon-ssm-agent",
			"/usr/sbin/google-osconfig-agent",
			"/usr/bin/cloud-init",
		},
		SystemTools: []string{
			// sudo gains every capability by design — must not count
			// as anomalous unless something downstream is suspicious.
			"/usr/bin/sudo", "/usr/local/bin/sudo",
			// systemd-related — frequently transitions caps.
			"/lib/systemd/systemd", "/usr/lib/systemd/systemd",
			"/lib/systemd/systemd-*", "/usr/lib/systemd/systemd-*",
			// Init / launchers.
			"/usr/bin/init", "/sbin/init",
			// P-PS.33: cron, system services, sysstat, named, mail.
			// Added after the plesk.douxl.com deploy surfaced these as
			// the day-1 FP cluster on a Plesk-managed host.
			"/usr/sbin/cron", "/usr/sbin/CRON", "/usr/bin/cron",
			"/usr/sbin/anacron",
			"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session",
			"/usr/sbin/postfix", "/usr/lib/postfix/sbin/*",
			"/usr/libexec/postfix/*",
			"/usr/sbin/dovecot", "/usr/lib/dovecot/*",
			"/usr/sbin/named", "/usr/sbin/rndc",
			"/usr/sbin/apache2", "/usr/sbin/httpd",
			"/usr/sbin/nginx",
			"/usr/sbin/sa1", "/usr/sbin/sa2",
			"/usr/lib/sysstat/*",
			"/usr/lib/policykit-1/*", "/usr/libexec/polkitd",
			"/usr/bin/qemu-ga", "/usr/sbin/qemu-ga",
			// Plesk-specific (Plesk-managed hosts).
			"/opt/plesk/php/*/sbin/*", "/opt/plesk/php/*/bin/*",
			"/opt/plesk/admin/*", "/opt/psa/admin/sbin/*",
			"/opt/psa/admin/bin/*",
			"/usr/lib/plesk-9.0/*",
			"/usr/local/psa/admin/sbin/*",
			// Imunify360 / ImunifyAV (paired with Plesk).
			"/usr/sbin/imunify-notifier",
			"/usr/libexec/imunify-notifier/*",
			"/opt/imunify360/*", "/opt/imunify-av/*",
			"/usr/lib/imunify360/*",
			// fail2ban-related (Plesk + standalone).
			"/usr/bin/fail2ban-server", "/usr/bin/fail2ban-client",
		},
	}
}

// New compiles a Config into a Set. Globs are normalized but no
// further work is done; matching uses filepath.Match per pattern.
func New(cfg Config) *Set {
	all := append([]string{}, cfg.JITEngines...)
	all = append(all, cfg.BuildSystems...)
	all = append(all, cfg.CIRunners...)
	all = append(all, cfg.ContainerRuntimes...)
	all = append(all, cfg.CloudAgents...)
	all = append(all, cfg.SystemTools...)

	// Derive a quick comm-set for the simple cases (basename of any
	// pattern that's a literal path). Lets us match on event.Comm
	// when event.ParentImage is empty, which happens for some sensors.
	commSet := make(map[string]struct{})
	for _, p := range all {
		if !strings.ContainsAny(p, "*?[") {
			commSet[filepath.Base(p)] = struct{}{}
		}
	}
	return &Set{patterns: all, commSet: commSet}
}

// LoadFile reads an allowlist YAML and overlays it on Default(). A
// missing file is not an error — Default() is returned.
func LoadFile(path string) (*Set, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(cfg), nil
		}
		return New(cfg), err
	}
	var override Config
	if err := yaml.Unmarshal(data, &override); err != nil {
		return New(cfg), err
	}
	// Merge: append override entries to default categories.
	cfg.JITEngines = append(cfg.JITEngines, override.JITEngines...)
	cfg.BuildSystems = append(cfg.BuildSystems, override.BuildSystems...)
	cfg.CIRunners = append(cfg.CIRunners, override.CIRunners...)
	cfg.ContainerRuntimes = append(cfg.ContainerRuntimes, override.ContainerRuntimes...)
	cfg.CloudAgents = append(cfg.CloudAgents, override.CloudAgents...)
	cfg.SystemTools = append(cfg.SystemTools, override.SystemTools...)
	return New(cfg), nil
}

// Match returns true if image matches any allowlist glob.
// Empty image is treated as no-match.
func (s *Set) Match(image string) bool {
	if s == nil || image == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, pat := range s.patterns {
		if ok, _ := filepath.Match(pat, image); ok {
			return true
		}
	}
	return false
}

// MatchComm returns true if comm matches the basename of any
// non-glob pattern. Use when image is unavailable.
//
// P-PS.33: Linux kernel + some readers wrap comm in parens when
// the process used PR_SET_NAME or when comm comes from
// /proc/PID/stat. Strip both forms before lookup so "(sa1)" and
// "sa1" both match the allowlist entry for "sa1".
func (s *Set) MatchComm(comm string) bool {
	if s == nil || comm == "" {
		return false
	}
	// Strip surrounding parens: "(sa1)" → "sa1"
	if len(comm) >= 2 && comm[0] == '(' && comm[len(comm)-1] == ')' {
		comm = comm[1 : len(comm)-1]
	}
	if comm == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.commSet[comm]
	return ok
}

// MatchAny returns true if either image or comm matches.
func (s *Set) MatchAny(image, comm string) bool {
	return s.Match(image) || s.MatchComm(comm)
}
