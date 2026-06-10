// Package redzones defines the web-worker red zone policy — the set of
// behaviours that are NEVER learnable and must always be blocked for
// processes spawned by web-facing services (nginx, php-fpm, node, etc.).
//
// These are not BRP behavioural baselines. They are unconditional hard
// denials derived from first principles: a web server process has zero
// legitimate reason to spawn /bin/sh, write to /etc/systemd/, or call
// ptrace(). No training window changes this.
//
// Consumers:
//   - cmd/xhelix/run.go  — merges WebWorkerExecRules() into execguard
//   - ruleset/core/redzones.yaml — CEL rules for file/read red zones
//   - (future) pkg/seccompprofile — syscall deny filter generation
package redzones

import (
	"github.com/xhelix/xhelix/pkg/execguard"
)

// Policy holds the per-category red zone sets for web-worker processes.
type Policy struct {
	// ExecPaths are absolute binary paths that web workers must never
	// exec. Entries ending in '*' are treated as prefix matches.
	ExecPaths []string

	// WriteZones are path prefixes where web workers must never write or
	// create files. Used for CEL rule generation and future enforcement.
	WriteZones []string

	// ReadZones are path prefixes containing secrets that web workers
	// must never read. Detection-only for Phase 1.
	ReadZones []string

	// DenySyscalls are Linux syscall names that web workers must never
	// invoke. Detection-only for Phase 1; seccomp enforcement is Phase 3.
	DenySyscalls []string
}

// Default returns the canonical web-worker red zone policy. This is
// the baseline applied to all web-facing service cgroups when the
// operator has not configured an override.
func Default() *Policy {
	return &Policy{
		ExecPaths: []string{
			// Shells
			"/bin/sh",
			"/bin/bash",
			"/bin/dash",
			"/usr/bin/sh",
			"/usr/bin/bash",
			"/usr/bin/dash",
			// Download / transfer tools
			"/usr/bin/curl",
			"/usr/bin/wget",
			// Scripting interpreters
			"/usr/bin/python*", // prefix — catches python3, python3.11, …
			"/usr/bin/python3",
			"/usr/bin/python",
			"/usr/bin/node",
			"/usr/bin/nodejs",
			"/usr/bin/php",
			"/usr/bin/perl",
			"/usr/bin/ruby",
			// Network tools
			"/usr/bin/nc",
			"/usr/bin/ncat",
			"/usr/bin/netcat",
			"/usr/bin/nmap",
			"/usr/bin/socat",
			// Encoder/decode tools (common in C2 payloads)
			"/usr/bin/base64",
			"/usr/bin/xxd",
		},
		WriteZones: []string{
			// Privilege escalation paths
			"/root/",
			"/etc/sudoers",
			"/etc/sudoers.d/",
			// Dynamic linker injection
			"/etc/ld.so.preload",
			// Persistence paths (cron covered by existing file.yaml rules)
			"/etc/systemd/system/",
			"/etc/systemd/user/",
			// Library injection vectors
			"/lib/",
			"/lib64/",
			"/usr/lib/",
			"/usr/local/lib/",
		},
		ReadZones: []string{
			// System credential files
			"/etc/shadow",
			"/etc/gshadow",
			// Root user secrets
			"/root/.ssh/",
			"/root/.aws/",
		},
		DenySyscalls: []string{
			// Process injection / debugging
			"ptrace",
			"process_vm_readv",
			"process_vm_writev",
			"kcmp",
			// Fault injection
			"userfaultfd",
			// Privileged kernel ops
			"bpf",
			"mount",
			"umount2",
			"unshare",
			"setns",
			"open_by_handle_at",
			// Kernel module loading
			"init_module",
			"finit_module",
			"delete_module",
			"kexec_load",
			"kexec_file_load",
		},
	}
}

// WebWorkerExecRules converts the ExecPaths red zone into execguard.Rule
// values. Entries ending in '*' become PathHasPrefix rules; all others
// become PathEquals rules.
//
// The caller should append these after any operator-configured rules so
// operator allowlists take precedence.
func (p *Policy) WebWorkerExecRules() []execguard.Rule {
	if p == nil {
		return nil
	}
	rules := make([]execguard.Rule, 0, len(p.ExecPaths))
	seen := make(map[string]bool, len(p.ExecPaths))
	for _, ep := range p.ExecPaths {
		if ep == "" {
			continue
		}
		var r execguard.Rule
		r.Decision = execguard.Deny
		r.Reason = "redzone: web-worker exec denied"
		if ep[len(ep)-1] == '*' {
			prefix := ep[:len(ep)-1]
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			r.PathHasPrefix = prefix
		} else {
			if seen[ep] {
				continue
			}
			seen[ep] = true
			r.PathEquals = ep
		}
		rules = append(rules, r)
	}
	return rules
}

// WriteZonePrefixes returns the write red zone path prefixes.
func (p *Policy) WriteZonePrefixes() []string {
	if p == nil {
		return nil
	}
	return p.WriteZones
}

// ReadZonePrefixes returns the credential read red zone path prefixes.
func (p *Policy) ReadZonePrefixes() []string {
	if p == nil {
		return nil
	}
	return p.ReadZones
}

// SyscallNames returns the deny-listed syscall names.
func (p *Policy) SyscallNames() []string {
	if p == nil {
		return nil
	}
	return p.DenySyscalls
}
