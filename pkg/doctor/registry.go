package doctor

import "github.com/xhelix/xhelix/pkg/config"

// HostChecks returns every check that doesn't depend on the running
// xhelix config. These can be run from the CLI without loading
// /etc/xhelix/xhelix.yaml.
func HostChecks() []Check {
	out := []Check{}
	out = append(out, kernelSysctlChecks()...)
	out = append(out, sshChecks()...)
	out = append(out, accountChecks()...)
	out = append(out, fsChecks()...)
	out = append(out, firewallChecks()...)
	out = append(out, macChecks()...)
	out = append(out, patchChecks()...)
	out = append(out, auditChecks()...)
	return out
}

// AllChecks returns HostChecks plus the xhelix self-config checks
// that require a loaded Config.
func AllChecks(cfg config.Config) []Check {
	return append(HostChecks(), XhelixSelfChecks(cfg)...)
}

// Categories returns the canonical category list, ordered for display.
func Categories() []string {
	return []string{
		"kernel", "ssh", "accounts", "fs", "firewall",
		"mac", "patches", "audit", "xhelix",
	}
}
