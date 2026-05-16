package doctor

import (
	"context"
	"fmt"
)

// kernelSysctlChecks returns the hardening sysctls we audit. Each
// check is small and self-describing so the report tells the operator
// exactly why we recommend each value.
//
// Sources of truth:
//   - kernel-hardening project recommendations (KSPP)
//   - CIS Linux benchmarks, where they don't conflict with KSPP
//   - linux-hardened patch set defaults
func kernelSysctlChecks() []Check {
	return []Check{
		sysctlEqualCheck(
			"kernel.kptr_restrict",
			"Hide kernel pointers from /proc",
			"kernel",
			SeverityHigh,
			"2",
			"Pointers exposed via /proc/kallsyms and similar interfaces are the building blocks of a local kernel exploit. kptr_restrict=2 hides them from all non-root readers.",
			"An attacker with a code-exec primitive uses leaked pointers to defeat KASLR, so the next exploit step is a one-liner instead of a research project.",
		),
		sysctlEqualCheck(
			"kernel.dmesg_restrict",
			"Restrict dmesg to root",
			"kernel",
			SeverityMedium,
			"1",
			"dmesg leaks kernel addresses, BUG/Oops traces, and stack frames. Restricting it forces an attacker to escalate before learning the kernel's secrets.",
			"Without this, any local user can read kernel oops messages that often include exploitable pointer leaks.",
		),
		sysctlEqualCheck(
			"kernel.unprivileged_bpf_disabled",
			"Disallow unprivileged eBPF",
			"kernel",
			SeverityHigh,
			"1",
			"Unprivileged BPF has been the source of dozens of LPE CVEs (CVE-2021-3490, CVE-2021-31440, CVE-2022-23222). Disabling it removes a major kernel-LPE surface.",
			"A local user can chain unprivileged BPF + a verifier bug into root. Disabling closes that primitive entirely.",
		),
		sysctlEqualCheck(
			"kernel.kexec_load_disabled",
			"Disable kexec_load",
			"kernel",
			SeverityHigh,
			"1",
			"kexec lets root replace the running kernel. With Secure Boot, that's a bypass primitive; without it, it's still a clean way to swap a malicious kernel into place.",
			"An attacker who reaches root can boot a forged kernel without rebooting visibly. Disabling kexec forces them through a real reboot.",
		),
		sysctlEqualCheck(
			"kernel.perf_event_paranoid",
			"Restrict perf_event_open",
			"kernel",
			SeverityMedium,
			"3",
			"perf_event_open has been a recurring kernel-LPE source. paranoid=3 disables it for non-root entirely.",
			"Multiple LPE chains depend on perf_event_open. paranoid=3 removes the syscall from the unprivileged surface.",
		),
		sysctlEqualCheck(
			"kernel.yama.ptrace_scope",
			"Restrict ptrace to direct children",
			"kernel",
			SeverityHigh,
			"2",
			"ptrace lets a process read another's memory. yama=1 limits to children; yama=2 requires CAP_SYS_PTRACE; yama=3 disables it. We recommend 2 as a balance — gdb still works for root; cred-stealing across user processes does not.",
			"Without yama, malware that lands as user A can attach to user B's session keys, browser memory, ssh-agent, etc. A common credential-theft path on Linux desktops and bastions.",
		),
		sysctlEqualCheck(
			"kernel.randomize_va_space",
			"Full ASLR",
			"kernel",
			SeverityHigh,
			"2",
			"randomize_va_space=2 is full ASLR (stack + libs + brk). Anything less hands attackers fixed addresses.",
			"Without ASLR, a single buffer-overflow becomes reliable RCE; with it, attackers need a leak primitive first.",
		),
		// Network sysctls — antispoofing & redirects.
		sysctlEqualCheck(
			"net.ipv4.conf.all.rp_filter",
			"Strict reverse-path filtering",
			"kernel",
			SeverityMedium,
			"1",
			"Drops packets that arrive on an interface where the routing table says the source IP shouldn't be reachable. Defeats simple source-spoofing on the local segment.",
			"Without it, attackers on the LAN can spoof internal IPs and reach services that trust source-IP for auth.",
		),
		sysctlEqualCheck(
			"net.ipv4.conf.all.accept_redirects",
			"Reject ICMP redirects (v4)",
			"kernel",
			SeverityMedium,
			"0",
			"ICMP redirects can rewrite the host's routing table. An on-path attacker uses them for MITM.",
			"Accepts let an attacker on the LAN steer your outbound traffic through their host. Tiny attack surface today; closes it permanently.",
		),
		sysctlEqualCheck(
			"net.ipv6.conf.all.accept_redirects",
			"Reject ICMP redirects (v6)",
			"kernel",
			SeverityMedium,
			"0",
			"Same risk as v4 redirects, just over IPv6.",
			"v6 redirects are a less-watched MITM primitive on dual-stack hosts.",
		),
		sysctlEqualCheck(
			"net.ipv4.conf.all.accept_source_route",
			"Reject source-routed packets (v4)",
			"kernel",
			SeverityMedium,
			"0",
			"Source routing lets a remote pick the path packets take to your host — a 1990s feature with no legitimate modern use.",
			"Allows trivial source-IP spoofing and bypass of stateful firewalls in some configurations.",
		),
		sysctlEqualCheck(
			"net.ipv4.conf.all.send_redirects",
			"Don't send ICMP redirects",
			"kernel",
			SeverityLow,
			"0",
			"Hosts that aren't routers shouldn't send redirects — it's a reconnaissance leak.",
			"Confirms to a probing attacker that this host has multiple interfaces or unusual routing.",
		),
		sysctlEqualCheck(
			"net.ipv4.tcp_syncookies",
			"Enable TCP SYN cookies",
			"kernel",
			SeverityLow,
			"1",
			"Defends against SYN-flood DoS by avoiding state allocation for half-opens.",
			"Trivial DoS surface for any open TCP listener.",
		),
		sysctlEqualCheck(
			"net.ipv4.icmp_echo_ignore_broadcasts",
			"Ignore broadcast pings",
			"kernel",
			SeverityLow,
			"1",
			"Defends against smurf-style amplification.",
			"Allows your host to be used as a DDoS amplifier on poorly-segmented networks.",
		),
		sysctlEqualCheck(
			"net.ipv4.conf.all.log_martians",
			"Log martian packets",
			"kernel",
			SeverityInfo,
			"1",
			"Martians (impossible source addresses) are reconnaissance markers worth logging.",
			"Loses early signal of an attacker probing your network from a spoofed source.",
		),
	}
}

// sysctlEqualCheck builds a Check that passes when /proc/sys/<key>
// equals want, and applies want via applySysctl().
func sysctlEqualCheck(key, title, category string, sev Severity, want, descr, impact string) Check {
	return Check{
		ID:       "sysctl." + key,
		Title:    title + " (" + key + " = " + want + ")",
		Category: category,
		Severity: sev,
		Description: descr,
		Impact:      impact,
		Recommendation: fmt.Sprintf("Set %s = %s in /etc/sysctl.d/99-xhelix.conf and apply with `sysctl -p`.", key, want),
		FixCommand:     fmt.Sprintf("echo '%s = %s' >> /etc/sysctl.d/99-xhelix.conf && sysctl -w %s=%s", key, want, key, want),
		Run: func(_ context.Context) Result {
			got, err := readSysctl(key)
			if err != nil {
				return SkipResult("sysctl key not present on this kernel")
			}
			if got == want {
				return PassResult(fmt.Sprintf("%s = %s", key, got))
			}
			return FailResult(fmt.Sprintf("%s = %s (want %s)", key, got, want))
		},
		Apply: func(_ context.Context) error {
			return applySysctl(key, want)
		},
	}
}
