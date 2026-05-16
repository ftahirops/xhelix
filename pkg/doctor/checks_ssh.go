package doctor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

// sshChecks audits sshd_config for the patterns that account for the
// vast majority of SSH compromises in the wild. We don't try to
// validate every option — we focus on the ones that decide whether
// the SSH daemon is a hardened service or a foothold.
func sshChecks() []Check {
	return []Check{
		sshConfigCheck(
			"PermitRootLogin",
			"no",
			"Disable direct root SSH login",
			SeverityCritical,
			"Root SSH means an attacker only needs the password / one key to compromise the box. Force them through a named user + sudo, which gives auditing and a second layer.",
			"Two of the three big SSH brute-force botnets specifically target root@. Disabling closes the most-attacked door on the internet.",
		),
		sshConfigCheck(
			"PasswordAuthentication",
			"no",
			"Disable SSH password auth",
			SeverityHigh,
			"Passwords are guessable, leakable, and reused. Public keys aren't.",
			"Internet-facing SSH with passwords gets brute-forced continuously. Even with rate-limiting, weak/reused passwords get found.",
		),
		sshConfigCheck(
			"PermitEmptyPasswords",
			"no",
			"Reject empty passwords",
			SeverityCritical,
			"Empty passwords should never be allowed for any auth path.",
			"Combined with a misconfigured PAM stack, empty passwords mean unauthenticated access.",
		),
		sshConfigCheck(
			"X11Forwarding",
			"no",
			"Disable X11 forwarding",
			SeverityLow,
			"X11 forwarding hands the SSH server a way to pivot into the client's display. Rarely needed on servers.",
			"A compromised server can keylog SSH clients via forwarded X11.",
		),
		sshConfigCheck(
			"PermitUserEnvironment",
			"no",
			"Disable PermitUserEnvironment",
			SeverityMedium,
			"Letting users set environment via ~/.ssh/environment can override LD_PRELOAD-equivalent values and bypass restrictions.",
			"A user with the ability to write ~/.ssh/environment can escalate via injected library paths.",
		),
		// MaxAuthTries — lower is safer; default is 6.
		{
			ID:       "ssh.MaxAuthTries",
			Title:    "Limit SSH auth attempts per connection (MaxAuthTries ≤ 4)",
			Category: "ssh",
			Severity: SeverityLow,
			Description: "Lowering MaxAuthTries reduces wasted compute on brute-force probes and forces botnets into more connections, which fail2ban / netban catch faster.",
			Impact:      "Higher MaxAuthTries means fewer connection attempts to fingerprint a valid username — attackers learn more per probe.",
			Recommendation: "Set MaxAuthTries 4 in /etc/ssh/sshd_config and reload sshd.",
			FixCommand:     "sed -ri 's/^#?MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && systemctl reload ssh",
			Risky:          true,
			Run: func(_ context.Context) Result {
				v, _, err := readSSHConfigKey("MaxAuthTries")
				if err != nil {
					return SkipResult("sshd_config not readable")
				}
				if v == "" {
					return WarnResult("MaxAuthTries not set (sshd default = 6)")
				}
				if v == "4" || v == "3" || v == "2" || v == "1" {
					return PassResult("MaxAuthTries = " + v)
				}
				return FailResult("MaxAuthTries = " + v + " (want ≤ 4)")
			},
		},
		// LoginGraceTime — shorter is safer.
		{
			ID:       "ssh.LoginGraceTime",
			Title:    "Short SSH login grace time (≤ 60s)",
			Category: "ssh",
			Severity: SeverityLow,
			Description: "Window during which an unauthenticated TCP connection can sit on the SSH daemon. Long grace times feed slowloris-style DoS.",
			Impact:      "Long grace allows attackers to tie up sshd connection slots cheaply.",
			Recommendation: "Set LoginGraceTime 60 in /etc/ssh/sshd_config and reload sshd.",
			FixCommand:     "sed -ri 's/^#?LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config && systemctl reload ssh",
			Risky:          true,
			Run: func(_ context.Context) Result {
				v, _, err := readSSHConfigKey("LoginGraceTime")
				if err != nil {
					return SkipResult("sshd_config not readable")
				}
				if v == "" {
					return WarnResult("LoginGraceTime not set (sshd default = 120s)")
				}
				return PassResult("LoginGraceTime = " + v)
			},
		},
		// ClientAlive — disconnects idle/lost sessions.
		sshConfigCheck(
			"ClientAliveInterval",
			"300",
			"Set ClientAliveInterval = 300",
			SeverityInfo,
			"Idle sessions linger across operator network hiccups. Sending alive probes lets sshd reap dead sessions.",
			"Stale sessions hang around indefinitely; if the operator's laptop sleeps and an attacker steals network access, the session is still authenticated.",
		),
		sshConfigCheck(
			"ClientAliveCountMax",
			"3",
			"Set ClientAliveCountMax = 3",
			SeverityInfo,
			"Pairs with ClientAliveInterval — three missed pings before disconnect.",
			"Without this, the alive-interval setting alone can keep dead sessions open forever.",
		),
		// Protocol must be 2.
		sshConfigCheck(
			"Protocol",
			"2",
			"Use SSH protocol version 2 only",
			SeverityHigh,
			"Protocol 1 has been broken since 2000. Protocol 2 should be the only setting on any modern sshd.",
			"Protocol 1 has known cryptographic flaws and should never be enabled.",
		),
	}
}

// sshConfigCheck is the common shape: read sshd_config, expect key=want.
func sshConfigCheck(key, want, title string, sev Severity, descr, impact string) Check {
	risky := key == "PasswordAuthentication" || key == "PermitRootLogin" ||
		key == "MaxAuthTries" || key == "LoginGraceTime" ||
		key == "PermitUserEnvironment"
	return Check{
		ID:       "ssh." + key,
		Title:    title,
		Category: "ssh",
		Severity: sev,
		Description: descr,
		Impact:      impact,
		Recommendation: fmt.Sprintf("Set %s %s in %s and `systemctl reload ssh`.", key, want, sshdConfigPath),
		FixCommand:     fmt.Sprintf("sed -ri 's/^#?%s.*/%s %s/' %s; grep -q '^%s' %s || echo '%s %s' >> %s; systemctl reload ssh", key, key, want, sshdConfigPath, key, sshdConfigPath, key, want, sshdConfigPath),
		Risky:          risky,
		Run: func(_ context.Context) Result {
			got, present, err := readSSHConfigKey(key)
			if err != nil {
				return SkipResult("sshd_config not readable")
			}
			if !present {
				// Many keys have safe defaults in modern OpenSSH; treat
				// silence as "not configured", which we report as a
				// warning so operators are explicit.
				return WarnResult(key + " not set (relying on sshd default)")
			}
			if strings.EqualFold(got, want) {
				return PassResult(key + " = " + got)
			}
			return FailResult(fmt.Sprintf("%s = %s (want %s)", key, got, want))
		},
	}
}

// readSSHConfigKey reads /etc/ssh/sshd_config and returns the
// effective value of key (last non-comment occurrence wins, matching
// sshd's own behaviour for non-Match-block keys). Returns ("", false, nil)
// if the key is absent.
func readSSHConfigKey(key string) (value string, present bool, err error) {
	f, err := os.Open(sshdConfigPath)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip Match blocks — we only audit the global section.
		if strings.HasPrefix(strings.ToLower(line), "match ") {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.EqualFold(fields[0], key) {
			value = fields[1]
			present = true
		}
	}
	return value, present, sc.Err()
}
