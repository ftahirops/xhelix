package brpparser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseSSHD parses an sshd_config file and any Include directives.
// Returns the derived behavior + a partially-filled ProfileKey
// (App="sshd", Role, FeatureFingerprint).
//
// sshd_config is simple key/value lines with optional Match blocks.
// Match blocks are recorded as features but their directives are still
// applied to the global behavior — we do not model per-Match overrides
// in v1 of this parser (the verification engine treats sshd as a single
// role; per-user overrides land in T17 inventory if needed).
func ParseSSHD(path string) (ConfigDerivedBehavior, ProfileKey, error) {
	p := &sshdParser{
		seen: make(map[string]bool),
		out: ConfigDerivedBehavior{
			ReadRoots: []string{
				"/etc/ssh/",
				"/etc/ssl/",
				"/root/.ssh/", // sshd reads root's authorized_keys
			},
			WriteRoots: []string{
				"/var/log/",
				"/run/",
				"/var/run/",
			},
		},
	}
	if err := p.parseFile(path); err != nil {
		p.out.ParseWarnings = append(p.out.ParseWarnings,
			fmt.Sprintf("parse %s: %v", path, err))
		return p.finalise(), p.key(), err
	}
	return p.finalise(), p.key(), nil
}

type sshdParser struct {
	out          ConfigDerivedBehavior
	seen         map[string]bool
	includeDepth int
}

func (p *sshdParser) parseFile(path string) error {
	if p.seen[path] {
		return nil
	}
	p.seen[path] = true
	if p.includeDepth >= maxIncludeDepth {
		return fmt.Errorf("include depth exceeded at %s", path)
	}
	p.includeDepth++
	defer func() { p.includeDepth-- }()

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	baseDir := filepath.Dir(path)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p.handleLine(line, baseDir)
	}
	return scanner.Err()
}

func (p *sshdParser) handleLine(line, baseDir string) {
	// sshd_config tolerates "Key Value" and "Key=Value".
	// Strip leading "=" if Key=Value form.
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '='
	})
	if len(fields) < 1 {
		return
	}
	key := fields[0]
	args := fields[1:]

	// sshd directives are case-insensitive.
	switch strings.ToLower(key) {
	case "include":
		for _, pattern := range args {
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(baseDir, pattern)
			}
			matches, err := filepath.Glob(pattern)
			if err != nil || len(matches) == 0 {
				p.out.ParseWarnings = append(p.out.ParseWarnings,
					fmt.Sprintf("include %s: %v", pattern, err))
				continue
			}
			for _, m := range matches {
				_ = p.parseFile(m)
			}
		}

	case "port":
		for _, a := range args {
			if port, ok := atoiPort(a); ok {
				p.out.ListenPorts = append(p.out.ListenPorts, port)
			}
		}

	case "listenaddress":
		for _, a := range args {
			if port, ok := parseListenPort(a); ok {
				p.out.ListenPorts = append(p.out.ListenPorts, port)
			}
		}

	case "permitrootlogin":
		if len(args) >= 1 {
			v := strings.ToLower(args[0])
			switch v {
			case "yes":
				p.addFeature("permit_root_login")
			case "prohibit-password", "without-password":
				p.addFeature("permit_root_login_key_only")
			case "no":
				p.addFeature("deny_root_login")
			case "forced-commands-only":
				p.addFeature("root_forced_commands_only")
			}
		}

	case "passwordauthentication":
		if len(args) >= 1 && strings.EqualFold(args[0], "yes") {
			p.addFeature("password_auth")
		}

	case "pubkeyauthentication":
		if len(args) >= 1 && strings.EqualFold(args[0], "yes") {
			p.addFeature("pubkey_auth")
		}

	case "kbdinteractiveauthentication", "challengeresponseauthentication":
		if len(args) >= 1 && strings.EqualFold(args[0], "yes") {
			p.addFeature("kbdint_auth")
		}

	case "permitemptypasswords":
		if len(args) >= 1 && strings.EqualFold(args[0], "yes") {
			p.addFeature("empty_passwords")
			p.out.ParseWarnings = append(p.out.ParseWarnings,
				"PermitEmptyPasswords yes is dangerous")
		}

	case "x11forwarding":
		if len(args) >= 1 && strings.EqualFold(args[0], "yes") {
			p.addFeature("x11_forwarding")
		}

	case "allowtcpforwarding":
		if len(args) >= 1 {
			v := strings.ToLower(args[0])
			if v == "yes" || v == "all" {
				p.addFeature("tcp_forwarding")
			} else if v == "local" || v == "remote" {
				p.addFeature("tcp_forwarding_" + v)
			}
		}

	case "gatewayports":
		if len(args) >= 1 && strings.EqualFold(args[0], "yes") {
			p.addFeature("gateway_ports")
		}

	case "permittunnel":
		if len(args) >= 1 && !strings.EqualFold(args[0], "no") {
			p.addFeature("tun_device")
		}

	case "subsystem":
		// Subsystem name path
		if len(args) >= 2 {
			p.addFeature("subsystem_" + strings.ToLower(args[0]))
			// The handler binary path becomes an allowed exec.
			p.out.ExecAllowed = append(p.out.ExecAllowed, args[1])
		}

	case "authorizedkeysfile":
		for _, a := range args {
			// AuthorizedKeysFile accepts %h tokens etc; the literal
			// prefix is what we record as a read root hint.
			cleaned := strings.ReplaceAll(a, "%h", "")
			cleaned = strings.ReplaceAll(cleaned, "%u", "")
			cleaned = strings.TrimSuffix(filepath.Dir(cleaned), "/")
			if cleaned != "" && cleaned != "." {
				p.out.ReadRoots = append(p.out.ReadRoots, cleaned+"/")
			}
		}

	case "authorizedkeyscommand":
		p.addFeature("authorizedkeyscommand")
		if len(args) >= 1 {
			p.out.ExecAllowed = append(p.out.ExecAllowed, args[0])
		}

	case "chrootdirectory":
		if len(args) >= 1 && !strings.EqualFold(args[0], "none") {
			p.addFeature("chroot")
		}

	case "allowusers", "allowgroups":
		p.addFeature("allowlist_users")

	case "denyusers", "denygroups":
		p.addFeature("denylist_users")

	case "match":
		p.addFeature("match_block")

	case "usepam":
		if len(args) >= 1 && strings.EqualFold(args[0], "yes") {
			p.addFeature("pam")
		}

	case "ciphers", "kexalgorithms", "hostkeyalgorithms", "macs":
		// Record only that explicit crypto policy is in use.
		p.addFeature("explicit_crypto_policy")

	case "hostkey":
		// no-op for behavior — sshd needs to read its own host keys,
		// already covered by /etc/ssh read root.

	case "logfacility", "syslogfacility":
		// no-op; logging is to syslog/journald, not file paths.
	}
}

func (p *sshdParser) addFeature(f string) {
	p.out.Features = append(p.out.Features, f)
}

func (p *sshdParser) finalise() ConfigDerivedBehavior {
	b := p.out
	// If no explicit Port directive, the default is 22.
	if len(b.ListenPorts) == 0 {
		b.ListenPorts = []int{22}
	}
	// If no auth features at all, default = pubkey (modern distros).
	hasAnyAuth := false
	for _, f := range b.Features {
		if f == "password_auth" || f == "pubkey_auth" || f == "kbdint_auth" {
			hasAnyAuth = true
			break
		}
	}
	if !hasAnyAuth {
		b.Features = append(b.Features, "pubkey_auth")
	}
	b.Features = normalise(b.Features)
	b.Modules = normalise(b.Modules)
	b.ListenPorts = normaliseInts(b.ListenPorts)
	b.ListenSockets = normaliseCS(b.ListenSockets)
	b.ReadRoots = normaliseCS(b.ReadRoots)
	b.WriteRoots = normaliseCS(b.WriteRoots)
	b.ExecAllowed = normaliseCS(b.ExecAllowed)
	b.UpstreamHosts = normaliseCS(b.UpstreamHosts)
	b.UpstreamSockets = normaliseCS(b.UpstreamSockets)
	b.Role = classifySSHDRole(b)
	return b
}

func (p *sshdParser) key() ProfileKey {
	b := p.finalise()
	return ProfileKey{
		App:                "sshd",
		Role:               b.Role,
		FeatureFingerprint: b.FeatureFingerprint(),
	}
}

// classifySSHDRole picks one of the role-family labels. sshd has
// fewer distinct roles than nginx/apache; the main axis is
// "hardened vs default vs sftp-only".
func classifySSHDRole(b ConfigDerivedBehavior) string {
	has := func(f string) bool {
		for _, x := range b.Features {
			if x == f {
				return true
			}
		}
		return false
	}
	switch {
	case has("chroot") && has("subsystem_sftp"):
		return "sshd-sftp-chroot"
	case has("tcp_forwarding") && !has("deny_root_login"):
		return "sshd-jumphost"
	case has("deny_root_login") && !has("password_auth"):
		return "sshd-hardened"
	case has("permit_root_login") || has("password_auth") || has("empty_passwords"):
		return "sshd-permissive"
	}
	return "sshd-default"
}
