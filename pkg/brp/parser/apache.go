package brpparser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ParseApache parses an apache (httpd) config file and any
// Include/IncludeOptional directives it references. Returns the derived
// behavior + a partially-filled ProfileKey (App="apache", Role,
// FeatureFingerprint).
//
// Robust to malformed input: parse errors land in ParseWarnings; the
// caller falls back to Unprofiled on any non-nil error.
func ParseApache(path string) (ConfigDerivedBehavior, ProfileKey, error) {
	p := &apacheParser{
		seen: make(map[string]bool),
		out: ConfigDerivedBehavior{
			// Standard apache reads + writes; per-role narrows / extends.
			ReadRoots:  []string{"/etc/apache2/", "/etc/httpd/", "/etc/ssl/"},
			WriteRoots: []string{"/var/log/apache2/", "/var/log/httpd/", "/var/run/", "/run/"},
		},
	}
	if err := p.parseFile(path); err != nil {
		p.out.ParseWarnings = append(p.out.ParseWarnings,
			fmt.Sprintf("parse %s: %v", path, err))
		return p.finalise(), p.key(), err
	}
	return p.finalise(), p.key(), nil
}

type apacheParser struct {
	out          ConfigDerivedBehavior
	seen         map[string]bool
	includeDepth int
}

func (p *apacheParser) parseFile(path string) error {
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

// handleLine processes one apache config line. Section tags (<Section>)
// are matched by their directive prefix; we don't need to track
// open/close balance for the fields we extract (LoadModule, ProxyPass,
// etc. all behave the same inside or outside containers).
func (p *apacheParser) handleLine(line, baseDir string) {
	// Container open/close tags.
	if strings.HasPrefix(line, "<") {
		tag := strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">")
		tag = strings.TrimSpace(tag)
		if strings.HasPrefix(tag, "/") {
			return // close tag — nothing to record
		}
		p.handleContainer(tag)
		return
	}

	fields := splitApacheFields(line)
	if len(fields) == 0 {
		return
	}
	directive := fields[0]
	args := fields[1:]

	switch directive {
	case "Include", "IncludeOptional":
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
				info, statErr := os.Stat(m)
				if statErr != nil {
					continue
				}
				if info.IsDir() {
					// Apache IncludeOptional /etc/apache2/sites-enabled/ — recurse globbed files.
					entries, _ := os.ReadDir(m)
					for _, e := range entries {
						if !e.IsDir() {
							_ = p.parseFile(filepath.Join(m, e.Name()))
						}
					}
					continue
				}
				_ = p.parseFile(m)
			}
		}

	case "Listen":
		for _, a := range args {
			if a == "https" {
				p.addFeature("tls")
				continue
			}
			if port, ok := parseListenPort(a); ok {
				p.out.ListenPorts = append(p.out.ListenPorts, port)
			}
		}

	case "LoadModule":
		// LoadModule module_name modules/mod_x.so
		if len(args) >= 2 {
			p.out.Modules = append(p.out.Modules, args[0])
			switch {
			case strings.Contains(args[0], "ssl"):
				p.addFeature("tls")
			case strings.Contains(args[0], "http2"):
				p.addFeature("http2")
			case strings.Contains(args[0], "proxy"):
				p.addFeature("proxy_pass")
			case strings.Contains(args[0], "rewrite"):
				p.addFeature("rewrite")
			case strings.Contains(args[0], "cgi"):
				p.addFeature("cgi")
			case strings.Contains(args[0], "php"):
				p.addFeature("php")
			case strings.Contains(args[0], "wsgi"):
				p.addFeature("wsgi")
			}
		}

	case "ProxyPass":
		p.addFeature("proxy_pass")
		// ProxyPass [path] target [flags]
		if len(args) >= 2 {
			recordUpstream(&p.out, args[1])
		} else if len(args) == 1 {
			recordUpstream(&p.out, args[0])
		}

	case "ProxyPassMatch":
		p.addFeature("proxy_pass")
		if len(args) >= 2 {
			recordUpstream(&p.out, args[1])
		}

	case "ProxyPassReverse":
		// no-op for behavior recording

	case "ScriptAlias", "ScriptAliasMatch":
		p.addFeature("cgi")
		if len(args) >= 2 {
			p.out.ExecAllowed = append(p.out.ExecAllowed, args[1])
			p.out.ReadRoots = append(p.out.ReadRoots, ensureSlash(args[1]))
		}

	case "Alias", "AliasMatch":
		if len(args) >= 2 {
			p.out.ReadRoots = append(p.out.ReadRoots, ensureSlash(args[1]))
		}

	case "DocumentRoot":
		if len(args) >= 1 {
			p.addFeature("static_root")
			p.out.ReadRoots = append(p.out.ReadRoots, ensureSlash(args[0]))
		}

	case "SSLCertificateFile", "SSLCertificateKeyFile", "SSLCACertificateFile":
		p.addFeature("tls")
		if len(args) >= 1 {
			p.out.ReadRoots = append(p.out.ReadRoots, filepath.Dir(args[0])+"/")
		}

	case "CustomLog", "ErrorLog":
		if len(args) >= 1 && args[0] != "syslog" && !strings.HasPrefix(args[0], "|") {
			p.out.WriteRoots = append(p.out.WriteRoots, filepath.Dir(args[0])+"/")
		}

	case "PidFile":
		if len(args) >= 1 {
			p.out.WriteRoots = append(p.out.WriteRoots, filepath.Dir(args[0])+"/")
		}

	case "Protocols":
		for _, a := range args {
			switch a {
			case "h2", "h2c":
				p.addFeature("http2")
			case "http/1.1":
				// noop, default
			}
		}

	case "SSLEngine":
		if len(args) >= 1 && strings.EqualFold(args[0], "on") {
			p.addFeature("tls")
		}

	case "SetHandler":
		// SetHandler "proxy:fcgi://127.0.0.1:9000" is a common php-fpm bridge.
		if len(args) >= 1 {
			a := strings.Trim(args[0], "\"")
			if strings.HasPrefix(a, "proxy:fcgi://") {
				p.addFeature("fastcgi_pass")
				recordUpstream(&p.out, strings.TrimPrefix(a, "proxy:fcgi://"))
			}
		}
	}
}

func (p *apacheParser) handleContainer(tag string) {
	// "VirtualHost *:443" / "Directory /var/www" / "Location /api" etc.
	parts := strings.Fields(tag)
	if len(parts) == 0 {
		return
	}
	switch strings.ToLower(parts[0]) {
	case "virtualhost":
		p.addFeature("vhost")
		// Each VirtualHost may declare its own listen via its argument
		// (e.g. *:443). Record as a hint.
		if len(parts) >= 2 {
			if port, ok := parseListenPort(parts[1]); ok {
				p.out.ListenPorts = append(p.out.ListenPorts, port)
				if port == 443 {
					p.addFeature("tls")
				}
			}
		}
	case "ifmodule":
		// no-op
	case "location", "locationmatch", "directory", "directorymatch", "files", "filesmatch":
		// no-op for behavior — directives inside still fire.
	}
}

// splitApacheFields handles apache's quoting (double-quoted strings
// preserved as one field).
func splitApacheFields(line string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '"' && (i == 0 || line[i-1] != '\\'):
			inQ = !inQ
		case (c == ' ' || c == '\t') && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func (p *apacheParser) addFeature(f string) {
	p.out.Features = append(p.out.Features, f)
}

func (p *apacheParser) finalise() ConfigDerivedBehavior {
	b := p.out
	b.Features = normalise(b.Features)
	b.Modules = normalise(b.Modules)
	b.ListenPorts = normaliseInts(b.ListenPorts)
	b.ListenSockets = normaliseCS(b.ListenSockets)
	b.ReadRoots = normaliseCS(b.ReadRoots)
	b.WriteRoots = normaliseCS(b.WriteRoots)
	b.ExecAllowed = normaliseCS(b.ExecAllowed)
	b.UpstreamHosts = normaliseCS(b.UpstreamHosts)
	b.UpstreamSockets = normaliseCS(b.UpstreamSockets)
	b.Role = classifyApacheRole(b)
	return b
}

func (p *apacheParser) key() ProfileKey {
	b := p.finalise()
	return ProfileKey{
		App:                "apache",
		Role:               b.Role,
		FeatureFingerprint: b.FeatureFingerprint(),
	}
}

// classifyApacheRole picks one of the role-family labels. Order:
// most-specific first.
func classifyApacheRole(b ConfigDerivedBehavior) string {
	has := func(f string) bool {
		for _, x := range b.Features {
			if x == f {
				return true
			}
		}
		return false
	}
	switch {
	case has("wsgi"):
		return "apache-wsgi"
	case has("fastcgi_pass") || has("php"):
		return "apache-fastcgi"
	case has("cgi"):
		return "apache-cgi"
	case has("proxy_pass"):
		return "apache-reverse-proxy"
	case has("static_root"):
		return "apache-static"
	}
	return "apache-default"
}
