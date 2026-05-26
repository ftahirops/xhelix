package brpparser

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ParseNginx parses an nginx config file (and any `include` directives
// it references) and returns the derived behavior + a partially-filled
// ProfileKey. The returned ProfileKey carries App="nginx", Role,
// FeatureFingerprint, and (empty) Version/OS/Package/Phase — those four
// come from the inventory + runtime layers, not the parser.
//
// Robust to malformed input: an unrecoverable error returns an empty
// behavior with the parse error described in ParseWarnings. Callers
// should treat a non-nil error as "fall back to Unprofiled".
func ParseNginx(path string) (ConfigDerivedBehavior, ProfileKey, error) {
	p := &nginxParser{
		seen: make(map[string]bool),
		out: ConfigDerivedBehavior{
			// Conservative defaults — nginx workers must always read
			// config and ssl certs, write logs and PID. Per-role
			// classification narrows / extends these.
			ReadRoots:  []string{"/etc/nginx/", "/etc/ssl/"},
			WriteRoots: []string{"/var/log/nginx/", "/var/cache/nginx/", "/var/run/", "/run/"},
		},
	}
	if err := p.parseFile(path); err != nil {
		p.out.ParseWarnings = append(p.out.ParseWarnings,
			fmt.Sprintf("parse %s: %v", path, err))
		return p.finalise(), p.key(), err
	}
	return p.finalise(), p.key(), nil
}

// nginxParser carries per-parse state across recursive `include`
// resolution. Not safe for concurrent use; create one per ParseNginx.
type nginxParser struct {
	out ConfigDerivedBehavior
	// seen tracks already-included files to break cycles.
	seen map[string]bool
	// includeDepth bounds recursion. 16 is generous; real configs are <5.
	includeDepth int
}

const maxIncludeDepth = 16

func (p *nginxParser) parseFile(path string) error {
	if p.seen[path] {
		return nil
	}
	p.seen[path] = true
	if p.includeDepth >= maxIncludeDepth {
		return fmt.Errorf("include depth exceeded at %s", path)
	}
	p.includeDepth++
	defer func() { p.includeDepth-- }()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tokens, err := tokenizeNginx(string(data))
	if err != nil {
		return fmt.Errorf("tokenize: %w", err)
	}
	return p.parseTokens(tokens, filepath.Dir(path), "")
}

// parseTokens consumes nginx directive tokens. baseDir is used to
// resolve relative include globs. blockCtx is the enclosing block name
// ("http", "server", "location", "") — used for context-sensitive
// classification.
func (p *nginxParser) parseTokens(tokens []nginxToken, baseDir, blockCtx string) error {
	i := 0
	for i < len(tokens) {
		t := tokens[i]
		switch t.kind {
		case nginxTokDirective:
			// Collect args until ; or {.
			args := []string{}
			j := i + 1
			for j < len(tokens) && tokens[j].kind == nginxTokArg {
				args = append(args, tokens[j].text)
				j++
			}
			if j >= len(tokens) {
				return fmt.Errorf("unterminated directive %q near token %d", t.text, i)
			}
			term := tokens[j]
			switch term.kind {
			case nginxTokSemi:
				p.handleDirective(t.text, args, baseDir, blockCtx)
				i = j + 1
			case nginxTokOpenBrace:
				// Block-opening directive. Find matching close, recurse.
				closeIdx, err := matchClose(tokens, j)
				if err != nil {
					return err
				}
				p.handleBlockOpen(t.text, args, blockCtx)
				inner := tokens[j+1 : closeIdx]
				if err := p.parseTokens(inner, baseDir, t.text); err != nil {
					return err
				}
				i = closeIdx + 1
			default:
				return fmt.Errorf("unexpected token after %q: %v", t.text, term)
			}
		case nginxTokCloseBrace, nginxTokSemi:
			// Stray; skip.
			i++
		default:
			i++
		}
	}
	return nil
}

func matchClose(tokens []nginxToken, openIdx int) (int, error) {
	depth := 0
	for i := openIdx; i < len(tokens); i++ {
		switch tokens[i].kind {
		case nginxTokOpenBrace:
			depth++
		case nginxTokCloseBrace:
			depth--
			if depth == 0 {
				return i, nil
			}
		}
	}
	return 0, fmt.Errorf("unmatched { at token %d", openIdx)
}

// handleDirective applies the semantics of a single ;-terminated
// directive. Unknown directives are silently ignored — the goal is to
// extract behavioral hints, not to fully validate nginx config.
func (p *nginxParser) handleDirective(name string, args []string, baseDir, blockCtx string) {
	switch name {
	case "include":
		for _, pattern := range args {
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(baseDir, pattern)
			}
			matches, err := filepath.Glob(pattern)
			if err != nil || len(matches) == 0 {
				// Best-effort: missing include is a soft warning.
				p.out.ParseWarnings = append(p.out.ParseWarnings,
					fmt.Sprintf("include %s: %v", pattern, err))
				continue
			}
			for _, m := range matches {
				if err := p.parseFile(m); err != nil {
					p.out.ParseWarnings = append(p.out.ParseWarnings,
						fmt.Sprintf("include %s: %v", m, err))
				}
			}
		}

	case "listen":
		for _, a := range args {
			if a == "ssl" || a == "http2" || a == "quic" || a == "default_server" || a == "reuseport" {
				if a == "ssl" {
					p.addFeature("tls")
				}
				if a == "http2" {
					p.addFeature("http2")
				}
				if a == "quic" {
					p.addFeature("http3")
				}
				continue
			}
			port, ok := parseListenPort(a)
			if ok {
				p.out.ListenPorts = append(p.out.ListenPorts, port)
			}
		}

	case "ssl_certificate", "ssl_certificate_key":
		p.addFeature("tls")
		if len(args) >= 1 {
			p.out.ReadRoots = append(p.out.ReadRoots, filepath.Dir(args[0])+"/")
		}

	case "http2", "http2_push_preload":
		p.addFeature("http2")

	case "proxy_pass":
		p.addFeature("proxy_pass")
		if len(args) >= 1 {
			recordUpstream(&p.out, args[0])
		}

	case "fastcgi_pass":
		p.addFeature("fastcgi_pass")
		if len(args) >= 1 {
			recordUpstream(&p.out, args[0])
		}

	case "uwsgi_pass":
		p.addFeature("uwsgi_pass")
		if len(args) >= 1 {
			recordUpstream(&p.out, args[0])
		}

	case "grpc_pass":
		p.addFeature("grpc_pass")
		if len(args) >= 1 {
			recordUpstream(&p.out, args[0])
		}

	case "scgi_pass":
		p.addFeature("scgi_pass")
		if len(args) >= 1 {
			recordUpstream(&p.out, args[0])
		}

	case "root", "alias":
		if len(args) >= 1 {
			p.addFeature("static_root")
			p.out.ReadRoots = append(p.out.ReadRoots, ensureSlash(args[0]))
		}

	case "access_log", "error_log":
		if len(args) >= 1 && args[0] != "off" {
			p.out.WriteRoots = append(p.out.WriteRoots, filepath.Dir(args[0])+"/")
		}

	case "client_body_temp_path", "proxy_temp_path", "fastcgi_temp_path",
		"uwsgi_temp_path", "scgi_temp_path":
		if len(args) >= 1 {
			p.out.WriteRoots = append(p.out.WriteRoots, ensureSlash(args[0]))
		}

	case "pid":
		if len(args) >= 1 {
			p.out.WriteRoots = append(p.out.WriteRoots, filepath.Dir(args[0])+"/")
		}

	case "auth_request":
		p.addFeature("auth_request")

	case "load_module":
		if len(args) >= 1 {
			p.out.Modules = append(p.out.Modules, filepath.Base(args[0]))
		}

	case "lua_package_path", "lua_package_cpath", "init_by_lua_file",
		"content_by_lua_file", "rewrite_by_lua_file", "access_by_lua_file":
		p.addFeature("lua")
		p.out.Modules = append(p.out.Modules, "ngx_http_lua_module")

	case "js_import", "js_include", "js_set", "js_content":
		p.addFeature("njs")
		p.out.Modules = append(p.out.Modules, "ngx_http_js_module")

	case "resolver":
		p.addFeature("resolver")

	case "server_name":
		// Indirectly tells us this is a serving role (not pure forward).
		if blockCtx == "server" {
			p.addFeature("server_block")
		}

	case "websocket_pass": // (some 3rd-party modules)
		p.addFeature("websocket")
	}
}

// handleBlockOpen reacts to entering certain known blocks for role
// classification. Most blocks need no special handling.
func (p *nginxParser) handleBlockOpen(name string, args []string, _ string) {
	switch name {
	case "upstream":
		// upstream block: its server directives feed UpstreamHosts via
		// parseTokens recursion. The block name itself is a feature.
		p.addFeature("upstream_block")

	case "server":
		// nothing to record at open time; directives within will fire.

	case "location":
		if len(args) >= 1 && strings.HasPrefix(args[0], "~") {
			p.addFeature("regex_location")
		}
	}
}

// recordUpstream parses an nginx upstream-target string (host:port,
// http://host, unix:/path) into the appropriate ConfigDerivedBehavior
// field.
func recordUpstream(b *ConfigDerivedBehavior, target string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	// Strip scheme prefix.
	for _, prefix := range []string{"http://", "https://", "grpc://", "grpcs://"} {
		if strings.HasPrefix(target, prefix) {
			target = target[len(prefix):]
		}
	}
	// Unix socket.
	if strings.HasPrefix(target, "unix:") {
		sock := strings.TrimPrefix(target, "unix:")
		// Strip ":fastcgi" type suffix after the socket path.
		if idx := strings.Index(sock, ":"); idx > 0 {
			sock = sock[:idx]
		}
		b.UpstreamSockets = append(b.UpstreamSockets, sock)
		return
	}
	// Trailing path segment (proxy_pass http://upstream/api/) — strip.
	if idx := strings.Index(target, "/"); idx > 0 {
		target = target[:idx]
	}
	if target != "" {
		b.UpstreamHosts = append(b.UpstreamHosts, target)
	}
}

// parseListenPort extracts a port number from a `listen` argument.
// Forms: "80", "127.0.0.1:80", "[::1]:80", "*:80", "80 ssl".
// Returns (0, false) if no port found.
func parseListenPort(arg string) (int, bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return 0, false
	}
	// IPv6 in brackets.
	if strings.HasPrefix(arg, "[") {
		if idx := strings.LastIndex(arg, "]:"); idx > 0 {
			return atoiPort(arg[idx+2:])
		}
	}
	// host:port.
	if idx := strings.LastIndex(arg, ":"); idx > 0 {
		return atoiPort(arg[idx+1:])
	}
	// Bare port number.
	return atoiPort(arg)
}

func atoiPort(s string) (int, bool) {
	// Strip trailing modifiers that aren't part of the number.
	s = strings.TrimSpace(s)
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil || n < 1 || n > 65535 {
		return 0, false
	}
	return n, true
}

func ensureSlash(p string) string {
	if !strings.HasSuffix(p, "/") {
		return p + "/"
	}
	return p
}

func (p *nginxParser) addFeature(f string) {
	p.out.Features = append(p.out.Features, f)
}

// finalise normalises all slices and classifies the role based on the
// feature set. Called once at the end of ParseNginx.
func (p *nginxParser) finalise() ConfigDerivedBehavior {
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
	b.Role = classifyNginxRole(b)
	return b
}

func (p *nginxParser) key() ProfileKey {
	b := p.finalise() // re-finalise: cheap, ensures Features sorted before fingerprint.
	return ProfileKey{
		App:                "nginx",
		Role:               b.Role,
		FeatureFingerprint: b.FeatureFingerprint(),
	}
}

// classifyNginxRole picks one of the role-family labels from the v2 BRP
// doc based on which features are present. Order matters: more
// specific roles must precede more general ones.
func classifyNginxRole(b ConfigDerivedBehavior) string {
	has := func(f string) bool {
		for _, x := range b.Features {
			if x == f {
				return true
			}
		}
		return false
	}
	switch {
	case has("lua"):
		return "nginx-lua"
	case has("njs"):
		return "nginx-njs"
	case has("grpc_pass"):
		return "nginx-grpc-proxy"
	case has("fastcgi_pass") || has("uwsgi_pass") || has("scgi_pass"):
		return "nginx-fastcgi"
	case has("proxy_pass"):
		return "nginx-reverse-proxy"
	case has("static_root"):
		return "nginx-static"
	}
	return "nginx-default"
}
