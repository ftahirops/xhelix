package brpparser

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ParsePHPFPM parses a php-fpm pool config (each pool is a [section] in
// an INI-style file). Returns derived behavior + a partially-filled
// ProfileKey (App="phpfpm", Role, FeatureFingerprint).
//
// Real-world php-fpm has TWO config layers:
//   - the global php-fpm.conf (process_manager, pid, error_log)
//   - one or more pool files under /etc/php/.../pool.d/*.conf
//
// This parser handles ONE input file at a time. The runtime matcher
// composes profiles from a global file + the pool file for a given
// worker; for v1 we extract whatever lives in the file we're given.
func ParsePHPFPM(path string) (ConfigDerivedBehavior, ProfileKey, error) {
	out := ConfigDerivedBehavior{
		ReadRoots: []string{
			"/etc/php/",
			"/etc/ssl/",
		},
		WriteRoots: []string{
			"/var/log/",
			"/run/",
			"/var/run/",
		},
	}

	sections, warnings, err := parseINI(path, 0)
	if err != nil {
		out.ParseWarnings = append(out.ParseWarnings,
			fmt.Sprintf("parse %s: %v", path, err))
		return finalisePHPFPM(out), keyForPHPFPM(finalisePHPFPM(out)), err
	}
	out.ParseWarnings = append(out.ParseWarnings, warnings...)

	pools := 0
	for _, sec := range sections {
		// [global] is the daemon-wide block; the rest are pools.
		section := strings.ToLower(sec.Name)
		if section == "global" {
			for _, kv := range sec.Pairs {
				handlePHPFPMGlobal(&out, strings.ToLower(kv.Key), kv.Value)
			}
			continue
		}
		// Empty-section bucket = top-of-file pairs before any [section].
		if section == "" {
			continue
		}
		// Pool section.
		pools++
		out.Features = append(out.Features, "pool_"+section)
		for _, kv := range sec.Pairs {
			handlePHPFPMPool(&out, strings.ToLower(kv.Key), kv.Value)
		}
	}
	if pools == 0 {
		out.ParseWarnings = append(out.ParseWarnings,
			"no [pool] section found — file may be global-only")
	}
	return finalisePHPFPM(out), keyForPHPFPM(finalisePHPFPM(out)), nil
}

func handlePHPFPMGlobal(out *ConfigDerivedBehavior, key, value string) {
	switch key {
	case "pid":
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, filepath.Dir(value)+"/")
		}
	case "error_log":
		if value != "" && value != "syslog" {
			out.WriteRoots = append(out.WriteRoots, filepath.Dir(value)+"/")
		}
	case "include":
		// Already parseable via INI !include; if php-fpm uses bare
		// `include = ...` form we record a warning since we don't
		// implement that variant.
		out.ParseWarnings = append(out.ParseWarnings,
			"global include= directive not followed (use !include or split files)")
	case "process_control_timeout", "daemonize":
		// no-op
	case "events.mechanism":
		out.Features = append(out.Features, "events_"+strings.ToLower(value))
	}
}

func handlePHPFPMPool(out *ConfigDerivedBehavior, key, value string) {
	// Pool keys with brackets need to be matched by prefix.
	switch {
	case key == "listen":
		// listen = 9000  → TCP on 9000 on localhost
		// listen = 127.0.0.1:9000
		// listen = /run/php/php8.1-fpm.sock
		if strings.HasPrefix(value, "/") {
			out.ListenSockets = append(out.ListenSockets, value)
			out.Features = append(out.Features, "listen_unix")
		} else if port, ok := parseListenPort(value); ok {
			out.ListenPorts = append(out.ListenPorts, port)
			out.Features = append(out.Features, "listen_tcp")
		}
	case key == "listen.owner", key == "listen.group", key == "listen.mode":
		// no-op
	case key == "listen.allowed_clients":
		out.Features = append(out.Features, "client_acl")
	case key == "user":
		if value != "" {
			out.Features = append(out.Features, "runas_"+strings.ToLower(value))
		}
	case key == "group":
		// no-op (covered by runas_)
	case strings.HasPrefix(key, "pm"):
		// pm = dynamic / static / ondemand
		if key == "pm" {
			out.Features = append(out.Features, "pm_"+strings.ToLower(value))
		}
	case key == "chdir":
		if value != "" && value != "/" {
			out.ReadRoots = append(out.ReadRoots, ensureSlash(value))
		}
	case key == "chroot":
		if value != "" {
			out.Features = append(out.Features, "chroot")
			out.ReadRoots = append(out.ReadRoots, ensureSlash(value))
		}
	case strings.HasPrefix(key, "access.log"):
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, filepath.Dir(value)+"/")
		}
	case strings.HasPrefix(key, "slowlog"):
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, filepath.Dir(value)+"/")
		}
	case strings.HasPrefix(key, "php_admin_value[") ||
		strings.HasPrefix(key, "php_value["):
		// Extract the option name from the bracketed key, e.g.
		// php_admin_value[disable_functions]
		opt := bracketedKey(key)
		if opt != "" {
			handlePHPOption(out, opt, value)
		}
	case strings.HasPrefix(key, "php_admin_flag[") ||
		strings.HasPrefix(key, "php_flag["):
		opt := bracketedKey(key)
		if opt != "" {
			handlePHPFlag(out, opt, value)
		}
	case key == "security.limit_extensions":
		if value != "" {
			out.Features = append(out.Features, "limit_extensions")
		} else {
			out.Features = append(out.Features, "no_limit_extensions")
		}
	case strings.HasPrefix(key, "env["):
		// no-op (could record exposed env vars but it's noise)
	case strings.HasPrefix(key, "clear_env"):
		if isTruthy(value) {
			out.Features = append(out.Features, "clear_env")
		}
	}
}

func handlePHPOption(out *ConfigDerivedBehavior, opt, value string) {
	opt = strings.ToLower(opt)
	switch opt {
	case "disable_functions":
		if value != "" {
			out.Features = append(out.Features, "disable_functions")
		}
	case "open_basedir":
		if value != "" {
			out.Features = append(out.Features, "open_basedir")
			for _, p := range strings.Split(value, ":") {
				p = strings.TrimSpace(p)
				if p != "" {
					out.ReadRoots = append(out.ReadRoots, ensureSlash(p))
				}
			}
		}
	case "upload_tmp_dir":
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, ensureSlash(value))
		}
	case "session.save_path":
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, ensureSlash(value))
		}
	case "error_log":
		if value != "" && value != "syslog" {
			out.WriteRoots = append(out.WriteRoots, filepath.Dir(value)+"/")
		}
	case "sys_temp_dir":
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, ensureSlash(value))
		}
	case "extension":
		if value != "" {
			out.Modules = append(out.Modules, value)
		}
	}
}

func handlePHPFlag(out *ConfigDerivedBehavior, opt, value string) {
	opt = strings.ToLower(opt)
	if !isTruthy(value) {
		return
	}
	switch opt {
	case "allow_url_fopen":
		out.Features = append(out.Features, "allow_url_fopen")
	case "allow_url_include":
		out.Features = append(out.Features, "allow_url_include")
		out.ParseWarnings = append(out.ParseWarnings,
			"allow_url_include=on is dangerous")
	case "expose_php":
		out.Features = append(out.Features, "expose_php")
	}
}

// bracketedKey returns the contents of `name[option]` → "option".
func bracketedKey(key string) string {
	lb := strings.IndexByte(key, '[')
	rb := strings.IndexByte(key, ']')
	if lb >= 0 && rb > lb {
		return key[lb+1 : rb]
	}
	return ""
}

func finalisePHPFPM(b ConfigDerivedBehavior) ConfigDerivedBehavior {
	b.Features = normalise(b.Features)
	b.Modules = normalise(b.Modules)
	b.ListenPorts = normaliseInts(b.ListenPorts)
	b.ListenSockets = normaliseCS(b.ListenSockets)
	b.ReadRoots = normaliseCS(b.ReadRoots)
	b.WriteRoots = normaliseCS(b.WriteRoots)
	b.ExecAllowed = normaliseCS(b.ExecAllowed)
	b.UpstreamHosts = normaliseCS(b.UpstreamHosts)
	b.UpstreamSockets = normaliseCS(b.UpstreamSockets)
	b.Role = classifyPHPFPMRole(b)
	return b
}

func keyForPHPFPM(b ConfigDerivedBehavior) ProfileKey {
	return ProfileKey{
		App:                "phpfpm",
		Role:               b.Role,
		FeatureFingerprint: b.FeatureFingerprint(),
	}
}

func classifyPHPFPMRole(b ConfigDerivedBehavior) string {
	has := func(f string) bool {
		for _, x := range b.Features {
			if x == f {
				return true
			}
		}
		return false
	}
	switch {
	case has("chroot") && has("open_basedir") && has("disable_functions"):
		return "phpfpm-hardened"
	case has("listen_unix") && !has("listen_tcp"):
		return "phpfpm-unix-pool"
	case has("listen_tcp"):
		return "phpfpm-tcp-pool"
	}
	return "phpfpm-default"
}
