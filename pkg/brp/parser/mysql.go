package brpparser

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ParseMySQL parses a my.cnf file (MySQL/MariaDB) and any
// !include / !includedir directives it references.
//
// Extracts: listen ports + bind address (TCP listen), socket path
// (unix listen), data/log/plugin directories (read+write roots),
// SSL features, plugin set, replication / SST tooling.
func ParseMySQL(path string) (ConfigDerivedBehavior, ProfileKey, error) {
	out := ConfigDerivedBehavior{
		ReadRoots: []string{
			"/etc/mysql/",
			"/etc/my.cnf",
			"/etc/ssl/",
		},
		WriteRoots: []string{
			"/var/log/",
			"/var/log/mysql/",
			"/var/run/",
			"/run/",
		},
	}

	sections, warnings, err := parseINI(path, 0)
	if err != nil {
		out.ParseWarnings = append(out.ParseWarnings,
			fmt.Sprintf("parse %s: %v", path, err))
		return finaliseMySQL(out), keyForMySQL(finaliseMySQL(out)), err
	}
	out.ParseWarnings = append(out.ParseWarnings, warnings...)

	for _, sec := range sections {
		// MySQL groups all daemon settings under [mysqld]; client and
		// embedded sections aren't relevant to a server profile.
		section := strings.ToLower(sec.Name)
		isServer := section == "mysqld" || section == "mariadb" ||
			strings.HasPrefix(section, "mysqld-") ||
			strings.HasPrefix(section, "mariadb-") ||
			section == "server"
		// We still extract from un-sectioned top-level pairs (some
		// distros set them there).
		if section != "" && !isServer {
			continue
		}
		for _, kv := range sec.Pairs {
			handleMySQLDirective(&out, normaliseMySQLKey(kv.Key), kv.Value)
		}
	}
	return finaliseMySQL(out), keyForMySQL(finaliseMySQL(out)), nil
}

// normaliseMySQLKey converts a my.cnf key to its canonical form.
// MySQL accepts both underscored and dashed forms (e.g.
// `bind-address` and `bind_address`); we normalise to underscored.
func normaliseMySQLKey(k string) string {
	return strings.ToLower(strings.ReplaceAll(k, "-", "_"))
}

func handleMySQLDirective(out *ConfigDerivedBehavior, key, value string) {
	switch key {
	case "port":
		if port, ok := atoiPort(value); ok {
			out.ListenPorts = append(out.ListenPorts, port)
		}
	case "bind_address":
		// bind-address tells us interfaces; the port is separate.
		// If a literal IP+port form is used we still want the port.
		if port, ok := parseListenPort(value); ok {
			out.ListenPorts = append(out.ListenPorts, port)
		}
	case "socket":
		if value != "" {
			out.ListenSockets = append(out.ListenSockets, value)
		}
	case "datadir":
		if value != "" {
			out.ReadRoots = append(out.ReadRoots, ensureSlash(value))
			out.WriteRoots = append(out.WriteRoots, ensureSlash(value))
			out.Features = append(out.Features, "datadir_custom")
		}
	case "log_error":
		if value != "" && value != "stderr" {
			out.WriteRoots = append(out.WriteRoots, filepath.Dir(value)+"/")
		}
	case "general_log_file", "slow_query_log_file", "log_bin", "log_bin_index",
		"relay_log", "relay_log_index":
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, filepath.Dir(value)+"/")
			if key == "log_bin" {
				out.Features = append(out.Features, "binary_log")
			}
			if key == "relay_log" {
				out.Features = append(out.Features, "replication_replica")
			}
		}
	case "general_log":
		if isTruthy(value) {
			out.Features = append(out.Features, "general_log")
		}
	case "slow_query_log":
		if isTruthy(value) {
			out.Features = append(out.Features, "slow_log")
		}
	case "log_bin_trust_function_creators":
		if isTruthy(value) {
			out.Features = append(out.Features, "binary_log_trusted_funcs")
		}
	case "plugin_dir":
		if value != "" {
			out.ReadRoots = append(out.ReadRoots, ensureSlash(value))
			out.Features = append(out.Features, "plugin_dir_custom")
		}
	case "plugin_load", "plugin_load_add":
		// Format: name1=lib1.so;name2=lib2.so or simple list.
		for _, p := range strings.Split(value, ";") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if eq := strings.IndexByte(p, '='); eq > 0 {
				out.Modules = append(out.Modules, p[:eq])
			} else {
				out.Modules = append(out.Modules, p)
			}
		}
	case "innodb_data_home_dir", "innodb_log_group_home_dir", "innodb_undo_directory":
		if value != "" {
			out.ReadRoots = append(out.ReadRoots, ensureSlash(value))
			out.WriteRoots = append(out.WriteRoots, ensureSlash(value))
		}
	case "tmpdir":
		if value != "" {
			out.WriteRoots = append(out.WriteRoots, ensureSlash(value))
		}
	case "secure_file_priv":
		if value != "" && value != "NULL" && !strings.EqualFold(value, "null") {
			out.WriteRoots = append(out.WriteRoots, ensureSlash(value))
			out.Features = append(out.Features, "file_priv_configured")
		}
	case "skip_networking":
		if isTruthy(value) {
			out.Features = append(out.Features, "no_network")
		}
	case "skip_name_resolve":
		if isTruthy(value) {
			out.Features = append(out.Features, "no_dns_resolve")
		}
	case "ssl", "have_ssl", "ssl_cert", "ssl_key", "ssl_ca":
		out.Features = append(out.Features, "tls")
		if value != "" && (key == "ssl_cert" || key == "ssl_key" || key == "ssl_ca") {
			out.ReadRoots = append(out.ReadRoots, filepath.Dir(value)+"/")
		}
	case "tls_version":
		out.Features = append(out.Features, "tls_explicit_version")
	case "default_authentication_plugin":
		if value != "" {
			out.Features = append(out.Features, "auth_"+strings.ToLower(value))
		}
	case "server_id":
		if value != "" && value != "0" {
			out.Features = append(out.Features, "replication_server_id_set")
		}
	case "gtid_mode":
		if isTruthy(value) || strings.EqualFold(value, "on") {
			out.Features = append(out.Features, "gtid")
		}
	case "wsrep_provider":
		if value != "" && value != "none" {
			out.Features = append(out.Features, "galera_cluster")
		}
	case "user":
		if value != "" {
			out.Features = append(out.Features, "runas_"+strings.ToLower(value))
		}
	}
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes":
		return true
	}
	return false
}

func finaliseMySQL(b ConfigDerivedBehavior) ConfigDerivedBehavior {
	// MySQL default port if none set.
	if len(b.ListenPorts) == 0 {
		// Only assume 3306 if skip_networking is NOT set.
		hasSkipNet := false
		for _, f := range b.Features {
			if f == "no_network" {
				hasSkipNet = true
				break
			}
		}
		if !hasSkipNet {
			b.ListenPorts = []int{3306}
		}
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
	b.Role = classifyMySQLRole(b)
	return b
}

func keyForMySQL(b ConfigDerivedBehavior) ProfileKey {
	return ProfileKey{
		App:                "mysql",
		Role:               b.Role,
		FeatureFingerprint: b.FeatureFingerprint(),
	}
}

func classifyMySQLRole(b ConfigDerivedBehavior) string {
	has := func(f string) bool {
		for _, x := range b.Features {
			if x == f {
				return true
			}
		}
		return false
	}
	switch {
	case has("galera_cluster"):
		return "mysql-galera"
	case has("replication_replica"):
		return "mysql-replica"
	case has("replication_server_id_set") || has("binary_log"):
		return "mysql-primary"
	case has("no_network"):
		return "mysql-unix-only"
	}
	return "mysql-default"
}
