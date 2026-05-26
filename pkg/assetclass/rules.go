package assetclass

import (
	"net"
	"strings"
)

// staticPathClass returns the canonical class for known system paths.
// This is the immutable floor — operator overrides cannot relax these.
//
// Longest-prefix-wins is approximated by checking specific prefixes
// before more general ones (rules are ordered).
func staticPathClass(path string) Class {
	// Credential-tier paths — highest sensitivity.
	switch {
	case strings.HasPrefix(path, "/etc/shadow"),
		path == "/etc/passwd",
		strings.HasPrefix(path, "/etc/sudoers"),
		strings.HasPrefix(path, "/etc/pam.d/"),
		strings.HasPrefix(path, "/etc/security/"),
		strings.HasPrefix(path, "/etc/ssh/ssh_host_"),
		path == "/etc/ssh/sshd_config",
		strings.HasPrefix(path, "/etc/ssh/sshd_config.d/"):
		return AssetSecretFile
	case strings.HasPrefix(path, "/root/.ssh/"),
		strings.Contains(path, "/.ssh/id_"),
		strings.Contains(path, "/.ssh/authorized_keys"),
		strings.Contains(path, "/.aws/credentials"),
		strings.Contains(path, "/.aws/config"),
		strings.Contains(path, "/.azure/credentials"),
		strings.Contains(path, "/.gcp/credentials"),
		strings.Contains(path, "/.docker/config.json"),
		strings.Contains(path, "/.npmrc"),
		strings.Contains(path, "/.netrc"),
		strings.Contains(path, "/.kube/config"):
		return AssetCredentialStore
	}

	// Workload identity tokens (kube service accounts, etc.).
	if strings.HasPrefix(path, "/var/run/secrets/kubernetes.io/") ||
		strings.HasPrefix(path, "/run/secrets/kubernetes.io/") {
		return AssetWorkloadIdentity
	}

	// Session/token stores (broker outputs, app-specific).
	if strings.HasPrefix(path, "/var/lib/xhelix/credbroker/") ||
		strings.HasPrefix(path, "/run/credentials/") {
		return AssetSessionStore
	}

	// Persistence surfaces.
	switch {
	case strings.HasPrefix(path, "/etc/cron.d/"),
		strings.HasPrefix(path, "/etc/cron.daily/"),
		strings.HasPrefix(path, "/etc/cron.hourly/"),
		strings.HasPrefix(path, "/etc/cron.weekly/"),
		strings.HasPrefix(path, "/etc/cron.monthly/"),
		path == "/etc/crontab",
		strings.HasPrefix(path, "/var/spool/cron/"),
		strings.HasPrefix(path, "/etc/systemd/system/"),
		strings.HasPrefix(path, "/etc/systemd/network/"),
		strings.HasPrefix(path, "/etc/init.d/"),
		path == "/etc/ld.so.preload",
		strings.HasPrefix(path, "/etc/ld.so.conf.d/"):
		return AssetPersistence
	}

	// Service control surfaces.
	switch {
	case strings.HasPrefix(path, "/lib/systemd/system/"),
		strings.HasPrefix(path, "/usr/lib/systemd/system/"),
		strings.HasPrefix(path, "/run/systemd/"):
		return AssetServiceControl
	}

	// Database storage.
	switch {
	case strings.HasPrefix(path, "/var/lib/mysql/"),
		strings.HasPrefix(path, "/var/lib/mariadb/"),
		strings.HasPrefix(path, "/var/lib/postgresql/"),
		strings.HasPrefix(path, "/var/lib/mongodb/"),
		strings.HasPrefix(path, "/var/lib/redis/"):
		return AssetCustomerData
	}

	// Package manager state.
	switch {
	case strings.HasPrefix(path, "/var/lib/dpkg/"),
		strings.HasPrefix(path, "/var/lib/rpm/"),
		strings.HasPrefix(path, "/var/lib/apt/lists/"),
		strings.HasPrefix(path, "/var/cache/apt/archives/"):
		return AssetPackageState
	}

	// Backup data.
	switch {
	case strings.HasPrefix(path, "/var/backups/"),
		strings.HasPrefix(path, "/backup/"):
		return AssetBackupData
	}

	// Config (general).
	if strings.HasPrefix(path, "/etc/") {
		return AssetConfig
	}

	// Log sinks.
	switch {
	case strings.HasPrefix(path, "/var/log/"),
		strings.HasPrefix(path, "/var/lib/systemd/journal/"):
		return AssetLogSink
	}

	// Cache.
	if strings.HasPrefix(path, "/var/cache/") {
		return AssetCache
	}

	// Temp.
	if strings.HasPrefix(path, "/tmp/") ||
		strings.HasPrefix(path, "/var/tmp/") ||
		strings.HasPrefix(path, "/dev/shm/") {
		return AssetTemp
	}

	// Code roots — common deployment locations.
	switch {
	case strings.HasPrefix(path, "/var/www/"),
		strings.HasPrefix(path, "/srv/"),
		strings.HasPrefix(path, "/opt/"),
		strings.HasPrefix(path, "/usr/local/share/"):
		return AssetCodeRoot
	}

	return ClassUnknown
}

// roleAwarePathClass refines classification using the actor's role.
// Called only when staticPathClass returns Unknown.
func roleAwarePathClass(path, role string) Class {
	if role == "" {
		return ClassUnknown
	}
	if strings.HasPrefix(role, "backup-") || role == "borgbackup" || role == "restic" {
		if strings.HasPrefix(path, "/var/www/") ||
			strings.HasPrefix(path, "/srv/") ||
			strings.HasPrefix(path, "/opt/") ||
			strings.HasPrefix(path, "/home/") {
			return AssetBackupData
		}
	}
	return ClassUnknown
}

// staticSocketClass returns the class for unix-socket paths.
func staticSocketClass(socketPath string) Class {
	switch {
	case strings.HasPrefix(socketPath, "/var/run/mysqld/"),
		strings.HasPrefix(socketPath, "/run/mysqld/"),
		strings.HasPrefix(socketPath, "/var/run/postgresql/"),
		strings.HasPrefix(socketPath, "/run/postgresql/"),
		strings.HasPrefix(socketPath, "/tmp/.s.PGSQL."),
		strings.HasPrefix(socketPath, "/var/run/redis/"):
		return AssetDBEndpoint
	}
	switch {
	case strings.HasPrefix(socketPath, "/run/php/"),
		strings.HasPrefix(socketPath, "/var/run/php/"),
		strings.HasPrefix(socketPath, "/run/uwsgi/"):
		return AssetInternalSocket
	}
	switch {
	case strings.HasPrefix(socketPath, "/run/dbus/"),
		strings.HasPrefix(socketPath, "/var/run/dbus/"),
		strings.HasPrefix(socketPath, "/run/systemd/"):
		return AssetServiceControl
	}
	switch {
	case socketPath == "/var/run/docker.sock",
		socketPath == "/run/docker.sock",
		strings.HasPrefix(socketPath, "/run/containerd/"):
		return AssetServiceControl
	}
	return AssetInternalSocket
}

// staticHostClass returns the class for a network destination.
func staticHostClass(ip, sni string, port uint16) Class {
	if ip == "169.254.169.254" || strings.HasPrefix(ip, "fd00:ec2::") {
		return AssetMetadataEndpoint
	}
	switch {
	case sniMatches(sni, "amazonaws.com", "s3."),
		sniMatches(sni, "googleapis.com", "storage."),
		sniMatches(sni, "blob.core.windows.net"):
		return AssetBlobStorage
	case sniMatches(sni, "github.com", "gitlab.com", "bitbucket.org",
		"codeberg.org", "sourcehut.org"):
		return AssetGitHosting
	case sniMatches(sni, "auth0.com", "okta.com", "onelogin.com",
		"login.microsoftonline.com", "accounts.google.com",
		"oauth2.googleapis.com"):
		return AssetIdentityProvider
	case sniMatches(sni, "datadoghq.com", "newrelic.com", "splunk.com",
		"sentry.io", "honeycomb.io", "lightstep.com"):
		return AssetTelemetry
	case sniMatches(sni, "discord.com", "slack.com", "hooks.slack.com",
		"webhook.site"):
		return AssetWebhook
	}
	if ip != "" {
		if parsed := net.ParseIP(ip); parsed != nil {
			if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
				return AssetInternalSocket
			}
		}
	}
	switch port {
	case 3306, 5432, 6379, 27017, 11211:
		return AssetDBEndpoint
	}
	if ip != "" || sni != "" {
		return AssetExternalAPI
	}
	return ClassUnknown
}

func sniMatches(sni string, suffixes ...string) bool {
	if sni == "" {
		return false
	}
	s := strings.ToLower(sni)
	for _, suf := range suffixes {
		ls := strings.ToLower(suf)
		if strings.HasSuffix(s, ls) || strings.Contains(s, ls) {
			return true
		}
	}
	return false
}
