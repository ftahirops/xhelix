package credbroker

// Default plaintext credential path + reader allowlist sets used when
// the operator hasn't customised them via config.
//
// Path list philosophy:
//   - cover the credential files every Linux server actually has
//     (cloud SDK creds, npm/pip/git auth tokens, kube/docker tokens,
//     SSH private keys);
//   - cover both root home AND common service users (www-data,
//     ec2-user, ubuntu, deploy);
//   - include glob expansion for /home/* and /var/www/vhosts/*.
//
// Allowlist philosophy:
//   - VERY narrow. Only the legitimate consumer of a given credential
//     class should be allowlisted: aws-cli for .aws/credentials, npm
//     for .npmrc, etc.
//   - All other reads are signal. A monit health probe, a curl from
//     within php-fpm, a find / grep from a shell — these should
//     produce alerts (and in enforce mode, denials).

// DefaultPlaintextPaths returns the set of credential files xhelix
// arms FAN_OPEN_PERM on by default. Each entry is either a literal
// path or a glob.
func DefaultPlaintextPaths() []string {
	return []string{
		// AWS — root + service users + per-home glob
		"/root/.aws/credentials",
		"/root/.aws/config",
		"/home/*/.aws/credentials",
		"/home/*/.aws/config",
		// GCP / Google Cloud
		"/root/.config/gcloud/credentials.db",
		"/root/.config/gcloud/access_tokens.db",
		"/root/.config/gcloud/application_default_credentials.json",
		"/home/*/.config/gcloud/credentials.db",
		"/home/*/.config/gcloud/access_tokens.db",
		"/home/*/.config/gcloud/application_default_credentials.json",
		// Azure
		"/root/.azure/credentials",
		"/root/.azure/accessTokens.json",
		"/home/*/.azure/credentials",
		"/home/*/.azure/accessTokens.json",
		// Kubernetes
		"/root/.kube/config",
		"/home/*/.kube/config",
		"/etc/kubernetes/admin.conf",
		// Docker
		"/root/.docker/config.json",
		"/home/*/.docker/config.json",
		// Git credential cache + token files
		"/root/.git-credentials",
		"/root/.netrc",
		"/home/*/.git-credentials",
		"/home/*/.netrc",
		// npm / Node / pip
		"/root/.npmrc",
		"/root/.pypirc",
		"/home/*/.npmrc",
		"/home/*/.pypirc",
		// GitHub CLI
		"/root/.config/gh/hosts.yml",
		"/home/*/.config/gh/hosts.yml",
		// 1Password CLI
		"/root/.config/op/config",
		"/home/*/.config/op/config",
		// SSH private keys (host + user)
		"/etc/ssh/ssh_host_rsa_key",
		"/etc/ssh/ssh_host_ed25519_key",
		"/etc/ssh/ssh_host_ecdsa_key",
		"/root/.ssh/id_rsa",
		"/root/.ssh/id_ed25519",
		"/root/.ssh/id_ecdsa",
		"/root/.ssh/id_dsa",
		"/home/*/.ssh/id_rsa",
		"/home/*/.ssh/id_ed25519",
		"/home/*/.ssh/id_ecdsa",
		"/home/*/.ssh/id_dsa",
		// Plesk
		"/etc/psa/.psa.shadow",
		"/etc/psa/private/secret_key",
		// Common web-vhost env files (Plesk + LAMP layouts)
		"/var/www/vhosts/*/httpdocs/.env",
		"/var/www/vhosts/*/.env",
		"/var/www/html/.env",
		"/srv/www/*/.env",
		// Database root credentials
		"/root/.my.cnf",
		"/etc/mysql/debian.cnf",
	}
}

// DefaultPlaintextReaderComms returns the comm-name allowlist used in
// enforce mode. These are the immediate process names that have a
// legitimate reason to open plaintext credential files.
//
// Kept narrow on purpose — anything outside this list reading a
// credential file is suspicious by construction.
func DefaultPlaintextReaderComms() []string {
	return []string{
		// AWS / GCP / Azure / Kubernetes / Docker tooling
		"aws", "aws-vault",
		"gcloud", "gsutil", "bq",
		"az",
		"kubectl", "helm", "k9s",
		"docker", "docker-credenti", // truncated to 16 chars
		// Git
		"git", "git-remote-http", "git-credential",
		// npm / pip / language package managers
		"npm", "yarn", "pnpm",
		"pip", "pip3", "pipenv", "poetry",
		// GitHub / 1Password CLIs
		"gh", "op",
		// SSH
		"ssh", "sshd", "ssh-agent", "scp", "sftp", "rsync",
		// Local mariadb/mysql client reading .my.cnf
		"mysql", "mariadb", "mysqldump", "mariadb-dump",
		// xhelix itself (must self-allow)
		"xhelix", "xhelixctl",
		// Plesk control panel processes
		"psa-tool", "plesk", "sw-engine",
	}
}

// DefaultPlaintextReaderImages is the absolute-path allowlist. Kept
// short on purpose — operators add to this via config when they
// have legitimate site-specific consumers (CI runners etc).
func DefaultPlaintextReaderImages() []string {
	return []string{
		"/usr/local/bin/xhelix",
		"/usr/local/bin/xhelixctl",
	}
}

// DefaultPlaintextReaderImageGlobs supports common install paths.
func DefaultPlaintextReaderImageGlobs() []string {
	return []string{
		"/usr/lib/xhelix/*",
		"/usr/lib/systemd/*",
	}
}
