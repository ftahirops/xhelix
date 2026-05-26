package secrettaint

import (
	"strings"

	"github.com/xhelix/xhelix/pkg/model"
)

// ClassifyEvent inspects an event for secret-touch signals and returns
// (class, true) if the event represents a secret access. Returns
// (zero, false) otherwise.
//
// Used by the pipeline: every event passes through ClassifyEvent; on a
// hit, the pipeline emits a Touch into the Store.
//
// Detection sources per Phase B.2 spec:
//   - file reads to canonical secret paths
//   - cloud metadata IP access
//   - /proc/<pid>/environ scraping (proc_scrape sensor)
//   - credbroker events (when wired)
//
// The classifier is intentionally narrow. False positives here turn
// benign lineages into "tainted" lineages — which then face stricter
// rules in the verifier and egressguard. Better to miss a touch than
// over-taint.
func ClassifyEvent(ev model.Event) (SecretClass, bool) {
	// Cloud metadata access (any role).
	if ev.Sensor == "ebpf.net" {
		if ev.Tags["dst_ip"] == "169.254.169.254" ||
			strings.HasPrefix(ev.Tags["dst_ip"], "fd00:ec2::") {
			return SecretMetadata, true
		}
	}

	// Procfs /environ scraping — the dedicated procscrape sensor + the
	// rule engine both flag this. We pick up the procscrape sensor's
	// output here.
	if ev.Sensor == "procscrape" || ev.Tags["proc_scrape"] == "environ" {
		return SecretProcEnviron, true
	}

	// File reads to canonical secret paths.
	if ev.Sensor == "ebpf.file" || ev.Sensor == "fim" {
		if path := ev.Tags["path"]; path != "" && isReadAction(ev.Tags) {
			if c, ok := classifyPath(path); ok {
				return c, true
			}
		}
	}

	// Credbroker events (credbroker explicitly reports release).
	if ev.Sensor == "credbroker" {
		switch ev.Tags["class"] {
		case "cloud_creds", "aws", "gcp", "azure":
			return SecretCloudCreds, true
		case "kube_token", "service_account":
			return SecretKubeToken, true
		case "git_token", "gh_token":
			return SecretGitToken, true
		case "api_key":
			return SecretAPIKey, true
		case "browser_session":
			return SecretBrowserSession, true
		default:
			return SecretToken, true
		}
	}

	return "", false
}

// isReadAction returns true if the file event represents a read.
// File-open events from ebpf.file carry kind=file_open or mode=read;
// FIM events carry write/create/delete tags but not read (FIM is
// inotify-based and doesn't see reads). So this primarily catches
// the eBPF file_open path.
func isReadAction(tags map[string]string) bool {
	if tags == nil {
		return false
	}
	if tags["kind"] == "file_open" || tags["kind"] == "file_read" {
		return true
	}
	if tags["mode"] == "read" || tags["mode"] == "" {
		// No mode tag often means a read-open on the open path.
		return tags["kind"] == "file_open" || tags["kind"] == ""
	}
	return false
}

// classifyPath maps a filesystem path to a SecretClass when it matches
// a well-known secret location. Sourced from the same canonical list as
// pkg/assetclass; kept here to avoid a package dependency cycle.
func classifyPath(path string) (SecretClass, bool) {
	switch {
	// /etc/shadow-class files
	case strings.HasPrefix(path, "/etc/shadow"),
		strings.HasPrefix(path, "/etc/gshadow"):
		return SecretSecretFile, true
	// SSH keys
	case strings.Contains(path, "/.ssh/id_"),
		strings.HasPrefix(path, "/etc/ssh/ssh_host_"):
		return SecretSecretFile, true
	// Cloud credentials
	case strings.Contains(path, "/.aws/credentials"),
		strings.Contains(path, "/.aws/config"),
		strings.Contains(path, "/.azure/credentials"),
		strings.Contains(path, "/.gcp/credentials"),
		strings.Contains(path, "service-account-key.json"):
		return SecretCloudCreds, true
	// Kube tokens
	case strings.HasPrefix(path, "/var/run/secrets/kubernetes.io/"),
		strings.HasPrefix(path, "/run/secrets/kubernetes.io/"),
		strings.Contains(path, "/.kube/config"):
		return SecretKubeToken, true
	// Git tokens
	case strings.Contains(path, "/.git-credentials"),
		strings.Contains(path, "/.netrc"):
		return SecretGitToken, true
	// Docker / npm config
	case strings.Contains(path, "/.docker/config.json"),
		strings.Contains(path, "/.npmrc"):
		return SecretAPIKey, true
	// Generic .env (project-level secret blob)
	case strings.HasSuffix(path, "/.env"),
		strings.HasSuffix(path, ".env.local"),
		strings.HasSuffix(path, ".env.production"):
		return SecretEnv, true
	// Session stores
	case strings.HasPrefix(path, "/var/lib/xhelix/credbroker/"),
		strings.HasPrefix(path, "/run/credentials/"):
		return SecretSessionStore, true
	// Workload identity
	case strings.Contains(path, "/var/lib/cloud/instance/sensitive-data-dir"):
		return SecretWorkloadIdentity, true
	}
	return "", false
}
