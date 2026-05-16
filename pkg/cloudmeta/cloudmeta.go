// Package cloudmeta classifies connections and DNS queries against
// known cloud metadata services.
//
// The metadata service is the single highest-value SSRF target in
// cloud environments: it hands out short-lived IAM credentials to
// any process on the host that can reach 169.254.169.254. Attackers
// pivot through it constantly; legitimate code paths are narrow
// (cloud-init at boot, kubelet, the AWS/GCP SDK in your own
// service code).
//
// The classifier is pure data + pure functions. Wiring into the
// dispatch loop (alert when an unexpected pid hits the service)
// lives upstream.
package cloudmeta

import (
	"net/netip"
	"strings"
)

// Provider names the cloud whose metadata service is being touched.
type Provider string

const (
	ProviderNone         Provider = ""
	ProviderAWS          Provider = "aws"
	ProviderGCP          Provider = "gcp"
	ProviderAzure        Provider = "azure"
	ProviderAlibaba      Provider = "alibaba"
	ProviderDigitalOcean Provider = "digitalocean"
	ProviderOracle       Provider = "oracle"
	ProviderIBM          Provider = "ibm"
	ProviderHetzner      Provider = "hetzner"
)

// Severity classifies how suspicious a hit is in isolation.
type Severity uint8

const (
	SeverityInfo     Severity = 1 // legitimate caller (cloud-init, IMDS by approved SDK)
	SeverityNotice   Severity = 2 // unknown caller, default tier
	SeverityHigh     Severity = 4 // unexpected pid + metadata access
	SeverityCritical Severity = 5 // user-shell or LOLBin accessing metadata
)

// Hit describes one observed metadata-service touch.
type Hit struct {
	Provider Provider
	IP       string // canonical service IP
	Domain   string // resolved hostname if observed via DNS path
	Severity Severity
	Reason   string
}

// metaIPs maps every IP we recognise as a cloud metadata service
// to the provider it belongs to. Multiple cloud providers share
// 169.254.169.254 (the link-local IANA-reserved IPv4); the caller
// disambiguates by the host's other context. We map that IP to
// AWS by default and surface the ambiguity in the Reason.
var metaIPs = map[string]Provider{
	"169.254.169.254":            ProviderAWS, // also Azure, DO, Hetzner — disambiguate by ASN
	"fd00:ec2::254":              ProviderAWS,
	"100.100.100.200":            ProviderAlibaba,
	"192.0.0.192":                ProviderOracle, // Oracle Cloud Infrastructure
	"100.100.100.110":            ProviderIBM,
}

// metaDomains maps canonical metadata DNS names to providers.
var metaDomains = map[string]Provider{
	"metadata.google.internal":      ProviderGCP,
	"metadata.googleapis.com":       ProviderGCP,
	"metadata":                       ProviderGCP, // bare unqualified
	"metadata.azure.com":             ProviderAzure,
	"169.254.169.254.nip.io":         ProviderAWS, // common nip.io DNS-rebinding pivot
	"instance-data":                  ProviderAWS,
	"instance-data.ec2.internal":     ProviderAWS,
	"100.100.100.200":                ProviderAlibaba,
}

// IsMetadataIP reports whether ip is a known metadata-service IP
// and returns the most-likely provider.
func IsMetadataIP(ip string) (Provider, bool) {
	if p, ok := metaIPs[ip]; ok {
		return p, true
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		// Catch IPv6 form variants by parsing.
		if a.Is4() {
			s := a.String()
			if p, ok := metaIPs[s]; ok {
				return p, true
			}
		}
	}
	return ProviderNone, false
}

// IsMetadataDomain reports whether qname matches any known
// metadata hostname (case-insensitive, trailing-dot tolerant).
func IsMetadataDomain(qname string) (Provider, bool) {
	q := strings.ToLower(strings.TrimSuffix(qname, "."))
	if p, ok := metaDomains[q]; ok {
		return p, true
	}
	return ProviderNone, false
}

// Classify takes optional ip + qname plus contextual hints about
// the touching process, and returns a Hit when one applies.
//
// Hints:
//   - ParentExe of the touching process (when known)
//   - Comm of the touching process
//   - IsKnownSDK indicates the caller is a recognised cloud SDK
//     process or system service (cloud-init, kubelet, etc.)
type Context struct {
	IP         string
	Domain     string
	ParentExe  string
	Comm       string
	IsKnownSDK bool
}

// Classify returns (Hit, true) when the inputs match a metadata
// service and the context warrants surfacing; otherwise the zero
// Hit and false. Always returns a Hit when either IP or Domain
// matches — only the severity varies with context.
func Classify(c Context) (Hit, bool) {
	var provider Provider
	var matchedIP, matchedDomain string

	if c.IP != "" {
		if p, ok := IsMetadataIP(c.IP); ok {
			provider = p
			matchedIP = c.IP
		}
	}
	if c.Domain != "" {
		if p, ok := IsMetadataDomain(c.Domain); ok {
			if provider == ProviderNone {
				provider = p
			}
			matchedDomain = c.Domain
		}
	}
	if provider == ProviderNone {
		return Hit{}, false
	}

	h := Hit{Provider: provider, IP: matchedIP, Domain: matchedDomain}

	// Severity grading.
	switch {
	case c.IsKnownSDK:
		h.Severity = SeverityInfo
		h.Reason = "metadata access by approved process"
	case isShellLike(c.Comm), isShellLike(c.ParentExe):
		h.Severity = SeverityCritical
		h.Reason = "metadata access by shell/LOLBin process — likely SSRF / privesc"
	case isWebDaemon(c.ParentExe):
		h.Severity = SeverityHigh
		h.Reason = "metadata access by web-server descendant — classic SSRF"
	default:
		h.Severity = SeverityNotice
		h.Reason = "metadata access by unexpected process"
	}
	return h, true
}

func isShellLike(s string) bool {
	if s == "" {
		return false
	}
	base := basename(s)
	switch base {
	case "bash", "sh", "dash", "zsh", "ksh", "busybox",
		"curl", "wget", "python", "python3", "perl", "ruby", "nc", "ncat":
		return true
	}
	if strings.HasPrefix(base, "python") {
		return true
	}
	return false
}

func isWebDaemon(s string) bool {
	if s == "" {
		return false
	}
	base := basename(s)
	switch base {
	case "nginx", "apache2", "httpd", "caddy", "php-fpm",
		"gunicorn", "uwsgi", "puma", "unicorn":
		return true
	}
	return false
}

func basename(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// AllowedCallers returns the curated set of "approved" comms that
// the caller should mark IsKnownSDK=true for in production. The
// daemon's config can extend this.
func AllowedCallers() []string {
	return []string{
		"cloud-init", "cloud-init-local", "cloud-init-net",
		"kubelet", "containerd", "dockerd",
		"systemd-resolved", "systemd-networkd",
		"chef-client", "puppet", "salt-minion",
		"amazon-ssm-agent", "amazon-cloudwatch-agent",
		"google_metadata_script_runner", "google_oslogin_agent",
		"WALinuxAgent", // Azure
	}
}
