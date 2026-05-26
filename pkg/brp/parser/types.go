// Package brpparser turns operator-authored service configuration
// (nginx.conf, apache.conf, sshd_config, my.cnf, php-fpm pool files)
// into a structured ConfigDerivedBehavior + a ProfileKey suitable for
// fleet-consensus bucketing.
//
// This is the v2 "config-first, learning-second" lever:
// configuration already declares most intended behavior, so we PARSE
// instead of LEARN where possible. Statistical fleet learning fills in
// the bounded remainder (resource envelopes, syscall mix, timing).
//
// Per-app parsers live in this package (nginx.go, apache.go, sshd.go,
// mysql.go, phpfpm.go). They share a single contract:
//
//	type Parser interface {
//	    Parse(path string) (ConfigDerivedBehavior, ProfileKey, error)
//	}
//
// On any parse failure the caller MUST fall back to the Unprofiled
// confidence class (see pkg/brp).
package brpparser

import (
	"encoding/binary"
	"hash/fnv"
	"sort"
	"strings"
)

// ProfileKey identifies a behavioral reference profile family.
//
// The full key combines parser output (Role + Features) with caller-
// supplied context (Version, OS, Package, Phase). The parser only fills
// App, Role, Features, and FeatureFingerprint — the rest comes from the
// inventory layer (T17) and the runtime phase detector (T06).
type ProfileKey struct {
	App                string // "nginx", "apache", "sshd", "mysql", "phpfpm"
	VersionFamily      string // "1.24.x", "2.4.x", "8.0.x"  (caller fills)
	OSFamily           string // "debian12", "rhel9"          (caller fills)
	PackageOrigin      string // "deb", "rpm", "source"       (caller fills)
	Role               string // parser-derived (e.g. "nginx-reverse-proxy")
	FeatureFingerprint string // fnv64 hex of normalised feature list
	Phase              string // "bootstrap"/"steady"/"reload"/"degraded" (runtime)
}

// String returns the canonical bucketing key:
//
//	brp-nginx-1.24.x-debian12-deb-reverse_proxy-a1b2c3d4e5f60718-steady
//
// Empty fields are rendered as "?". Stable across runs because the
// parser sorts features before hashing.
func (k ProfileKey) String() string {
	parts := []string{
		"brp", emptyAsQ(k.App), emptyAsQ(k.VersionFamily), emptyAsQ(k.OSFamily),
		emptyAsQ(k.PackageOrigin), emptyAsQ(k.Role), emptyAsQ(k.FeatureFingerprint),
		emptyAsQ(k.Phase),
	}
	return strings.Join(parts, "-")
}

func emptyAsQ(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

// ConfigDerivedBehavior is what the operator's config DECLARES the app
// should do. The verification engine treats this as "intent" — the
// operator's signed promise about what is normal — and consults it
// BEFORE consulting statistical fleet learning.
//
// All slices are normalised: sorted, deduplicated, lowercased where
// case-insensitive. ParseWarnings carries soft errors that did not
// abort the parse but the operator may want to fix.
type ConfigDerivedBehavior struct {
	// Role-classification result. Parser-specific value, e.g.
	// "nginx-static", "nginx-reverse-proxy", "apache-fastcgi",
	// "sshd-default", "mysql-replica". Empty means "could not classify".
	Role string

	// Features is the normalised set of config features that drive
	// role classification and feature_fingerprint hashing. Examples:
	// "tls", "http2", "proxy_pass", "fastcgi_pass", "lua", "njs",
	// "auth_request", "websocket". Sorted, deduplicated, lowercase.
	Features []string

	// ListenPorts is the set of TCP ports the app accepts on.
	ListenPorts []int

	// ListenSockets is the set of Unix sockets the app accepts on.
	ListenSockets []string

	// ReadRoots is the set of filesystem path prefixes the app may
	// legitimately read from. Includes config files, static roots,
	// data directories. Trailing slash for directories.
	ReadRoots []string

	// WriteRoots is the set of filesystem path prefixes the app may
	// legitimately write to. Includes logs, cache, temp, pid files.
	WriteRoots []string

	// ExecAllowed is the set of helper binaries the app may exec.
	// Empty for daemons that should never exec anything (sshd in
	// strict mode), populated for apache+mod_cgi, php-fpm, etc.
	ExecAllowed []string

	// UpstreamHosts is the set of declared outbound TCP targets.
	// Format "host:port" or "host" (port resolved at runtime).
	UpstreamHosts []string

	// UpstreamSockets is the set of declared outbound Unix sockets.
	UpstreamSockets []string

	// Modules is the set of loaded dynamic modules / extensions
	// (nginx dynamic modules, apache LoadModule, php extensions,
	// mysql plugins). Used to fingerprint feature variants.
	Modules []string

	// ParseWarnings carries soft parse issues. An empty slice means
	// the parser fully understood the config; non-empty means the
	// operator should review (we still return a usable profile).
	ParseWarnings []string
}

// FeatureFingerprint returns the order-independent fnv64 hex of the
// (Role, Features, Modules) triple. Stable across runs.
func (b ConfigDerivedBehavior) FeatureFingerprint() string {
	// Normalise inputs into a sorted, deduplicated slice and feed each
	// element (length-prefixed) into fnv64a. Length-prefixing makes
	// {"a","bc"} distinct from {"ab","c"}.
	parts := make([]string, 0, 1+len(b.Features)+len(b.Modules))
	if b.Role != "" {
		parts = append(parts, "role:"+b.Role)
	}
	for _, f := range b.Features {
		parts = append(parts, "feat:"+f)
	}
	for _, m := range b.Modules {
		parts = append(parts, "mod:"+m)
	}
	sort.Strings(parts)

	h := fnv.New64a()
	var lenBuf [4]byte
	for _, p := range parts {
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(p)))
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write([]byte(p))
	}
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], h.Sum64())
	const hex = "0123456789abcdef"
	dst := make([]byte, 16)
	for i, b := range out {
		dst[i*2] = hex[b>>4]
		dst[i*2+1] = hex[b&0x0f]
	}
	return string(dst)
}

// normalise returns a sorted, deduplicated, lowercased slice. Used by
// per-app parsers before storing into ConfigDerivedBehavior. Empty
// strings are dropped.
func normalise(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// normaliseCS is like normalise but preserves case. Used for path
// prefixes where case matters on Linux.
func normaliseCS(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// normaliseInts returns sorted, deduplicated ints.
func normaliseInts(in []int) []int {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, n := range in {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}
