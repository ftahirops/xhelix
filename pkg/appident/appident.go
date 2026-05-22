// Package appident derives a stable application identity from process
// observation signals. It powers the analytics layer described in
// docs/EGRESS_C2_DISARM_AND_BINARY_INTEGRITY_2026-05-22.md so that
// a host running multiple WordPress sites can answer "how much
// outbound did SITE-A do today, vs SITE-B?" rather than "how much
// outbound did /usr/sbin/php-fpm8.2 do today?"
//
// Identification has two layers, identical in spirit to credbroker's
// Layer-1 / Layer-2 split:
//
//   - Layer 1 — built-in heuristics. Match against cgroup unit name,
//     exe path, argv substrings to derive an AppID without any
//     operator config. Covers nginx vhosts, php-fpm pools, well-known
//     binaries, container images.
//
//   - Layer 2 — operator declarations under /etc/xhelix/apps.d/*.yaml.
//     A YAML file declares an app name + match conditions. Layer 2
//     takes precedence over Layer 1 when both match.
//
// Identity is sticky per lineage: once a process tree is identified
// as "wordpress:site-a", every subsequent event from that lineage
// carries the same tag, so analytics roll up correctly even when the
// originating signal isn't available on every event.
package appident

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Kind classifies the app shape — used for default policy templating
// later (e.g. "web" apps have implicit known-good destinations like
// CDN and registry; "service" apps don't).
type Kind string

const (
	KindUnknown    Kind = ""
	KindWeb        Kind = "web"
	KindService    Kind = "service"
	KindCLI        Kind = "cli"
	KindBackground Kind = "background"
	KindContainer  Kind = "container"
)

// AppID is the identity stamped on every event from a given lineage.
type AppID struct {
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// Vhost is optional, set when the app is a web vhost / virtual
	// host. For "wordpress:site-a" Vhost would be "site-a.com".
	Vhost string `json:"vhost,omitempty"`
	// Source records which matcher produced this identity for audit.
	Source string `json:"source,omitempty"`
}

// String returns "name[:vhost]" for display.
func (a AppID) String() string {
	if a.Name == "" {
		return "(unidentified)"
	}
	if a.Vhost != "" {
		return a.Name + ":" + a.Vhost
	}
	return a.Name
}

// Empty reports whether identification failed.
func (a AppID) Empty() bool { return a.Name == "" }

// Declaration is the operator-supplied YAML shape under apps.d/.
//
//	app: my-wordpress-site-a
//	kind: web
//	vhost: site-a.com
//	match:
//	  cgroup_substring: "php-fpm@site-a"
//	  exe_path: /usr/sbin/php-fpm8.2
//	  argv_substring: "/etc/nginx/sites-enabled/site-a.conf"
//	  exe_regex: '^/opt/myapp/bin/.*'
//
// Any single match clause that hits = the whole declaration matches
// (OR semantics).
type Declaration struct {
	App   string     `yaml:"app"`
	Kind  Kind       `yaml:"kind"`
	Vhost string     `yaml:"vhost"`
	Match MatchRules `yaml:"match"`
	// Compiled state.
	exeRegex *regexp.Regexp
}

// MatchRules is the OR-set of identifying signals.
type MatchRules struct {
	CgroupSubstring []string `yaml:"cgroup_substring,omitempty"`
	ExePath         []string `yaml:"exe_path,omitempty"`
	ExeRegex        []string `yaml:"exe_regex,omitempty"`
	ArgvSubstring   []string `yaml:"argv_substring,omitempty"`
	ParentImage     []string `yaml:"parent_image,omitempty"`
}

// LoadDecls reads /etc/xhelix/apps.d/*.yaml. Missing dir is not an
// error (returns empty slice). Per-file parse errors are collected.
func LoadDecls(dir string) ([]Declaration, []error) {
	var decls []Declaration
	var errs []error
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []error{fmt.Errorf("read %s: %w", dir, err)}
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var d Declaration
		if err := yaml.Unmarshal(data, &d); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", n, err))
			continue
		}
		if d.App == "" {
			errs = append(errs, fmt.Errorf("%s: app field required", n))
			continue
		}
		for _, p := range d.Match.ExeRegex {
			r, err := regexp.Compile(p)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: exe_regex %q: %w", n, p, err))
				continue
			}
			d.exeRegex = r
		}
		decls = append(decls, d)
	}
	return decls, errs
}

// Signals are what the identifier examines to derive an AppID.
type Signals struct {
	LineageID    uint64
	CgroupPath   string   // e.g. /system.slice/php-fpm@site-a.service
	ExePath      string
	ArgvJoined   string   // single space-joined argv string
	ParentImages []string // ancestor exe paths (best-effort)
}

// Identifier is goroutine-safe and caches per-lineage identity so
// repeated calls for the same lineage return the same AppID without
// re-matching.
type Identifier struct {
	decls []Declaration

	mu    sync.RWMutex
	cache map[uint64]AppID
}

// New constructs an Identifier from a declaration set (may be nil/empty).
func New(decls []Declaration) *Identifier {
	return &Identifier{
		decls: decls,
		cache: map[uint64]AppID{},
	}
}

// Identify returns the AppID for the given signals. Results are
// cached by LineageID; the first call computes, later calls are
// O(1) map lookups.
func (i *Identifier) Identify(s Signals) AppID {
	if s.LineageID != 0 {
		i.mu.RLock()
		a, ok := i.cache[s.LineageID]
		i.mu.RUnlock()
		if ok {
			return a
		}
	}
	a := i.compute(s)
	if s.LineageID != 0 {
		i.mu.Lock()
		i.cache[s.LineageID] = a
		i.mu.Unlock()
	}
	return a
}

// Forget evicts a cache entry — called when a lineage exits.
func (i *Identifier) Forget(lid uint64) {
	i.mu.Lock()
	delete(i.cache, lid)
	i.mu.Unlock()
}

func (i *Identifier) compute(s Signals) AppID {
	// Layer 2 first: operator decls win over heuristics.
	for _, d := range i.decls {
		if matchesDecl(s, d) {
			return AppID{
				Name:   d.App,
				Kind:   d.Kind,
				Vhost:  d.Vhost,
				Source: "decl:" + d.App,
			}
		}
	}
	// Layer 1: heuristics in priority order.
	if a, ok := heuristicNginxVhost(s); ok {
		return a
	}
	if a, ok := heuristicPHPFPMPool(s); ok {
		return a
	}
	if a, ok := heuristicSystemdUnit(s); ok {
		return a
	}
	if a, ok := heuristicContainer(s); ok {
		return a
	}
	if a, ok := heuristicExeBasename(s); ok {
		return a
	}
	return AppID{}
}

func matchesDecl(s Signals, d Declaration) bool {
	for _, sub := range d.Match.CgroupSubstring {
		if sub != "" && strings.Contains(s.CgroupPath, sub) {
			return true
		}
	}
	for _, p := range d.Match.ExePath {
		if p != "" && s.ExePath == p {
			return true
		}
	}
	if d.exeRegex != nil && d.exeRegex.MatchString(s.ExePath) {
		return true
	}
	for _, sub := range d.Match.ArgvSubstring {
		if sub != "" && strings.Contains(s.ArgvJoined, sub) {
			return true
		}
	}
	for _, img := range d.Match.ParentImage {
		for _, p := range s.ParentImages {
			if img == p {
				return true
			}
		}
	}
	return false
}

// ─── Layer-1 heuristics ────────────────────────────────────────────

// nginx -c /etc/nginx/sites-enabled/<name>.conf or vhost via argv
var nginxArgvRE = regexp.MustCompile(`/etc/nginx/sites[-_]?enabled/([^/.\s]+)`)

func heuristicNginxVhost(s Signals) (AppID, bool) {
	if !strings.Contains(s.ExePath, "nginx") {
		return AppID{}, false
	}
	if m := nginxArgvRE.FindStringSubmatch(s.ArgvJoined); len(m) == 2 {
		return AppID{Name: "nginx", Vhost: m[1], Kind: KindWeb, Source: "heuristic:nginx_vhost"}, true
	}
	return AppID{Name: "nginx", Kind: KindWeb, Source: "heuristic:nginx"}, true
}

// php-fpm pool name from cgroup like php-fpm@<pool>.service or argv
var phpfpmCgroupRE = regexp.MustCompile(`php[-_]fpm[@:]([^./\s]+)`)
var phpfpmArgvRE = regexp.MustCompile(`pool\s+([^\s]+)`)

func heuristicPHPFPMPool(s Signals) (AppID, bool) {
	if !strings.Contains(s.ExePath, "php-fpm") {
		return AppID{}, false
	}
	if m := phpfpmCgroupRE.FindStringSubmatch(s.CgroupPath); len(m) == 2 {
		return AppID{Name: "php-fpm", Vhost: m[1], Kind: KindWeb, Source: "heuristic:phpfpm_cgroup"}, true
	}
	if m := phpfpmArgvRE.FindStringSubmatch(s.ArgvJoined); len(m) == 2 {
		return AppID{Name: "php-fpm", Vhost: m[1], Kind: KindWeb, Source: "heuristic:phpfpm_argv"}, true
	}
	return AppID{Name: "php-fpm", Kind: KindWeb, Source: "heuristic:phpfpm"}, true
}

// systemd unit name from cgroup like /system.slice/<unit>.service
var systemdUnitRE = regexp.MustCompile(`/system\.slice/(?:[^/]+/)?([^/]+)\.service`)

func heuristicSystemdUnit(s Signals) (AppID, bool) {
	if m := systemdUnitRE.FindStringSubmatch(s.CgroupPath); len(m) == 2 {
		name := m[1]
		// Strip @instance from templated units (foo@bar -> foo).
		// We keep the instance as vhost when it looks like an identifier.
		if at := strings.Index(name, "@"); at > 0 {
			return AppID{Name: name[:at], Vhost: name[at+1:], Kind: KindService, Source: "heuristic:systemd_template"}, true
		}
		return AppID{Name: name, Kind: KindService, Source: "heuristic:systemd_unit"}, true
	}
	return AppID{}, false
}

// container app from cgroup like /docker/<id>/ or /system.slice/docker-<id>.scope
var containerCgroupRE = regexp.MustCompile(`docker[-/]([0-9a-f]{6,12})`)

func heuristicContainer(s Signals) (AppID, bool) {
	if m := containerCgroupRE.FindStringSubmatch(s.CgroupPath); len(m) == 2 {
		return AppID{Name: "docker", Vhost: m[1][:12], Kind: KindContainer, Source: "heuristic:docker_cgroup"}, true
	}
	return AppID{}, false
}

func heuristicExeBasename(s Signals) (AppID, bool) {
	if s.ExePath == "" {
		return AppID{}, false
	}
	base := filepath.Base(s.ExePath)
	// Strip version suffix like "php8.2" → "php" only for well-known prefixes.
	for _, fam := range []string{"python", "ruby", "node", "perl", "php"} {
		if strings.HasPrefix(base, fam) {
			return AppID{Name: fam, Kind: KindBackground, Source: "heuristic:exe_basename_strip"}, true
		}
	}
	return AppID{Name: base, Kind: KindBackground, Source: "heuristic:exe_basename"}, true
}
