// Package catalog classifies sensitive data and assigns sensitivity
// points. It is the source of truth for the DLCF subsystem (P7).
//
// The catalog answers four questions:
//
//  1. Given a table name, which data class(es) does it carry?
//  2. Given a file path or glob, which data class(es) does it carry?
//  3. Given a secret pattern (regex), which data class does it match?
//  4. Given a route, which data classes is it permitted to touch?
//
// The catalog is loaded from YAML, validated on load, and hot-reloadable.
// Lookups are O(1) for tables and patterns, O(n) for path globs (n is
// typically < 100, so this is fine).
package catalog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// DataClass is a coarse-grained label for a kind of sensitive data.
// New classes are added to the bitset in pkg/lineage as needed; the
// string form here is what operators write in YAML.
type DataClass string

const (
	ClassPII           DataClass = "pii"
	ClassCredentials   DataClass = "credentials"
	ClassPaymentToken  DataClass = "payment_token"
	ClassCustomerOrder DataClass = "customer_order"
	ClassAPIKey        DataClass = "api_key"
	ClassSourceCode    DataClass = "source_code"
	ClassBackup        DataClass = "backup"
	ClassCanary        DataClass = "canary"
	ClassPublic        DataClass = "public"
)

// Points is the sensitivity weight assigned to a single touch event
// involving the class. Budgets are denominated in Points.
type Points uint32

// Catalog is the loaded, validated classification table. It is safe
// for concurrent reads; reloads atomically swap the underlying maps
// under a write lock.
type Catalog struct {
	mu sync.RWMutex

	// Sensitivity weight per class.
	pointsByClass map[DataClass]Points

	// Table classifications. Key is normalized (lowercased).
	tableClasses map[string][]DataClass

	// File path globs paired with their classes. Evaluated in
	// declaration order; first match wins.
	pathGlobs []pathGlob

	// Secret regexes. First match wins.
	secretPatterns []secretPattern

	// Route → allowed classes map. Used by the rule engine to
	// detect a route touching data it shouldn't.
	routeAllowed map[string]map[DataClass]struct{}

	// Canary users: explicit uids and inclusive ranges. No
	// legitimate consumer touches these — see P-B.1 in
	// BEHAVIORAL_DEFENSE.md. Lookup is O(N) over ranges + O(1) for
	// explicit uids; total entries are operator-bounded.
	canaryUIDs   map[uint64]struct{}
	canaryRanges []uidRange

	// Canary routes: exact and prefix patterns. Trailing "/" means
	// prefix; otherwise exact. /admin-legacy/, /api/v0/, etc.
	canaryRouteExact  map[string]struct{}
	canaryRoutePrefix []string

	// LOTL ("living off the land") classification — see
	// BEHAVIORAL_DEFENSE.md §3.8. Lookup is O(1) for the binary,
	// O(N) over parent classes (typically 3-5).
	lotlBinaries     map[string]lotlBinary
	lotlParentClasses []lotlParentClass

	// Source path, for reload + diagnostics.
	source string
}

type pathGlob struct {
	Glob    string
	Classes []DataClass
}

// uidRange is a closed inclusive range of canary user ids.
type uidRange struct {
	Low, High uint64
}

// LOTLScore is the risk score (0-100) for a (binary, parent context)
// pair. Used by the dispatch loop's exec-event enrichment per
// BEHAVIORAL_DEFENSE.md §3.8 (P-B.7).
type LOTLScore uint8

// lotlBinary holds the LOTL classification for one binary name.
type lotlBinary struct {
	BaseRisk LOTLScore
	// parentRisk overrides BaseRisk * multiplier with an explicit
	// score when a specific parent_comm matches.
	parentRisk map[string]LOTLScore
}

// lotlParentClass classifies a set of parent comms as a risk category
// (e.g. "web_tier" / "scheduler") with a multiplier applied to the
// binary's BaseRisk.
type lotlParentClass struct {
	Name       string
	comms      map[string]struct{}
	Multiplier float32
}

type secretPattern struct {
	Name    string
	Re      *regexp.Regexp
	Classes []DataClass
}

// fileSchema mirrors the on-disk YAML one-to-one.
type fileSchema struct {
	Version int `yaml:"version"`

	Points map[string]uint32 `yaml:"sensitivity_points"`

	Tables []struct {
		Match   []string `yaml:"match"`
		Classes []string `yaml:"classes"`
	} `yaml:"tables"`

	Paths []struct {
		Glob    string   `yaml:"glob"`
		Classes []string `yaml:"classes"`
	} `yaml:"paths"`

	Secrets []struct {
		Name    string   `yaml:"name"`
		Regex   string   `yaml:"regex"`
		Classes []string `yaml:"classes"`
	} `yaml:"secrets"`

	Routes []struct {
		Match   []string `yaml:"match"`
		Allowed []string `yaml:"allowed_classes"`
	} `yaml:"routes"`

	CanaryUIDs []struct {
		UID  uint64 `yaml:"uid,omitempty"`
		From uint64 `yaml:"from,omitempty"`
		To   uint64 `yaml:"to,omitempty"`
	} `yaml:"canary_uids"`

	CanaryRoutes []string `yaml:"canary_routes"`

	LOTL struct {
		Binaries []struct {
			Name       string             `yaml:"name"`
			BaseRisk   uint8              `yaml:"base_risk"`
			ParentRisk map[string]uint8   `yaml:"parent_risk"` // parent_comm → explicit score
		} `yaml:"binaries"`
		ParentClasses []struct {
			Name       string   `yaml:"name"`
			Comms      []string `yaml:"comms"`
			Multiplier float32  `yaml:"multiplier"`
		} `yaml:"parent_classes"`
	} `yaml:"lotl"`
}

// Load reads and validates a catalog from path. Returns a *Catalog
// ready for concurrent reads. Returns an error if the file is
// missing, unreadable, malformed, or fails validation (unknown
// class, bad regex, conflicting points).
func Load(path string) (*Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("catalog read: %w", err)
	}
	c, err := parse(raw)
	if err != nil {
		return nil, fmt.Errorf("catalog parse: %w", err)
	}
	c.source = path
	return c, nil
}

// Reload re-reads the catalog's source path and atomically swaps
// the live data. Lookups in flight see a consistent old-or-new view.
func (c *Catalog) Reload() error {
	if c.source == "" {
		return errors.New("catalog: no source path set (was the catalog constructed via Load?)")
	}
	fresh, err := Load(c.source)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pointsByClass = fresh.pointsByClass
	c.tableClasses = fresh.tableClasses
	c.pathGlobs = fresh.pathGlobs
	c.secretPatterns = fresh.secretPatterns
	c.routeAllowed = fresh.routeAllowed
	c.canaryUIDs = fresh.canaryUIDs
	c.canaryRanges = fresh.canaryRanges
	c.canaryRouteExact = fresh.canaryRouteExact
	c.canaryRoutePrefix = fresh.canaryRoutePrefix
	c.lotlBinaries = fresh.lotlBinaries
	c.lotlParentClasses = fresh.lotlParentClasses
	return nil
}

func parse(raw []byte) (*Catalog, error) {
	var f fileSchema
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported catalog version: %d (expected 1)", f.Version)
	}

	c := &Catalog{
		pointsByClass:    make(map[DataClass]Points, len(f.Points)),
		tableClasses:     make(map[string][]DataClass),
		routeAllowed:     make(map[string]map[DataClass]struct{}),
		canaryUIDs:       make(map[uint64]struct{}),
		canaryRouteExact: make(map[string]struct{}),
		lotlBinaries:     make(map[string]lotlBinary),
	}

	for k, v := range f.Points {
		c.pointsByClass[DataClass(k)] = Points(v)
	}

	// Canary is always present and always at the maximum useful weight;
	// operators are not allowed to silence it via low points.
	if _, ok := c.pointsByClass[ClassCanary]; !ok {
		c.pointsByClass[ClassCanary] = 10_000
	}

	for _, t := range f.Tables {
		classes, err := classesOf(c, t.Classes)
		if err != nil {
			return nil, fmt.Errorf("tables: %w", err)
		}
		for _, m := range t.Match {
			key := strings.ToLower(m)
			c.tableClasses[key] = append(c.tableClasses[key], classes...)
		}
	}

	for _, p := range f.Paths {
		classes, err := classesOf(c, p.Classes)
		if err != nil {
			return nil, fmt.Errorf("paths: %w", err)
		}
		// Validate the glob compiles.
		if _, err := filepath.Match(p.Glob, ""); err != nil {
			return nil, fmt.Errorf("paths: bad glob %q: %w", p.Glob, err)
		}
		c.pathGlobs = append(c.pathGlobs, pathGlob{Glob: p.Glob, Classes: classes})
	}

	for _, s := range f.Secrets {
		re, err := regexp.Compile(s.Regex)
		if err != nil {
			return nil, fmt.Errorf("secrets %q: %w", s.Name, err)
		}
		classes, err := classesOf(c, s.Classes)
		if err != nil {
			return nil, fmt.Errorf("secrets %q: %w", s.Name, err)
		}
		c.secretPatterns = append(c.secretPatterns, secretPattern{
			Name: s.Name, Re: re, Classes: classes,
		})
	}

	for _, cu := range f.CanaryUIDs {
		if cu.UID != 0 {
			c.canaryUIDs[cu.UID] = struct{}{}
		}
		if cu.From != 0 || cu.To != 0 {
			lo, hi := cu.From, cu.To
			if hi < lo {
				lo, hi = hi, lo
			}
			c.canaryRanges = append(c.canaryRanges, uidRange{Low: lo, High: hi})
		}
	}

	for _, b := range f.LOTL.Binaries {
		if b.Name == "" {
			continue
		}
		entry := lotlBinary{
			BaseRisk:   LOTLScore(b.BaseRisk),
			parentRisk: make(map[string]LOTLScore, len(b.ParentRisk)),
		}
		for parent, score := range b.ParentRisk {
			entry.parentRisk[parent] = LOTLScore(score)
		}
		c.lotlBinaries[b.Name] = entry
	}
	for _, pc := range f.LOTL.ParentClasses {
		if pc.Name == "" || len(pc.Comms) == 0 {
			continue
		}
		comms := make(map[string]struct{}, len(pc.Comms))
		for _, comm := range pc.Comms {
			comms[comm] = struct{}{}
		}
		mult := pc.Multiplier
		if mult < 0 {
			mult = 0
		}
		c.lotlParentClasses = append(c.lotlParentClasses, lotlParentClass{
			Name:       pc.Name,
			comms:      comms,
			Multiplier: mult,
		})
	}

	for _, route := range f.CanaryRoutes {
		if route == "" {
			continue
		}
		if strings.HasSuffix(route, "/") {
			c.canaryRoutePrefix = append(c.canaryRoutePrefix, route)
		} else {
			c.canaryRouteExact[route] = struct{}{}
		}
	}

	for _, r := range f.Routes {
		classes, err := classesOf(c, r.Allowed)
		if err != nil {
			return nil, fmt.Errorf("routes: %w", err)
		}
		set := make(map[DataClass]struct{}, len(classes))
		for _, cl := range classes {
			set[cl] = struct{}{}
		}
		for _, m := range r.Match {
			c.routeAllowed[m] = set
		}
	}

	return c, nil
}

// classesOf parses a YAML list of class strings, validates each
// against the points table (an unknown class is an error — it would
// silently weigh zero otherwise), and returns the typed slice.
func classesOf(c *Catalog, names []string) ([]DataClass, error) {
	out := make([]DataClass, 0, len(names))
	for _, n := range names {
		cl := DataClass(n)
		if _, ok := c.pointsByClass[cl]; !ok {
			return nil, fmt.Errorf("unknown data class %q (missing from sensitivity_points)", n)
		}
		out = append(out, cl)
	}
	return out, nil
}

// PointsFor returns the sensitivity weight for class. Returns 0 for
// unknown classes — callers should treat that as "no contribution
// to the budget" rather than an error, since unknown classes can
// legitimately arrive from older event sources during a rolling
// upgrade.
func (c *Catalog) PointsFor(cl DataClass) Points {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pointsByClass[cl]
}

// ClassesForTable returns the data classes associated with a table.
// The name is matched case-insensitively. Returns nil if the table
// is unclassified.
func (c *Catalog) ClassesForTable(name string) []DataClass {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tableClasses[strings.ToLower(name)]
}

// ClassesForPath returns the data classes associated with a file
// path. Globs are evaluated in declaration order; first match wins.
// Returns nil if no glob matches.
func (c *Catalog) ClassesForPath(path string) []DataClass {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, g := range c.pathGlobs {
		if ok, _ := filepath.Match(g.Glob, path); ok {
			return g.Classes
		}
	}
	return nil
}

// ClassesForSecret returns the data classes if any secret regex
// matches the input string. First match wins.
func (c *Catalog) ClassesForSecret(s string) (name string, classes []DataClass, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, p := range c.secretPatterns {
		if p.Re.MatchString(s) {
			return p.Name, p.Classes, true
		}
	}
	return "", nil, false
}

// RouteAllows reports whether the given route is permitted to touch
// the given data class. A route absent from the catalog returns
// (false, false): "no policy declared" — callers decide whether to
// treat that as default-allow or default-deny.
func (c *Catalog) RouteAllows(route string, cl DataClass) (allowed, hasPolicy bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	set, ok := c.routeAllowed[route]
	if !ok {
		return false, false
	}
	_, allowed = set[cl]
	return allowed, true
}

// IsCanaryUID reports whether the given user id matches any declared
// canary uid or range. Used by the App DB tap and other identity-
// aware sensors to stamp `data_classes=canary` on events that touch
// a planted user. Zero false positives by construction — operators
// declare canary uids that no legitimate workflow references.
func (c *Catalog) IsCanaryUID(uid uint64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.canaryUIDs[uid]; ok {
		return true
	}
	for _, r := range c.canaryRanges {
		if uid >= r.Low && uid <= r.High {
			return true
		}
	}
	return false
}

// IsCanaryRoute reports whether the given HTTP route is a planted
// canary. Operators name routes that no legitimate client should
// ever request (e.g. /api/v0/debug, /admin-legacy/). Used by the
// Request Contract layer to tag the contract — and every downstream
// event — with `data_classes=canary` for instant-fire detection.
//
// Trailing "/" in a declared pattern means prefix match; otherwise
// exact match.
func (c *Catalog) IsCanaryRoute(route string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.canaryRouteExact[route]; ok {
		return true
	}
	for _, p := range c.canaryRoutePrefix {
		if strings.HasPrefix(route, p) {
			return true
		}
	}
	return false
}

// LOTLScore computes the living-off-the-land risk score for an exec
// event with binary name `comm` spawned by `parentComm`. Returns
// (score, true) if the binary is classified; (0, false) otherwise —
// callers should treat unknown binaries as "not LOTL-scorable", not
// "score 0".
//
// Scoring algorithm (per BEHAVIORAL_DEFENSE.md §3.8):
//
//  1. Look up the binary. If unknown, return (0, false).
//  2. If the binary has an explicit parent_risk for parentComm, use
//     that value directly. Operators can pin specific edge cases
//     (e.g. "bash spawned by php-fpm is 100").
//  3. Otherwise walk parent_classes in declaration order; the first
//     class matching parentComm contributes its multiplier × BaseRisk.
//     Clamped to 100.
//  4. No class match → return BaseRisk alone.
//
// All operations under the read lock — sub-microsecond.
func (c *Catalog) LOTLScore(comm, parentComm string) (LOTLScore, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	b, ok := c.lotlBinaries[comm]
	if !ok {
		return 0, false
	}

	// Explicit per-parent override wins.
	if parentComm != "" {
		if score, ok := b.parentRisk[parentComm]; ok {
			return score, true
		}
	}

	// Parent-class multiplier.
	for _, pc := range c.lotlParentClasses {
		if _, ok := pc.comms[parentComm]; ok {
			scaled := float32(b.BaseRisk) * pc.Multiplier
			if scaled > 100 {
				scaled = 100
			}
			return LOTLScore(scaled), true
		}
	}

	return b.BaseRisk, true
}

// LOTLBinary returns whether comm is a tracked LOTL binary at all,
// without computing a score. Useful for the dispatch enricher's
// fast-path skip.
func (c *Catalog) LOTLBinary(comm string) bool {
	c.mu.RLock()
	_, ok := c.lotlBinaries[comm]
	c.mu.RUnlock()
	return ok
}

// Stats returns counters useful for the health.snapshot LocalAPI
// handler and operator introspection.
type Stats struct {
	Classes        int    `json:"classes"`
	Tables         int    `json:"tables"`
	PathGlobs      int    `json:"path_globs"`
	SecretPatterns int    `json:"secret_patterns"`
	Routes         int    `json:"routes"`
	CanaryUIDs     int    `json:"canary_uids"`
	CanaryRanges   int    `json:"canary_uid_ranges"`
	CanaryRoutes   int    `json:"canary_routes"`
	Source         string `json:"source,omitempty"`
}

func (c *Catalog) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Stats{
		Classes:        len(c.pointsByClass),
		Tables:         len(c.tableClasses),
		PathGlobs:      len(c.pathGlobs),
		SecretPatterns: len(c.secretPatterns),
		Routes:         len(c.routeAllowed),
		CanaryUIDs:     len(c.canaryUIDs),
		CanaryRanges:   len(c.canaryRanges),
		CanaryRoutes:   len(c.canaryRouteExact) + len(c.canaryRoutePrefix),
		Source:         c.source,
	}
}
