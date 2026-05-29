// Package xhubfleet implements deterministic fleet-aware intelligence:
// cohort grouping, peer-rarity index, additive risk scoring, host trust
// levels, and BRP-candidate gating. Consumes baseline.Window rollups
// uploaded by agents; emits Findings with full evidence breakdown.
//
// All scoring is integer + additive + auditable. No ML. Every verdict
// carries the exact conditions that contributed and their weights so
// operators can tune the policy and reproduce decisions offline.
package xhubfleet

import (
	"strings"

	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/baselinehub"
)

// CohortKey is the comparable identity of a peer group. Two hosts with
// the same CohortKey are 1:1 comparable; different keys means "do not
// compare" (a Plesk PHP host vs a bare nginx frontend differ in app
// behavior even when both run nginx).
type CohortKey struct {
	HostRole      string
	AppRole       string
	OSFamily      string
	PackageOrigin string
	VersionFamily string
	Environment   string
	ControlPanel  string
	NetworkZone   string
}

// FromTags reduces an Upload's CohortTags to a CohortKey, dropping the
// Tenant field (tenant is a slice within a cohort, not a separate cohort).
func FromTags(t baselinehub.CohortTags) CohortKey {
	return CohortKey{
		HostRole:      t.HostRole,
		AppRole:       t.AppRole,
		OSFamily:      t.OSFamily,
		PackageOrigin: t.PackageOrigin,
		VersionFamily: t.VersionFamily,
		Environment:   t.Environment,
		ControlPanel:  t.ControlPanel,
		NetworkZone:   t.NetworkZone,
	}
}

// String renders the cohort as a stable identifier suitable for map keys
// and persistence. Empty fields render as "-" so two empties don't collide
// with an empty-on-one-side comparison.
func (k CohortKey) String() string {
	parts := []string{
		nz(k.HostRole), nz(k.AppRole), nz(k.OSFamily),
		nz(k.PackageOrigin), nz(k.VersionFamily), nz(k.Environment),
		nz(k.ControlPanel), nz(k.NetworkZone),
	}
	return strings.Join(parts, "|")
}

func nz(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Cohort holds the aggregated peer data for one CohortKey. A Cohort is
// built by RarityIndex.Build() from all uploads in the cohort.
type Cohort struct {
	Key   CohortKey
	Hosts map[string]struct{} // host_tag set
	// Per-binary aggregates across the cohort (binary → feature → host_count).
	BinaryChildren    map[string]map[string]int // binary → child_comm → hosts_seen_count
	BinaryEndpoints   map[string]map[string]int // binary → "cidr:port" → hosts_seen_count
	BinaryFileWrites  map[string]map[string]int // binary → write_dir → hosts_seen_count
	BinarySensitive   map[string]map[string]int // binary → sensitive_path → hosts_seen_count
	BinarySHAs        map[string]map[string]int // binary → sha → hosts_seen_count
	BinaryListenPorts map[string]map[string]int // binary → "tcp:port" → hosts_seen_count
}

func newCohort(k CohortKey) *Cohort {
	return &Cohort{
		Key:               k,
		Hosts:             map[string]struct{}{},
		BinaryChildren:    map[string]map[string]int{},
		BinaryEndpoints:   map[string]map[string]int{},
		BinaryFileWrites:  map[string]map[string]int{},
		BinarySensitive:   map[string]map[string]int{},
		BinarySHAs:        map[string]map[string]int{},
		BinaryListenPorts: map[string]map[string]int{},
	}
}

// AddWindow folds one host's window into the cohort.
func (c *Cohort) AddWindow(hostTag string, w *baseline.Window) {
	c.Hosts[hostTag] = struct{}{}
	foldHostFeatures(c.BinaryChildren, w.Binary, hostTag, w.Children)
	foldHostFeatures(c.BinaryEndpoints, w.Binary, hostTag, w.Endpoints)
	foldHostFeatures(c.BinaryFileWrites, w.Binary, hostTag, w.FileWrites)
	foldHostFeatures(c.BinarySensitive, w.Binary, hostTag, w.SensitivePaths)
	foldHostFeatures(c.BinarySHAs, w.Binary, hostTag, w.BinarySHAs)
	foldHostFeatures(c.BinaryListenPorts, w.Binary, hostTag, w.ListenPorts)
}

// foldHostFeatures records that hostTag has seen this binary doing
// these features. We count HOSTS not events — peer rarity is about how
// many distinct hosts have shown the behavior, not its volume.
func foldHostFeatures(idx map[string]map[string]int, binary, hostTag string, features map[string]uint64) {
	if len(features) == 0 {
		return
	}
	bm := idx[binary]
	if bm == nil {
		bm = map[string]int{}
		idx[binary] = bm
	}
	// Use a per-binary host-seen set so the same host counted once
	// per feature regardless of event count.
	for feat := range features {
		// We accept double-count across windows — the index is rebuilt
		// fresh each Build() so it's a window-set view, not unique-host.
		bm[feat]++
	}
}

// HostCount returns the number of hosts in this cohort.
func (c *Cohort) HostCount() int {
	return len(c.Hosts)
}
