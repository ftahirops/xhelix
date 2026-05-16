// Package activity clusters raw flows into logical activities —
// the human-readable unit of "what happened" in the narrative
// network history (docs/NETWORK_TELEMETRY_AND_HISTORY.md).
//
// One activity ≈ one user action ("user opened example.com",
// "snapd refreshed packages"). A page-load that fans out across
// 30 sub-resources collapses into a single activity row instead
// of 30 raw-flow rows, which is what makes the journal readable.
//
// Clustering rules (any of, anchored by same-process-and-time):
//   1. Same process (process_id equal) — always required
//   2. Time-overlap ≤ GapWindow between any two members
//   3. Either: shared DNS registrable domain, OR shared ASN, OR
//      the first member's DNS qname appears in another's headers
//      (we use ASN match as the proxy for "same CDN")
//
// The cluster's verdict is the worst verdict among members; the
// primary_host is the destination receiving the most incoming
// bytes (the actual page, not its CDN sub-fetches).
//
// This package is pure: Clusterer.Add(flow) accumulates,
// Clusterer.Flush(time) returns the closed activities. No I/O.
package activity

import (
	"sort"
	"strings"
	"time"
)

// Verdict is the activity-level outcome (string for SQLite friendliness).
type Verdict string

const (
	VerdictUnknown Verdict = ""
	VerdictGreen   Verdict = "green"
	VerdictAdvise  Verdict = "advise"
	VerdictAmber   Verdict = "amber"
	VerdictRed     Verdict = "red"
	VerdictOpaque  Verdict = "opaque" // encrypted destination, can't classify
)

// rank returns a comparable integer; higher = worse.
func rank(v Verdict) int {
	switch v {
	case VerdictGreen:
		return 1
	case VerdictAdvise:
		return 2
	case VerdictAmber:
		return 3
	case VerdictRed:
		return 4
	case VerdictOpaque:
		return 2 // between green and amber — informational
	}
	return 0
}

// worseOf returns the higher-ranked verdict.
func worseOf(a, b Verdict) Verdict {
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Flow is one observed L4 flow, the input to the clusterer.
type Flow struct {
	ProcessID int64
	Proto     string
	SrcIP     string
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	DNSQName  string // resolved domain, if known (empty on direct-IP)
	Country   string
	ASN       string
	OpenedAt  time.Time
	ClosedAt  time.Time // zero = still open at flush time
	BytesIn   uint64
	BytesOut  uint64
	Verdict   Verdict
	Reasons   []string
}

// Activity is one clustered output ready for storage.
type Activity struct {
	ProcessID    int64
	StartedAt    time.Time
	EndedAt      time.Time
	PrimaryHost  string
	RelatedHosts []string
	PrimaryIP    string
	RelatedIPs   []string
	Countries    []string
	ASNs         []string
	BytesIn      uint64
	BytesOut     uint64
	FlowCount    int
	Verdict      Verdict
	VerdictScore float64
	Reasons      []string
	Protocols    string

	// Flows holds the raw inputs that made this cluster. Caller
	// can re-attach activity_id to each Flow record on storage.
	Flows []Flow
}

// Clusterer maintains in-progress activities and flushes them
// when they go quiet for longer than GapWindow.
type Clusterer struct {
	GapWindow time.Duration

	// open is the in-progress set, keyed by process_id. We keep
	// the most recent activity per process; older ones are
	// returned by Flush as soon as they exceed GapWindow.
	open map[int64]*Activity
}

// New returns a Clusterer. gap<=0 selects 30s (NETWORK_TELEMETRY
// design default).
func New(gap time.Duration) *Clusterer {
	if gap <= 0 {
		gap = 30 * time.Second
	}
	return &Clusterer{GapWindow: gap, open: make(map[int64]*Activity)}
}

// Add ingests one flow. Returns any activity that became inactive
// because of this Add (i.e. the previous open activity for the
// same pid that didn't share intent with the new flow).
func (c *Clusterer) Add(f Flow) []Activity {
	if f.ProcessID == 0 {
		return nil
	}
	cur := c.open[f.ProcessID]
	if cur == nil {
		c.open[f.ProcessID] = c.newActivity(f)
		return nil
	}

	// New flow within GapWindow + same-cluster predicate → extend.
	if f.OpenedAt.Sub(cur.EndedAt) <= c.GapWindow && sameCluster(cur, f) {
		mergeFlow(cur, f)
		return nil
	}

	// Either too late or different cluster: close the old one,
	// start a new one.
	closed := *cur
	c.open[f.ProcessID] = c.newActivity(f)
	finalize(&closed)
	return []Activity{closed}
}

// Flush forces every still-open activity older than maxAge to
// close and be returned. Pass time.Time{} to flush everything
// regardless of age.
func (c *Clusterer) Flush(now time.Time) []Activity {
	out := make([]Activity, 0, len(c.open))
	for pid, a := range c.open {
		if !now.IsZero() && now.Sub(a.EndedAt) < c.GapWindow {
			continue
		}
		cp := *a
		finalize(&cp)
		out = append(out, cp)
		delete(c.open, pid)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].StartedAt.Before(out[j].StartedAt)
	})
	return out
}

// OpenCount returns the number of currently-open activities.
func (c *Clusterer) OpenCount() int { return len(c.open) }

// newActivity seeds an Activity from a first flow.
func (c *Clusterer) newActivity(f Flow) *Activity {
	a := &Activity{
		ProcessID: f.ProcessID,
		StartedAt: f.OpenedAt,
		EndedAt:   chooseEnd(f),
		BytesIn:   f.BytesIn,
		BytesOut:  f.BytesOut,
		FlowCount: 1,
		Verdict:   f.Verdict,
		Protocols: f.Proto,
		Flows:     []Flow{f},
	}
	if f.DNSQName != "" {
		a.PrimaryHost = f.DNSQName
	}
	if f.DstIP != "" {
		a.PrimaryIP = f.DstIP
	}
	if f.Country != "" {
		a.Countries = []string{f.Country}
	}
	if f.ASN != "" {
		a.ASNs = []string{f.ASN}
	}
	a.Reasons = appendUnique(a.Reasons, f.Reasons...)
	return a
}

// mergeFlow folds f into a.
func mergeFlow(a *Activity, f Flow) {
	a.Flows = append(a.Flows, f)
	a.FlowCount++
	a.BytesIn += f.BytesIn
	a.BytesOut += f.BytesOut
	if e := chooseEnd(f); e.After(a.EndedAt) {
		a.EndedAt = e
	}
	if f.OpenedAt.Before(a.StartedAt) {
		a.StartedAt = f.OpenedAt
	}
	a.Verdict = worseOf(a.Verdict, f.Verdict)

	if f.DNSQName != "" && f.DNSQName != a.PrimaryHost {
		a.RelatedHosts = appendUnique(a.RelatedHosts, f.DNSQName)
	}
	if f.DstIP != "" && f.DstIP != a.PrimaryIP {
		a.RelatedIPs = appendUnique(a.RelatedIPs, f.DstIP)
	}
	if f.Country != "" {
		a.Countries = appendUnique(a.Countries, f.Country)
	}
	if f.ASN != "" {
		a.ASNs = appendUnique(a.ASNs, f.ASN)
	}
	if f.Proto != "" && !strings.Contains(a.Protocols, f.Proto) {
		if a.Protocols == "" {
			a.Protocols = f.Proto
		} else {
			a.Protocols = a.Protocols + "," + f.Proto
		}
	}
	a.Reasons = appendUnique(a.Reasons, f.Reasons...)
}

// finalize promotes primary_host to the highest-bytes-in destination
// across the cluster's flows, replacing the seed if a later flow
// dominated. Also computes verdict_score.
func finalize(a *Activity) {
	if len(a.Flows) == 0 {
		return
	}
	// Aggregate bytes_in by domain (or IP if no domain) to pick
	// the actual page from its CDN sub-fetches.
	byHost := map[string]uint64{}
	byIP := map[string]uint64{}
	for _, f := range a.Flows {
		if f.DNSQName != "" {
			byHost[f.DNSQName] += f.BytesIn
		} else if f.DstIP != "" {
			byIP[f.DstIP] += f.BytesIn
		}
	}
	var bestHost string
	var bestBytes uint64
	for h, b := range byHost {
		if b > bestBytes || (b == bestBytes && bestHost == "") {
			bestHost, bestBytes = h, b
		}
	}
	if bestHost != "" {
		a.PrimaryHost = bestHost
		// Re-derive RelatedHosts to exclude the primary
		seen := map[string]bool{bestHost: true}
		a.RelatedHosts = a.RelatedHosts[:0]
		for _, f := range a.Flows {
			if f.DNSQName != "" && !seen[f.DNSQName] {
				seen[f.DNSQName] = true
				a.RelatedHosts = append(a.RelatedHosts, f.DNSQName)
			}
		}
		sort.Strings(a.RelatedHosts)
	}
	// Same for primary_ip when no DNS at all
	if a.PrimaryHost == "" {
		var bestIP string
		bestBytes = 0
		for ip, b := range byIP {
			if b > bestBytes || (b == bestBytes && bestIP == "") {
				bestIP, bestBytes = ip, b
			}
		}
		if bestIP != "" {
			a.PrimaryIP = bestIP
		}
	}
	// VerdictScore: simple inversion — green=95, advise=70,
	// amber=40, red=10, opaque=60. Real model arrives with Tier 2
	// ML; this gives the UI a comparable number now.
	switch a.Verdict {
	case VerdictGreen:
		a.VerdictScore = 95
	case VerdictAdvise:
		a.VerdictScore = 70
	case VerdictOpaque:
		a.VerdictScore = 60
	case VerdictAmber:
		a.VerdictScore = 40
	case VerdictRed:
		a.VerdictScore = 10
	default:
		a.VerdictScore = 0
	}
	// Sort country / ASN slices for stable output
	sort.Strings(a.Countries)
	sort.Strings(a.ASNs)
	sort.Strings(a.RelatedIPs)
	sort.Strings(a.Reasons)
}

// sameCluster decides whether f is "the same activity" as a's
// existing membership. The predicate is:
//   - shared DNS registrable root, OR
//   - shared destination ASN, OR
//   - no DNS at all and same dst IP (rare retry case)
func sameCluster(a *Activity, f Flow) bool {
	// Direct shared host: definitely same.
	if f.DNSQName != "" && (f.DNSQName == a.PrimaryHost ||
		contains(a.RelatedHosts, f.DNSQName)) {
		return true
	}
	// Registrable-root match (e.g. "fonts.gstatic.com" and
	// "gstatic.com" share root "gstatic.com"). We use the last
	// 2-label approximation; this misses public-suffix-list
	// edge cases (.co.uk etc.) but is fine for clustering.
	if f.DNSQName != "" {
		root := registrableRoot(f.DNSQName)
		if root != "" {
			if registrableRoot(a.PrimaryHost) == root {
				return true
			}
			for _, rh := range a.RelatedHosts {
				if registrableRoot(rh) == root {
					return true
				}
			}
		}
	}
	// Same ASN — common CDN clustering signal.
	if f.ASN != "" && contains(a.ASNs, f.ASN) {
		return true
	}
	// Same dst IP, no DNS.
	if f.DNSQName == "" && f.DstIP != "" && f.DstIP == a.PrimaryIP {
		return true
	}
	return false
}

// registrableRoot returns the last 2 labels of a domain. Coarse
// approximation of the public-suffix-list "registrable root."
// "fonts.gstatic.com" -> "gstatic.com".
func registrableRoot(d string) string {
	if d == "" {
		return ""
	}
	parts := strings.Split(strings.ToLower(strings.TrimSuffix(d, ".")), ".")
	if len(parts) < 2 {
		return d
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// chooseEnd returns the flow's effective end time — ClosedAt if
// set, otherwise OpenedAt (the conservative "still open right
// now" assumption).
func chooseEnd(f Flow) time.Time {
	if !f.ClosedAt.IsZero() {
		return f.ClosedAt
	}
	return f.OpenedAt
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}

func appendUnique(s []string, vs ...string) []string {
	for _, v := range vs {
		if v == "" || contains(s, v) {
			continue
		}
		s = append(s, v)
	}
	return s
}
