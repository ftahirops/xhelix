// Package web — egress intelligence endpoints (countries, companies,
// connections, overview). Consumes geoip + destclass + connstate via
// small interfaces so the web layer doesn't import those packages
// directly; the daemon wires concrete implementations in
// cmd/xhelix/run.go via SetGeoIP / SetDestClass / SetConnstate.
//
// All endpoints are nil-safe: when a provider isn't wired up they
// return an empty array / sensible default so the dashboard still
// renders.
package web

import (
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/egressledger"
)

// ── Provider interfaces ───────────────────────────────────────

// GeoIPLookup is the minimum surface the egress UI needs from
// pkg/geoip. Returning ok=false means "couldn't resolve" — UI shows
// "—" for country / ASN.
type GeoIPLookup interface {
	Lookup(ip string) (country, asn, org string, ok bool)
}

// DestClassify wraps pkg/destclass.Classifier so the web layer
// doesn't import it. ip may be nil → returns "unknown".
type DestClassify interface {
	Classify(ip net.IP, sni string, port uint16) string
	// ClassFromPTR maps a reverse-DNS name to a cdn/cloud class + operator
	// org, or ("","") if no known suffix matches. Enriches the IP-info
	// view from rDNS.
	ClassFromPTR(ptr string) (class, org string)
}

// ConnSnap is a closure-form provider for connstate.Snapshot(). We
// model it as a function returning []ConnView so the web layer
// doesn't depend on pkg/connstate.
type ConnSnap func() []ConnView

// ProcTreeLookup resolves a PID's parent comm (and optionally the
// chain). Returns "" if the PID isn't known. Daemon wires this via
// SetProcTree using a proctree.Graph adapter.
type ProcTreeLookup interface {
	ParentComm(pid uint32) string
}

// SetProcTree wires the proctree provider. Nil-safe.
func (s *Server) SetProcTree(p ProcTreeLookup) { s.proctree = p }

// ConnView is the projection of pkg/connstate.Conn the UI needs.
// The daemon converts connstate.Conn → ConnView at the boundary.
type ConnView struct {
	PID         uint32 `json:"pid"`
	PPID        uint32 `json:"ppid"`
	Comm        string `json:"comm"`
	Exe         string `json:"exe"`
	ExeSHA      string `json:"exe_sha"`
	Proto       string `json:"proto"`
	State       string `json:"state"`
	Direction   string `json:"direction"`
	SrcAddr     string `json:"src_addr"`
	SrcPort     uint16 `json:"src_port"`
	DstAddr     string `json:"dst_addr"`
	DstPort     uint16 `json:"dst_port"`
	DNSName     string `json:"dns_name"`
	SNI         string `json:"sni"`
	BytesOut    uint64 `json:"bytes_out"`
	BytesIn     uint64 `json:"bytes_in"`
	OpenedAt    int64  `json:"opened_at"` // unix seconds
	LastSeen    int64  `json:"last_seen"`
	CGroupClass string `json:"cgroup_class"`
	Unit        string `json:"unit"`
	UserID      string `json:"user_id"`
}

// SetGeoIP wires the geoip provider. Nil-safe.
func (s *Server) SetGeoIP(g GeoIPLookup) { s.geoip = g }

// SetDestClass wires the destination classifier. Nil-safe.
func (s *Server) SetDestClass(c DestClassify) { s.destclass = c }

// SetConnstate wires the live conn-table snapshot closure. Nil-safe.
func (s *Server) SetConnstate(fn ConnSnap) { s.connstateSnap = fn }

// AlertSnap returns the most recent N alerts (newest first or any
// order — the country drilldown filters and re-sorts). Wired by the
// daemon via SetAlertSnap (typically from alert.RingSink.Snapshot).
type AlertSnap func() []AlertSummary

// AlertSummary is the projection of model.Alert the UI needs for
// drilldowns. Daemon converts model.Alert → AlertSummary at the
// boundary so the web layer doesn't pull in pkg/model.
type AlertSummary struct {
	Time   time.Time `json:"time"`
	RuleID string    `json:"rule_id"`
	Reason string    `json:"reason,omitempty"`
	Action string    `json:"action,omitempty"`
	Class  int       `json:"class,omitempty"`
	DstIP  string    `json:"dst_ip,omitempty"`
	SrcIP  string    `json:"src_ip,omitempty"`
	PID    uint32    `json:"pid,omitempty"`
	Binary string    `json:"binary,omitempty"`
}

// SetAlertSnap wires the alert snapshot provider. Nil-safe.
func (s *Server) SetAlertSnap(fn AlertSnap) { s.alertSnap = fn }

// RegisterEgressIntelRoutes mounts the intelligence endpoints. Called
// alongside RegisterEgressRoutes.
func (s *Server) RegisterEgressIntelRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/egress/countries", s.handleEgressCountries)
	mux.HandleFunc("/api/egress/companies", s.handleEgressCompanies)
	mux.HandleFunc("/api/egress/connections", s.handleEgressConnections)
	mux.HandleFunc("/api/egress/overview", s.handleEgressOverview)
	mux.HandleFunc("/api/egress/uid_names", s.handleEgressUIDNames)
	mux.HandleFunc("/api/egress/policy/list", s.handleEgressPolicyList)
	mux.HandleFunc("/api/egress/ipinfo", s.handleEgressIPInfo)
	mux.HandleFunc("/api/egress/flow", s.handleEgressFlow)
	mux.HandleFunc("/api/egress/internal", s.handleEgressInternal)
	mux.HandleFunc("/api/egress/process_detail", s.handleEgressProcessDetail)
	mux.HandleFunc("/api/egress/pid", s.handleEgressPID)
	mux.HandleFunc("/api/egress/verdict", s.handleEgressVerdict)
}

// ── /api/egress/uid_names ─────────────────────────────────────
//
// Returns {uid: username} parsed from /etc/passwd. Cached for 60s
// to avoid re-reading on every dashboard tick.

var (
	uidNameMu      sync.Mutex
	uidNameCache   map[uint32]string
	uidNameLoadedAt time.Time
)

func loadUIDNames() map[uint32]string {
	uidNameMu.Lock()
	defer uidNameMu.Unlock()
	if uidNameCache != nil && time.Since(uidNameLoadedAt) < 60*time.Second {
		return uidNameCache
	}
	out := map[uint32]string{}
	body, err := os.ReadFile("/etc/passwd")
	if err != nil {
		uidNameCache = out
		uidNameLoadedAt = time.Now()
		return out
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.SplitN(line, ":", 7)
		if len(parts) < 3 {
			continue
		}
		uid64, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			continue
		}
		out[uint32(uid64)] = parts[0]
	}
	uidNameCache = out
	uidNameLoadedAt = time.Now()
	return out
}

func (s *Server) handleEgressUIDNames(w http.ResponseWriter, r *http.Request) {
	writeJSONEgress(w, loadUIDNames())
}

// ── helpers ───────────────────────────────────────────────────

// firstHostIP extracts the network address from a CIDR string, or
// returns the string as-is if it isn't a CIDR. Used to do geoip /
// destclass lookups on a representative IP per FlowKey.
func firstHostIP(cidr string) string {
	if cidr == "" {
		return ""
	}
	if i := strings.IndexByte(cidr, '/'); i > 0 {
		return cidr[:i]
	}
	return cidr
}

// ── handlers ──────────────────────────────────────────────────

// CountryAgg is the per-country aggregate row.
type CountryAgg struct {
	Country        string   `json:"country"`
	BytesOut       uint64   `json:"bytes_out"`
	BytesIn        uint64   `json:"bytes_in"`
	Connects       uint64   `json:"connects"`
	DistinctDests  int      `json:"distinct_dests"`
	DistinctBins   int      `json:"distinct_binaries"`
	TopBinary      string   `json:"top_binary"`
	TopBinaryBytes uint64   `json:"top_binary_bytes"`
	Sparkline      []uint64 `json:"sparkline"`
}

func (s *Server) handleEgressCountries(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, []CountryAgg{})
		return
	}
	end := time.Now()
	start := end.Add(-1 * time.Hour)
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 720 {
			start = end.Add(-time.Duration(n) * time.Hour)
		}
	}
	rows := s.egress.QueryTimeline(start, end, egressledger.FlowFilter{
		UID: -1, CGroupID: -1, DestPort: -1,
		Visibility: parseVisibility(r.URL.Query().Get("visibility")),
	})
	type byBin map[string]uint64
	type acc struct {
		bytesOut, bytesIn, connects uint64
		dests                       map[string]struct{}
		bins                        byBin
	}
	m := make(map[string]*acc)
	for _, r := range rows {
		c := ""
		if s.geoip != nil {
			if cc, _, _, ok := s.geoip.Lookup(firstHostIP(r.Key.DestCIDR)); ok {
				c = cc
			}
		}
		if c == "" {
			c = "??"
		}
		a := m[c]
		if a == nil {
			a = &acc{dests: map[string]struct{}{}, bins: byBin{}}
			m[c] = a
		}
		a.bytesOut += r.Metrics.BytesOut
		a.bytesIn += r.Metrics.BytesIn
		a.connects += r.Metrics.Connects
		a.dests[r.Key.DestCIDR] = struct{}{}
		a.bins[r.Key.Binary] += r.Metrics.BytesOut
	}
	out := make([]CountryAgg, 0, len(m))
	for c, a := range m {
		var topBin string
		var topBytes uint64
		for b, by := range a.bins {
			if by > topBytes {
				topBytes = by
				topBin = b
			}
		}
		out = append(out, CountryAgg{
			Country:        c,
			BytesOut:       a.bytesOut,
			BytesIn:        a.bytesIn,
			Connects:       a.connects,
			DistinctDests:  len(a.dests),
			DistinctBins:   len(a.bins),
			TopBinary:      topBin,
			TopBinaryBytes: topBytes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BytesOut > out[j].BytesOut })
	writeJSONEgress(w, out)
}

// CompanyAgg aggregates by ASN org + dest class.
type CompanyAgg struct {
	Org            string `json:"org"`
	ASN            string `json:"asn"`
	Class          string `json:"class"`
	BytesOut       uint64 `json:"bytes_out"`
	BytesIn        uint64 `json:"bytes_in"`
	Connects       uint64 `json:"connects"`
	DistinctDests  int    `json:"distinct_dests"`
	TopBinary      string `json:"top_binary"`
	TopBinaryBytes uint64 `json:"top_binary_bytes"`
}

func (s *Server) handleEgressCompanies(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, []CompanyAgg{})
		return
	}
	end := time.Now()
	start := end.Add(-1 * time.Hour)
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 720 {
			start = end.Add(-time.Duration(n) * time.Hour)
		}
	}
	rows := s.egress.QueryTimeline(start, end, egressledger.FlowFilter{
		UID: -1, CGroupID: -1, DestPort: -1,
		Visibility: parseVisibility(r.URL.Query().Get("visibility")),
	})
	type acc struct {
		org, asn, class             string
		bytesOut, bytesIn, connects uint64
		dests                       map[string]struct{}
		bins                        map[string]uint64
	}
	m := make(map[string]*acc)
	for _, r := range rows {
		ip := firstHostIP(r.Key.DestCIDR)
		var asn, org string
		if s.geoip != nil {
			if _, a, o, ok := s.geoip.Lookup(ip); ok {
				asn = a
				org = o
			}
		}
		class := r.Key.DestClass
		if class == "" && s.destclass != nil {
			if p := net.ParseIP(ip); p != nil {
				class = s.destclass.Classify(p, r.Key.SNI, r.Key.DestPort)
			}
		}
		key := org
		if key == "" {
			key = asn
		}
		if key == "" {
			key = "unknown"
		}
		a := m[key]
		if a == nil {
			a = &acc{org: org, asn: asn, class: class,
				dests: map[string]struct{}{}, bins: map[string]uint64{}}
			m[key] = a
		}
		a.bytesOut += r.Metrics.BytesOut
		a.bytesIn += r.Metrics.BytesIn
		a.connects += r.Metrics.Connects
		a.dests[r.Key.DestCIDR] = struct{}{}
		a.bins[r.Key.Binary] += r.Metrics.BytesOut
	}
	out := make([]CompanyAgg, 0, len(m))
	for _, a := range m {
		var topBin string
		var topBytes uint64
		for b, by := range a.bins {
			if by > topBytes {
				topBytes = by
				topBin = b
			}
		}
		out = append(out, CompanyAgg{
			Org:            a.org,
			ASN:            a.asn,
			Class:          a.class,
			BytesOut:       a.bytesOut,
			BytesIn:        a.bytesIn,
			Connects:       a.connects,
			DistinctDests:  len(a.dests),
			TopBinary:      topBin,
			TopBinaryBytes: topBytes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BytesOut > out[j].BytesOut })
	writeJSONEgress(w, out)
}

// ConnView with geo/class enrichment for the live connections page.
type EnrichedConn struct {
	ConnView
	Country    string `json:"country"`
	ASN        string `json:"asn"`
	Org        string `json:"org"`
	Class      string `json:"class"`
	ParentComm string `json:"parent_comm"`
}

func (s *Server) handleEgressConnections(w http.ResponseWriter, r *http.Request) {
	if s.connstateSnap == nil {
		writeJSONEgress(w, []EnrichedConn{})
		return
	}
	vis := parseVisibility(r.URL.Query().Get("visibility"))
	conns := s.connstateSnap()
	out := make([]EnrichedConn, 0, len(conns))
	for _, c := range conns {
		ec := EnrichedConn{ConnView: c}
		if s.geoip != nil {
			if cc, asn, org, ok := s.geoip.Lookup(c.DstAddr); ok {
				ec.Country = cc
				ec.ASN = asn
				ec.Org = org
			}
		}
		if s.destclass != nil {
			if p := net.ParseIP(c.DstAddr); p != nil {
				ec.Class = s.destclass.Classify(p, c.SNI, c.DstPort)
			}
		}
		if s.proctree != nil && c.PPID != 0 {
			ec.ParentComm = s.proctree.ParentComm(c.PPID)
		}
		// Apply visibility filter when requested.
		if vis == "public" || vis == "internal" {
			class := ec.Class
			isPublic := egressledger.IsPublicDestClass(class)
			if class == "" {
				isPublic = egressledger.IsPublicCIDR(c.DstAddr)
			}
			if vis == "public" && !isPublic {
				continue
			}
			if vis == "internal" && isPublic {
				continue
			}
		}
		out = append(out, ec)
	}
	// Sort by bytes_out desc by default.
	sort.Slice(out, func(i, j int) bool { return out[i].BytesOut > out[j].BytesOut })
	writeJSONEgress(w, out)
}

// OverviewResp is the landing-page aggregate.
type OverviewResp struct {
	ActiveConns      int                 `json:"active_conns"`
	BytesOut1h       uint64              `json:"bytes_out_1h"`
	BytesIn1h        uint64              `json:"bytes_in_1h"`
	UniqueDests1h    int                 `json:"unique_dests_1h"`
	UniqueBins1h     int                 `json:"unique_binaries_1h"`
	UniqueCountries  int                 `json:"unique_countries_1h"`
	TopBinaries      []TopRow            `json:"top_binaries"`
	TopDestinations  []TopRow            `json:"top_destinations"`
	TopCountries     []TopRow            `json:"top_countries"`
	TopDenied        []TopRow            `json:"top_denied"`
	ClassBreakdown   map[string]uint64   `json:"class_breakdown"`
	HourlyByClass    []HourlyClassPoint  `json:"hourly_by_class"` // 24 buckets
	LedgerStats      egressledger.Stats  `json:"ledger_stats"`

	// Portmaster-style additions.
	AppCards       []AppCard      `json:"app_cards"`
	RecentBlocks   []BlockEvent   `json:"recent_blocks"`
	ActiveAlerts   []AlertSummary `json:"active_alerts"`
	TopASNs        []TopRow       `json:"top_asns"`
	BlockedCount24h uint64        `json:"blocked_count_24h"`
	ActiveAppCount  int           `json:"active_app_count"`
	OpenAlertsCount int           `json:"open_alerts_count"`
}

// AppCard is one tile in the Portmaster-style apps grid. Each card
// represents one binary currently active on this host.
type AppCard struct {
	Binary      string   `json:"binary"`
	Comm        string   `json:"comm,omitempty"`
	Category    string   `json:"category"`         // network|database|system|user|browser|unknown
	PIDs        int      `json:"pids"`             // live count
	BytesOut    uint64   `json:"bytes_out"`        // 1h
	BytesIn     uint64   `json:"bytes_in"`         // 1h
	Conns       uint64   `json:"conns"`
	BlockedConns uint64  `json:"blocked_conns"`
	Countries   []string `json:"countries"`        // top-5 codes
	Direction   string   `json:"direction"`        // outbound|inbound_reply|mixed|unknown
	Unit        string   `json:"unit,omitempty"`
	Alive       bool     `json:"alive"`
}

// BlockEvent is one recently-blocked attempt for the "Recently Blocked"
// card. Sourced from safety-net + egressguard deny events.
type BlockEvent struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"` // "safety_net" | "egress_policy"
	DstIP    string    `json:"dst_ip"`
	DstPort  uint16    `json:"dst_port,omitempty"`
	Binary   string    `json:"binary,omitempty"`
	Country  string    `json:"country,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

// TopRow is a generic name/value pair for "top N" panels.
type TopRow struct {
	Label    string `json:"label"`
	Sub      string `json:"sub,omitempty"`
	Bytes    uint64 `json:"bytes"`
	Connects uint64 `json:"connects"`
	Denied   uint64 `json:"denied,omitempty"`
	Class    string `json:"class,omitempty"`
	Country  string `json:"country,omitempty"`
}

// HourlyClassPoint is one hour-bucket of per-class bytes_out.
type HourlyClassPoint struct {
	Hour   int64             `json:"hour"` // unix seconds, hour-floored
	Bytes  map[string]uint64 `json:"bytes"`
}

func (s *Server) handleEgressOverview(w http.ResponseWriter, r *http.Request) {
	resp := OverviewResp{
		ClassBreakdown: map[string]uint64{},
		HourlyByClass:  []HourlyClassPoint{},
		TopBinaries:    []TopRow{},
		TopDestinations: []TopRow{},
		TopCountries:   []TopRow{},
		TopDenied:      []TopRow{},
	}
	if s.egress == nil {
		writeJSONEgress(w, resp)
		return
	}
	resp.LedgerStats = s.egress.Stats()

	vis := parseVisibility(r.URL.Query().Get("visibility"))

	// 1h aggregate from live (hot tier).
	live := s.egress.QueryLive(egressledger.FlowFilter{
		UID: -1, CGroupID: -1, DestPort: -1,
		Visibility: vis,
	})
	dests := map[string]struct{}{}
	bins := map[string]uint64{}
	binConn := map[string]uint64{}
	destBytes := map[string]uint64{}
	destClass := map[string]string{}
	countries := map[string]uint64{}
	denied := map[string]uint64{}
	for _, r := range live {
		resp.BytesOut1h += r.Metrics.BytesOut
		resp.BytesIn1h += r.Metrics.BytesIn
		dests[r.Key.DestCIDR] = struct{}{}
		bins[r.Key.Binary] += r.Metrics.BytesOut
		binConn[r.Key.Binary] += r.Metrics.Connects
		dk := r.Key.DestCIDR + ":" + strconv.Itoa(int(r.Key.DestPort))
		destBytes[dk] += r.Metrics.BytesOut
		if r.Key.DestClass != "" {
			destClass[dk] = r.Key.DestClass
			resp.ClassBreakdown[r.Key.DestClass] += r.Metrics.BytesOut
		} else {
			resp.ClassBreakdown["unknown"] += r.Metrics.BytesOut
		}
		if r.Metrics.DenyEvents > 0 {
			denied[r.Key.Binary+" → "+dk] += r.Metrics.DenyEvents
		}
		if s.geoip != nil {
			if cc, _, _, ok := s.geoip.Lookup(firstHostIP(r.Key.DestCIDR)); ok && cc != "" {
				countries[cc] += r.Metrics.BytesOut
			}
		}
	}
	resp.UniqueDests1h = len(dests)
	resp.UniqueBins1h = len(bins)
	resp.UniqueCountries = len(countries)

	// Top binaries.
	for b, by := range bins {
		resp.TopBinaries = append(resp.TopBinaries, TopRow{
			Label: b, Bytes: by, Connects: binConn[b],
		})
	}
	sort.Slice(resp.TopBinaries, func(i, j int) bool {
		return resp.TopBinaries[i].Bytes > resp.TopBinaries[j].Bytes
	})
	if len(resp.TopBinaries) > 10 {
		resp.TopBinaries = resp.TopBinaries[:10]
	}
	// Top destinations.
	for dk, by := range destBytes {
		resp.TopDestinations = append(resp.TopDestinations, TopRow{
			Label: dk, Bytes: by, Class: destClass[dk],
		})
	}
	sort.Slice(resp.TopDestinations, func(i, j int) bool {
		return resp.TopDestinations[i].Bytes > resp.TopDestinations[j].Bytes
	})
	if len(resp.TopDestinations) > 10 {
		resp.TopDestinations = resp.TopDestinations[:10]
	}
	// Top countries.
	for c, by := range countries {
		resp.TopCountries = append(resp.TopCountries, TopRow{
			Label: c, Country: c, Bytes: by,
		})
	}
	sort.Slice(resp.TopCountries, func(i, j int) bool {
		return resp.TopCountries[i].Bytes > resp.TopCountries[j].Bytes
	})
	if len(resp.TopCountries) > 10 {
		resp.TopCountries = resp.TopCountries[:10]
	}
	// Top denied.
	for k, c := range denied {
		resp.TopDenied = append(resp.TopDenied, TopRow{Label: k, Denied: c})
	}
	sort.Slice(resp.TopDenied, func(i, j int) bool {
		return resp.TopDenied[i].Denied > resp.TopDenied[j].Denied
	})
	if len(resp.TopDenied) > 10 {
		resp.TopDenied = resp.TopDenied[:10]
	}

	// 24h stacked-area: query timeline for last 24h, bucket by hour×class.
	end := time.Now()
	start := end.Add(-24 * time.Hour)
	tl := s.egress.QueryTimeline(start, end, egressledger.FlowFilter{
		UID: -1, CGroupID: -1, DestPort: -1,
		Visibility: vis,
	})
	hourly := map[int64]map[string]uint64{}
	for _, r := range tl {
		h := r.Bucket.Truncate(time.Hour).Unix()
		if hourly[h] == nil {
			hourly[h] = map[string]uint64{}
		}
		cls := r.Key.DestClass
		if cls == "" {
			cls = "unknown"
		}
		hourly[h][cls] += r.Metrics.BytesOut
	}
	hours := make([]int64, 0, len(hourly))
	for h := range hourly {
		hours = append(hours, h)
	}
	sort.Slice(hours, func(i, j int) bool { return hours[i] < hours[j] })
	for _, h := range hours {
		resp.HourlyByClass = append(resp.HourlyByClass, HourlyClassPoint{
			Hour: h, Bytes: hourly[h],
		})
	}

	// Active conns from live snapshot (if wired).
	if s.connstateSnap != nil {
		resp.ActiveConns = len(s.connstateSnap())
	}

	// ── Portmaster-style additions ────────────────────────────────

	// AppCards: one card per binary with active flows in the last 1h.
	binIn := map[string]uint64{}
	binConnects := map[string]uint64{}
	binBlocked := map[string]uint64{}
	binCountries := map[string]map[string]uint64{}
	binDestPorts := map[string][]uint16{}
	for _, r := range live {
		b := r.Key.Binary
		binIn[b] += r.Metrics.BytesIn
		binConnects[b] += r.Metrics.Connects
		binBlocked[b] += r.Metrics.DenyEvents
		if binCountries[b] == nil {
			binCountries[b] = map[string]uint64{}
		}
		if s.geoip != nil {
			if cc, _, _, ok := s.geoip.Lookup(firstHostIP(r.Key.DestCIDR)); ok && cc != "" {
				binCountries[b][cc] += r.Metrics.BytesOut
			}
		}
		binDestPorts[b] = append(binDestPorts[b], r.Key.DestPort)
	}
	// Map binary → live PID count from connstate.
	binLivePIDs := map[string]map[uint32]bool{}
	if s.connstateSnap != nil {
		for _, c := range s.connstateSnap() {
			if c.Comm == "" {
				continue
			}
			if binLivePIDs[c.Comm] == nil {
				binLivePIDs[c.Comm] = map[uint32]bool{}
			}
			binLivePIDs[c.Comm][c.PID] = true
		}
	}
	classifyApp := func(name string) string {
		n := name
		if i := strings.LastIndexByte(n, '/'); i >= 0 {
			n = n[i+1:]
		}
		switch n {
		case "nginx", "apache2", "httpd", "caddy", "haproxy", "envoy":
			return "web-server"
		case "sshd":
			return "ssh"
		case "mysqld", "postgres", "redis-server", "mongod", "memcached", "etcd":
			return "database"
		case "systemd", "systemd-resolved", "systemd-networkd", "dbus-daemon",
			"chronyd", "ntpd", "cron", "rsyslogd":
			return "system"
		case "curl", "wget", "ssh", "rsync", "git", "scp", "telnet":
			return "user-cli"
		case "chrome", "firefox", "brave", "chromium":
			return "browser"
		case "docker", "dockerd", "containerd", "runc":
			return "container"
		case "python", "python3", "node", "perl", "ruby", "php", "java":
			return "runtime"
		}
		return "unknown"
	}
	wellKnown := map[uint16]bool{
		22: true, 25: true, 53: true, 80: true, 443: true, 3306: true, 5432: true,
		6379: true, 8080: true, 8443: true,
	}
	classifyDir := func(ports []uint16, bin string) string {
		eph, svc := 0, 0
		for _, p := range ports {
			if p >= 32768 {
				eph++
			} else if wellKnown[p] {
				svc++
			}
		}
		isServer := false
		switch bin {
		case "nginx", "apache2", "httpd", "caddy", "sshd", "mysqld", "postgres", "redis-server", "haproxy":
			isServer = true
		}
		if isServer && eph >= svc {
			return "inbound_reply"
		}
		if svc > eph {
			return "outbound"
		}
		if eph > 0 {
			return "outbound"
		}
		return "mixed"
	}
	for binary, bout := range bins {
		// Top countries (max 5) for this binary.
		type cc struct {
			c string
			b uint64
		}
		var cs []cc
		for c, b := range binCountries[binary] {
			cs = append(cs, cc{c, b})
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].b > cs[j].b })
		var ccCodes []string
		for i, x := range cs {
			if i >= 5 {
				break
			}
			ccCodes = append(ccCodes, x.c)
		}
		pids := len(binLivePIDs[binary])
		resp.AppCards = append(resp.AppCards, AppCard{
			Binary:       binary,
			Comm:         binary,
			Category:     classifyApp(binary),
			PIDs:         pids,
			BytesOut:     bout,
			BytesIn:      binIn[binary],
			Conns:        binConnects[binary],
			BlockedConns: binBlocked[binary],
			Countries:    ccCodes,
			Direction:    classifyDir(binDestPorts[binary], binary),
			Alive:        pids > 0,
		})
	}
	sort.Slice(resp.AppCards, func(i, j int) bool {
		// Sort: alive first, then by bytes out.
		if resp.AppCards[i].Alive != resp.AppCards[j].Alive {
			return resp.AppCards[i].Alive
		}
		return resp.AppCards[i].BytesOut > resp.AppCards[j].BytesOut
	})
	resp.ActiveAppCount = 0
	for _, c := range resp.AppCards {
		if c.Alive {
			resp.ActiveAppCount++
		}
	}

	// Top ASNs (from live 1h, public only).
	asnBytes := map[string]uint64{}
	asnOrg := map[string]string{}
	asnDests := map[string]map[string]struct{}{}
	for _, r := range live {
		if s.geoip == nil {
			break
		}
		_, asn, org, ok := s.geoip.Lookup(firstHostIP(r.Key.DestCIDR))
		if !ok || asn == "" {
			continue
		}
		asnBytes[asn] += r.Metrics.BytesOut
		if asnOrg[asn] == "" {
			asnOrg[asn] = org
		}
		if asnDests[asn] == nil {
			asnDests[asn] = map[string]struct{}{}
		}
		asnDests[asn][r.Key.DestCIDR] = struct{}{}
	}
	for a, b := range asnBytes {
		resp.TopASNs = append(resp.TopASNs, TopRow{
			Label:    asnOrg[a],
			Sub:      a,
			Bytes:    b,
			Connects: uint64(len(asnDests[a])),
		})
	}
	sort.Slice(resp.TopASNs, func(i, j int) bool { return resp.TopASNs[i].Bytes > resp.TopASNs[j].Bytes })
	if len(resp.TopASNs) > 10 {
		resp.TopASNs = resp.TopASNs[:10]
	}

	// Recent blocks: pull from safety-net attempts + flow rows with deny_events.
	if s.safety != nil {
		attempts := s.safety.RecentAttempts(50)
		for _, a := range attempts {
			cc := ""
			if s.geoip != nil {
				cc, _, _, _ = s.geoip.Lookup(a.DstIP)
			}
			resp.RecentBlocks = append(resp.RecentBlocks, BlockEvent{
				Time:    a.Time,
				Source:  "safety_net",
				DstIP:   a.DstIP,
				DstPort: a.DstPort,
				Country: cc,
				Reason:  "safety-net drop",
			})
		}
	}
	// Egress-policy denies (from flow rows in the last 24h with DenyEvents>0).
	for _, r := range tl {
		if r.Metrics.DenyEvents == 0 {
			continue
		}
		ip := firstHostIP(r.Key.DestCIDR)
		cc := ""
		if s.geoip != nil {
			cc, _, _, _ = s.geoip.Lookup(ip)
		}
		resp.RecentBlocks = append(resp.RecentBlocks, BlockEvent{
			Time:    r.Metrics.LastSeen,
			Source:  "egress_policy",
			DstIP:   ip,
			DstPort: r.Key.DestPort,
			Binary:  r.Key.Binary,
			Country: cc,
			Reason:  "egress policy deny",
		})
		resp.BlockedCount24h += r.Metrics.DenyEvents
	}
	sort.Slice(resp.RecentBlocks, func(i, j int) bool {
		return resp.RecentBlocks[i].Time.After(resp.RecentBlocks[j].Time)
	})
	if len(resp.RecentBlocks) > 30 {
		resp.RecentBlocks = resp.RecentBlocks[:30]
	}

	// Active alerts from the daemon's ring snapshot.
	if s.alertSnap != nil {
		snap := s.alertSnap()
		cutoff := time.Now().Add(-24 * time.Hour)
		for _, a := range snap {
			if a.Time.Before(cutoff) {
				continue
			}
			resp.ActiveAlerts = append(resp.ActiveAlerts, a)
		}
		sort.Slice(resp.ActiveAlerts, func(i, j int) bool {
			return resp.ActiveAlerts[i].Time.After(resp.ActiveAlerts[j].Time)
		})
		resp.OpenAlertsCount = len(resp.ActiveAlerts)
		if len(resp.ActiveAlerts) > 20 {
			resp.ActiveAlerts = resp.ActiveAlerts[:20]
		}
	}

	writeJSONEgress(w, resp)
}

// PolicyRule is a stub for the policy list endpoint. Real policy
// engine lands in Week 3; for now we return an empty array.
type PolicyRule struct {
	ID        string `json:"id"`
	Binary    string `json:"binary"`
	UID       int    `json:"uid"`
	Action    string `json:"action"`   // allow | deny | observe
	Scope     string `json:"scope"`    // process | user | country
	Country   string `json:"country,omitempty"`
	DestCIDR  string `json:"dest_cidr,omitempty"`
	DestPort  uint16 `json:"dest_port,omitempty"`
	Signed    bool   `json:"signed"`
	Suggested bool   `json:"suggested"`
	Reason    string `json:"reason,omitempty"`
}

func (s *Server) handleEgressPolicyList(w http.ResponseWriter, r *http.Request) {
	// Week 3: prefer the actual signed policies if the engine is
	// wired. Each Policy becomes one PolicyRule per Allow rule (plus
	// a synthetic "mode" row when the policy has no Allow list — e.g.
	// allow_any / tor_only). Fall back to the Week 2 "observed flow
	// suggestions" stub when no engine is wired so the UI is never
	// empty.
	out := []PolicyRule{}
	if s.egressPolicy != nil {
		for _, sp := range s.egressPolicy.List() {
			p := sp.Policy
			if len(p.Allow) == 0 && len(p.Deny) == 0 {
				out = append(out, PolicyRule{
					ID:     "pol-" + p.Binary,
					Binary: p.Binary,
					Action: string(p.Mode),
					Scope:  "process",
					Signed: true,
					Reason: "signer=" + p.Signer,
				})
				continue
			}
			for i, ar := range p.Allow {
				out = append(out, PolicyRule{
					ID:       "pol-" + p.Binary + "-allow-" + strconv.Itoa(i),
					Binary:   p.Binary,
					Action:   "allow",
					Scope:    "process",
					DestCIDR: ar.DestCIDR,
					DestPort: portOrZero(ar.Ports),
					Signed:   true,
					Reason:   ar.Comment,
				})
			}
			for i, dr := range p.Deny {
				out = append(out, PolicyRule{
					ID:       "pol-" + p.Binary + "-deny-" + strconv.Itoa(i),
					Binary:   p.Binary,
					Action:   "deny",
					Scope:    "process",
					DestCIDR: dr.DestCIDR,
					DestPort: portOrZero(dr.Ports),
					Signed:   true,
					Reason:   dr.Comment,
				})
			}
		}
		if len(out) > 0 {
			writeJSONEgress(w, out)
			return
		}
	}
	if s.egress != nil {
		live := s.egress.QueryLive(egressledger.FlowFilter{
			UID: -1, CGroupID: -1, DestPort: -1,
		})
		seen := map[string]struct{}{}
		for _, r := range live {
			k := r.Key.Binary + "|" + r.Key.DestCIDR
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, PolicyRule{
				ID:        "obs-" + strconv.Itoa(len(out)+1),
				Binary:    r.Key.Binary,
				UID:       int(r.Key.UID),
				Action:    "observe",
				Scope:     "process",
				DestCIDR:  r.Key.DestCIDR,
				DestPort:  r.Key.DestPort,
				Suggested: true,
				Reason:    "observed " + strconv.FormatUint(r.Metrics.Connects, 10) + " connects",
			})
			if len(out) >= 200 {
				break
			}
		}
	}
	writeJSONEgress(w, out)
}

// ── /api/egress/internal ──────────────────────────────────────
//
// Public/internal traffic separation: the main dashboards default to
// "public" so docker bridge chatter doesn't dominate. This endpoint
// is the dedicated view for internal flows — lateral movement, IMDS
// abuse, and docker noise are aggregated in one place.

// InternalReport is the response shape for /api/egress/internal.
type InternalReport struct {
	TotalFlows        int                 `json:"total_flows"`
	TotalBytesOut     uint64              `json:"total_bytes_out"`
	TotalBytesIn      uint64              `json:"total_bytes_in"`
	IMDSContacts      []InternalRow       `json:"imds_contacts"`
	LateralCandidates []InternalRow       `json:"lateral_candidates"`
	PerBinary         []InternalBinaryAgg `json:"per_binary"`
	PerCgroup         []InternalCgroupAgg `json:"per_cgroup,omitempty"`
}

// InternalBinaryAgg is one row per binary aggregating internal traffic.
type InternalBinaryAgg struct {
	Binary              string   `json:"binary"`
	BytesOut            uint64   `json:"bytes_out"`
	BytesIn             uint64   `json:"bytes_in"`
	Connects            uint64   `json:"connects"`
	DistinctInternal24s int      `json:"distinct_internal_24s"`
	TopTargets          []string `json:"top_targets"`
}

// InternalCgroupAgg captures docker/podman cgroup activity.
type InternalCgroupAgg struct {
	CGroupID    uint64 `json:"cgroup_id"`
	BytesOut    uint64 `json:"bytes_out"`
	BytesIn     uint64 `json:"bytes_in"`
	Connects    uint64 `json:"connects"`
	DistinctIPs int    `json:"distinct_ips"`
}

// InternalRow is a single flow-level row (IMDS / lateral candidate).
type InternalRow struct {
	Binary   string    `json:"binary"`
	DestCIDR string    `json:"dest_cidr"`
	DestPort uint16    `json:"dest_port"`
	Connects uint64    `json:"connects"`
	LastSeen time.Time `json:"last_seen"`
}

// imdsIP is the EC2 / cloud Instance Metadata Service magic address.
const imdsIP = "169.254.169.254"

// slash24 reduces an IP-or-CIDR to its /24 (v4) or /48 (v6) key for
// counting "distinct subnets contacted". For exact IPs we coerce to
// /24; for already-bucketed strings we accept them as-is.
func slash24(s string) string {
	if s == "" {
		return ""
	}
	host := s
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[2])) + ".0/24"
	}
	return s
}

func (s *Server) handleEgressInternal(w http.ResponseWriter, r *http.Request) {
	resp := InternalReport{
		IMDSContacts:      []InternalRow{},
		LateralCandidates: []InternalRow{},
		PerBinary:         []InternalBinaryAgg{},
		PerCgroup:         []InternalCgroupAgg{},
	}
	if s.egress == nil {
		writeJSONEgress(w, resp)
		return
	}
	// Pull last hour from the ledger, internal-only.
	end := time.Now()
	start := end.Add(-1 * time.Hour)
	rows := s.egress.QueryTimeline(start, end, egressledger.FlowFilter{
		UID: -1, CGroupID: -1, DestPort: -1,
		Visibility: "internal",
	})

	type binAgg struct {
		bytesOut, bytesIn, connects uint64
		subnets                     map[string]struct{}
		targets                     map[string]uint64 // "cidr:port" → bytes_out
	}
	type cgAgg struct {
		bytesOut, bytesIn, connects uint64
		dests                       map[string]struct{}
	}
	bins := map[string]*binAgg{}
	cgs := map[uint64]*cgAgg{}

	for _, rec := range rows {
		resp.TotalFlows++
		resp.TotalBytesOut += rec.Metrics.BytesOut
		resp.TotalBytesIn += rec.Metrics.BytesIn

		k := rec.Key
		// IMDS detection — exact-IP destclass keeps 169.254.169.254 visible.
		host := firstHostIP(k.DestCIDR)
		if host == imdsIP {
			resp.IMDSContacts = append(resp.IMDSContacts, InternalRow{
				Binary:   k.Binary,
				DestCIDR: k.DestCIDR,
				DestPort: k.DestPort,
				Connects: rec.Metrics.Connects,
				LastSeen: rec.Metrics.LastSeen,
			})
		}

		// Per-binary aggregation.
		ba := bins[k.Binary]
		if ba == nil {
			ba = &binAgg{
				subnets: map[string]struct{}{},
				targets: map[string]uint64{},
			}
			bins[k.Binary] = ba
		}
		ba.bytesOut += rec.Metrics.BytesOut
		ba.bytesIn += rec.Metrics.BytesIn
		ba.connects += rec.Metrics.Connects
		if sub := slash24(k.DestCIDR); sub != "" {
			ba.subnets[sub] = struct{}{}
		}
		tk := k.DestCIDR + ":" + strconv.Itoa(int(k.DestPort))
		ba.targets[tk] += rec.Metrics.BytesOut

		// Per-cgroup aggregation (only when CGroupID known).
		if k.CGroupID != 0 {
			ca := cgs[k.CGroupID]
			if ca == nil {
				ca = &cgAgg{dests: map[string]struct{}{}}
				cgs[k.CGroupID] = ca
			}
			ca.bytesOut += rec.Metrics.BytesOut
			ca.bytesIn += rec.Metrics.BytesIn
			ca.connects += rec.Metrics.Connects
			ca.dests[k.DestCIDR] = struct{}{}
		}
	}

	// Flatten per-binary; flag lateral candidates (>5 distinct /24s).
	for name, ba := range bins {
		// Pick top targets by bytes_out, up to 5 samples.
		type tv struct {
			k string
			v uint64
		}
		tvs := make([]tv, 0, len(ba.targets))
		for k, v := range ba.targets {
			tvs = append(tvs, tv{k, v})
		}
		sort.Slice(tvs, func(i, j int) bool { return tvs[i].v > tvs[j].v })
		if len(tvs) > 5 {
			tvs = tvs[:5]
		}
		top := make([]string, 0, len(tvs))
		for _, x := range tvs {
			top = append(top, x.k)
		}
		row := InternalBinaryAgg{
			Binary:              name,
			BytesOut:            ba.bytesOut,
			BytesIn:             ba.bytesIn,
			Connects:            ba.connects,
			DistinctInternal24s: len(ba.subnets),
			TopTargets:          top,
		}
		resp.PerBinary = append(resp.PerBinary, row)
		if len(ba.subnets) > 5 {
			// Surface the loudest target as the lateral-movement marker.
			var lastSeen time.Time
			var top1 string
			var top1Bytes uint64
			for _, x := range tvs {
				if x.v > top1Bytes {
					top1Bytes = x.v
					top1 = x.k
				}
			}
			cidr, port := splitCIDRPort(top1)
			// Use the latest LastSeen in any record for this binary.
			for _, rec := range rows {
				if rec.Key.Binary == name && rec.Metrics.LastSeen.After(lastSeen) {
					lastSeen = rec.Metrics.LastSeen
				}
			}
			resp.LateralCandidates = append(resp.LateralCandidates, InternalRow{
				Binary:   name,
				DestCIDR: cidr,
				DestPort: port,
				Connects: ba.connects,
				LastSeen: lastSeen,
			})
		}
	}
	sort.Slice(resp.PerBinary, func(i, j int) bool {
		return resp.PerBinary[i].BytesOut > resp.PerBinary[j].BytesOut
	})
	sort.Slice(resp.LateralCandidates, func(i, j int) bool {
		return resp.LateralCandidates[i].Connects > resp.LateralCandidates[j].Connects
	})

	// Flatten per-cgroup.
	for id, ca := range cgs {
		resp.PerCgroup = append(resp.PerCgroup, InternalCgroupAgg{
			CGroupID:    id,
			BytesOut:    ca.bytesOut,
			BytesIn:     ca.bytesIn,
			Connects:    ca.connects,
			DistinctIPs: len(ca.dests),
		})
	}
	sort.Slice(resp.PerCgroup, func(i, j int) bool {
		return resp.PerCgroup[i].BytesOut > resp.PerCgroup[j].BytesOut
	})

	writeJSONEgress(w, resp)
}

// splitCIDRPort parses a "cidr:port" or "ip:port" string. Best-effort.
func splitCIDRPort(s string) (string, uint16) {
	// Find LAST ':' so v6 CIDRs with embedded colons still work — the
	// trailing ":<port>" is the suffix we want to strip.
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	port64, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return s, 0
	}
	return s[:i], uint16(port64)
}

// portOrZero returns the first port in xs (0 if empty). Used by the
// policy-list UI projection so the row's DestPort column has a value
// for single-port rules; multi-port rules are flattened to the first.
func portOrZero(xs []uint16) uint16 {
	if len(xs) == 0 {
		return 0
	}
	return xs[0]
}
