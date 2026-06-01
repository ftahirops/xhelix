// Package web — per-IP "deep analysis" and per-flow "analysis"
// endpoints. Wired by the daemon via SetReverseDNS / SetDNSObs /
// SetThreatIntel. All providers nil-safe — when a subsystem isn't
// available, the corresponding field on the response is left empty.
//
// Operator framing: clicking any IP in the dashboard should land here
// (or on the flow page when there's a binary+dest+port triple). The
// goal is "everything xhelix knows about this IP" / "everything
// xhelix knows about this flow" on a single page, without forcing
// the operator to flip between tabs.
package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/egressledger"
)

// ── Provider interfaces ───────────────────────────────────────

// ReverseDNSResolver lets the daemon plug in a system / custom
// resolver. When unset the handler falls back to net.DefaultResolver.
// 2s context timeout is enforced by the handler.
type ReverseDNSResolver interface {
	Lookup(ctx context.Context, ip string) (string, error)
}

// DNSObservations links IPs to recently-observed domain names. The
// daemon's DNS collector (if present) implements this; it returns up
// to ~10 names that have recently resolved to ip.
type DNSObservations interface {
	NamesForIP(ip string) []string
}

// ThreatIntelHits returns a non-empty source/feed name when ip is on
// the loaded threat-intel feed, otherwise "".
type ThreatIntelHits interface {
	Match(ip string) string
}

// SetReverseDNS wires the reverse-DNS resolver. Nil-safe.
func (s *Server) SetReverseDNS(r ReverseDNSResolver) { s.revdns = r }

// SetDNSObs wires the DNS-observations provider. Nil-safe.
func (s *Server) SetDNSObs(d DNSObservations) { s.dnsobs = d }

// SetThreatIntel wires the threat-intel provider. Nil-safe.
func (s *Server) SetThreatIntel(t ThreatIntelHits) { s.threatintel = t }

// ── Response types ────────────────────────────────────────────

// IPInfo is the per-IP deep-analysis payload.
type IPInfo struct {
	IP             string    `json:"ip"`
	Country        string    `json:"country,omitempty"`
	ASN            string    `json:"asn,omitempty"`
	Org            string    `json:"org,omitempty"`
	Class          string    `json:"class,omitempty"`
	IsPrivate      bool      `json:"is_private"`
	IsLoopback     bool      `json:"is_loopback"`
	IsLinkLocal    bool      `json:"is_link_local"`
	ReverseDNS     string    `json:"reverse_dns,omitempty"`
	RelatedDomains []string  `json:"related_domains,omitempty"`
	ThreatIntelHit string    `json:"threat_intel_hit,omitempty"`
	Whois          string    `json:"whois,omitempty"`
	FirstSeen      time.Time `json:"first_seen,omitempty"`
	LastSeen       time.Time `json:"last_seen,omitempty"`
	TotalBytesOut  uint64    `json:"total_bytes_out"`
	TotalBytesIn   uint64    `json:"total_bytes_in"`
	TotalConnects  uint64    `json:"total_connects"`
	DistinctBins   int       `json:"distinct_binaries"`
	TopBinaries    []string  `json:"top_binaries"`
	RecentFlows    []IPFlowRow `json:"recent_flows,omitempty"`
	CohortFraction float64   `json:"cohort_fraction,omitempty"`
	CohortSize     int       `json:"cohort_size,omitempty"`

	// 24h hourly time-series (each slice has 24 entries, oldest first).
	HourlyBytesOut []uint64 `json:"hourly_bytes_out,omitempty"`
	HourlyBytesIn  []uint64 `json:"hourly_bytes_in,omitempty"`
	HourlyConnects []uint64 `json:"hourly_connects,omitempty"`

	// Protocol breakdown over last 24h (well, the same 7d window since
	// that's the source data — clients can still treat it as overview).
	Protocols []ProtocolStat `json:"protocols,omitempty"`

	// Per-process activity (binary → first/last seen + counts).
	ProcessActivity []ProcessActivity `json:"process_activity,omitempty"`

	// Recent related alerts (from alerts.jsonl) referencing this IP.
	RelatedAlerts []RelatedAlert `json:"related_alerts,omitempty"`

	// Suspicion scoring.
	Suspicion SuspicionScore `json:"suspicion"`
}

// ProtocolStat is one row of the app-protocol breakdown table.
type ProtocolStat struct {
	Protocol string   `json:"protocol"`
	Flows    int      `json:"flows"`
	BytesOut uint64   `json:"bytes_out"`
	BytesIn  uint64   `json:"bytes_in"`
	SNIs     []string `json:"snis,omitempty"`
}

// ProcessActivity is one binary's aggregated activity against this IP.
type ProcessActivity struct {
	Binary    string    `json:"binary"`
	PID       uint32    `json:"pid,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Connects  uint64    `json:"connects"`
	BytesOut  uint64    `json:"bytes_out"`
	BytesIn   uint64    `json:"bytes_in"`
}

// RelatedAlert is one alert from alerts.jsonl that mentions this IP.
type RelatedAlert struct {
	Time     time.Time `json:"time"`
	RuleID   string    `json:"rule_id"`
	Severity string    `json:"severity"`
	Comm     string    `json:"comm,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

// SuspicionScore is the deterministic, explainable score for this IP.
// Verdict bands: <20 normal, <50 watch, <80 suspicious, ≥80 critical.
type SuspicionScore struct {
	Score         int                `json:"score"`
	Verdict       string             `json:"verdict"`
	Contributions []SuspicionContrib `json:"contributions"`
}

// SuspicionContrib is one explainable row of the score breakdown.
type SuspicionContrib struct {
	Condition string `json:"condition"`
	Delta     int    `json:"delta"`
	Detail    string `json:"detail,omitempty"`
}

// IPFlowRow is one (binary, port) row of flows touching this IP/CIDR.
type IPFlowRow struct {
	Binary   string    `json:"binary"`
	DestCIDR string    `json:"dest_cidr"`
	DestPort uint16    `json:"dest_port"`
	BytesOut uint64    `json:"bytes_out"`
	BytesIn  uint64    `json:"bytes_in"`
	Connects uint64    `json:"connects"`
	LastSeen time.Time `json:"last_seen"`
}

// FlowAnalysis is the per-flow detail page payload.
type FlowAnalysis struct {
	Binary        string                `json:"binary"`
	DestCIDR      string                `json:"dest_cidr"`
	DestPort      uint16                `json:"dest_port"`
	DestCountry   string                `json:"dest_country,omitempty"`
	DestClass     string                `json:"dest_class,omitempty"`
	FirstSeen     time.Time             `json:"first_seen"`
	LastSeen      time.Time             `json:"last_seen"`
	TotalConnects uint64                `json:"total_connects"`
	TotalBytesOut uint64                `json:"total_bytes_out"`
	TotalBytesIn  uint64                `json:"total_bytes_in"`
	PeakOutBytes  uint64                `json:"peak_out_bytes"`
	Initiator     *FlowInitiator        `json:"initiator,omitempty"`
	LiveConns     []ConnView            `json:"live_conns,omitempty"`
	RelatedFlows  []FlowAnalysisRelated `json:"related_flows,omitempty"`
	Timeline      []FlowAnalysisTimePt  `json:"timeline,omitempty"`
	SourceLineage []string              `json:"source_lineage,omitempty"`
}

// FlowInitiator describes who opened the first live connection.
type FlowInitiator struct {
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid"`
	ParentComm string    `json:"parent_comm"`
	OpenedAt   time.Time `json:"opened_at"`
}

// FlowAnalysisRelated is one "related flow" row.
type FlowAnalysisRelated struct {
	Binary   string `json:"binary"`
	DestCIDR string `json:"dest_cidr"`
	DestPort uint16 `json:"dest_port,omitempty"`
	BytesOut uint64 `json:"bytes_out"`
	Reason   string `json:"reason"`
}

// FlowAnalysisTimePt is one hourly bucket on the per-flow timeline.
type FlowAnalysisTimePt struct {
	Hour     int64  `json:"hour"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	Connects uint64 `json:"connects"`
}

// ── Helpers ───────────────────────────────────────────────────

// cidrFor returns the bucketed CIDR for an IP, matching the egress
// ledger's cidr16() convention: v4 /16, v6 /48. We reproduce the exact
// formatting (net.IPNet.String()) so equality comparisons against
// FlowKey.DestCIDR are reliable.
// cidrFor returns the ledger bucket key for an IP. The ledger now stores
// every dest as the exact IP (the /16 bucketing was removed), so this
// returns ip.String() — preserving the function name so the rest of the
// handler doesn't churn.
func cidrFor(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// topNByValue returns the top N keys by value, sorted descending.
func topNByValue(m map[string]uint64, n int) []string {
	type kv struct {
		k string
		v uint64
	}
	xs := make([]kv, 0, len(m))
	for k, v := range m {
		xs = append(xs, kv{k, v})
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].v > xs[j].v })
	if len(xs) > n {
		xs = xs[:n]
	}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.k)
	}
	return out
}

// runWhois shells out to /usr/bin/whois with a strict argv: only the
// validated IP as a positional argument (after `--` to disambiguate).
// 5s timeout. Returns up to 30 lines or "" on any failure. Caller has
// already validated `ip` via net.ParseIP — we re-validate here as a
// defense-in-depth measure so a future caller can't bypass that.
func runWhois(ctx context.Context, ip string) string {
	if net.ParseIP(ip) == nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "/usr/bin/whois", "--", ip).Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) > 30 {
		lines = lines[:30]
	}
	return strings.Join(lines, "\n")
}

// ── /api/egress/ipinfo ────────────────────────────────────────

func (s *Server) handleEgressIPInfo(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, "ip param required", http.StatusBadRequest)
		return
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}

	info := IPInfo{
		IP:          ip,
		IsPrivate:   parsed.IsPrivate(),
		IsLoopback:  parsed.IsLoopback(),
		IsLinkLocal: parsed.IsLinkLocalUnicast(),
		TopBinaries: []string{},
	}

	// GeoIP.
	if s.geoip != nil {
		if cc, asn, org, ok := s.geoip.Lookup(ip); ok {
			info.Country = cc
			info.ASN = asn
			info.Org = org
		}
	}
	// Destination class.
	if s.destclass != nil {
		info.Class = s.destclass.Classify(parsed, "", 0)
	}
	// Threat intel.
	if s.threatintel != nil {
		info.ThreatIntelHit = s.threatintel.Match(ip)
	}
	// Reverse DNS — skip for private/loopback/link-local (they wouldn't
	// have meaningful PTR records and we don't want to leak internal
	// names back into a lookup queue).
	if !info.IsPrivate && !info.IsLoopback && !info.IsLinkLocal {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		if s.revdns != nil {
			if name, err := s.revdns.Lookup(ctx, ip); err == nil {
				info.ReverseDNS = strings.TrimSuffix(name, ".")
			}
		} else {
			names, err := net.DefaultResolver.LookupAddr(ctx, ip)
			if err == nil && len(names) > 0 {
				info.ReverseDNS = strings.TrimSuffix(names[0], ".")
			}
		}
		cancel()
		// rDNS-suffix enrichment: when the reverse name reveals a known
		// cloud/CDN operator, fill in class/org if not already known.
		if info.ReverseDNS != "" && s.destclass != nil {
			if cls, org := s.destclass.ClassFromPTR(info.ReverseDNS); cls != "" {
				if info.Class == "" || info.Class == "unknown" {
					info.Class = cls
				}
				if info.Org == "" {
					info.Org = org
				}
			}
		}
	}
	// Related domains (recent names that resolved to this IP).
	if s.dnsobs != nil {
		info.RelatedDomains = s.dnsobs.NamesForIP(ip)
	}

	// Aggregate ledger stats for this IP — matched at the CIDR bucket
	// the ledger uses (/16 v4, /48 v6). This is a 7-day window.
	if s.egress != nil {
		end := time.Now()
		start := end.Add(-7 * 24 * time.Hour)
		rows := s.egress.QueryTimeline(start, end, egressledger.FlowFilter{
			UID: -1, CGroupID: -1, DestPort: -1,
		})
		cidr := cidrFor(parsed)
		binBytes := map[string]uint64{}
		// (binary, port) → aggregated row for "recent flows" card.
		type flowKey struct {
			bin  string
			port uint16
		}
		flowAgg := map[flowKey]*IPFlowRow{}
		for _, row := range rows {
			if row.Key.DestCIDR != cidr {
				continue
			}
			info.TotalBytesOut += row.Metrics.BytesOut
			info.TotalBytesIn += row.Metrics.BytesIn
			info.TotalConnects += row.Metrics.Connects
			binBytes[row.Key.Binary] += row.Metrics.BytesOut
			if info.FirstSeen.IsZero() || (!row.Metrics.FirstSeen.IsZero() && row.Metrics.FirstSeen.Before(info.FirstSeen)) {
				if !row.Metrics.FirstSeen.IsZero() {
					info.FirstSeen = row.Metrics.FirstSeen
				}
			}
			if row.Metrics.LastSeen.After(info.LastSeen) {
				info.LastSeen = row.Metrics.LastSeen
			}
			k := flowKey{bin: row.Key.Binary, port: row.Key.DestPort}
			f := flowAgg[k]
			if f == nil {
				f = &IPFlowRow{Binary: row.Key.Binary, DestCIDR: row.Key.DestCIDR, DestPort: row.Key.DestPort}
				flowAgg[k] = f
			}
			f.BytesOut += row.Metrics.BytesOut
			f.BytesIn += row.Metrics.BytesIn
			f.Connects += row.Metrics.Connects
			if row.Metrics.LastSeen.After(f.LastSeen) {
				f.LastSeen = row.Metrics.LastSeen
			}
		}
		info.DistinctBins = len(binBytes)
		info.TopBinaries = topNByValue(binBytes, 10)
		flows := make([]IPFlowRow, 0, len(flowAgg))
		for _, f := range flowAgg {
			flows = append(flows, *f)
		}
		sort.Slice(flows, func(i, j int) bool { return flows[i].BytesOut > flows[j].BytesOut })
		if len(flows) > 50 {
			flows = flows[:50]
		}
		info.RecentFlows = flows

		// ── Phase-2 enrichment ────────────────────────────────────
		// All computations below scope to rows whose DestCIDR == cidr.

		// 24h hourly time series (oldest bucket first).
		hEnd := time.Now().Truncate(time.Hour)
		hStart := hEnd.Add(-24 * time.Hour)
		info.HourlyBytesOut = make([]uint64, 24)
		info.HourlyBytesIn = make([]uint64, 24)
		info.HourlyConnects = make([]uint64, 24)
		for _, row := range rows {
			if row.Key.DestCIDR != cidr {
				continue
			}
			bt := row.Bucket.Truncate(time.Hour)
			if bt.Before(hStart) || !bt.Before(hEnd) {
				continue
			}
			idx := int(bt.Sub(hStart) / time.Hour)
			if idx < 0 || idx >= 24 {
				continue
			}
			info.HourlyBytesOut[idx] += row.Metrics.BytesOut
			info.HourlyBytesIn[idx] += row.Metrics.BytesIn
			info.HourlyConnects[idx] += row.Metrics.Connects
		}

		// Protocol breakdown.
		protoMap := map[string]*ProtocolStat{}
		sniSet := map[string]map[string]struct{}{}
		for _, row := range rows {
			if row.Key.DestCIDR != cidr {
				continue
			}
			p := protocolOfFlow(row.Key.DestPort, row.Key.Protocol, row.Key.SNI)
			ps := protoMap[p]
			if ps == nil {
				ps = &ProtocolStat{Protocol: p}
				protoMap[p] = ps
				sniSet[p] = map[string]struct{}{}
			}
			ps.Flows++
			ps.BytesOut += row.Metrics.BytesOut
			ps.BytesIn += row.Metrics.BytesIn
			if row.Key.SNI != "" {
				sniSet[p][row.Key.SNI] = struct{}{}
			}
		}
		for p, ps := range protoMap {
			for sni := range sniSet[p] {
				ps.SNIs = append(ps.SNIs, sni)
			}
			sort.Strings(ps.SNIs)
			if len(ps.SNIs) > 10 {
				ps.SNIs = ps.SNIs[:10]
			}
			info.Protocols = append(info.Protocols, *ps)
		}
		sort.Slice(info.Protocols, func(i, j int) bool {
			return info.Protocols[i].BytesOut > info.Protocols[j].BytesOut
		})

		// Per-process activity.
		procMap := map[string]*ProcessActivity{}
		for _, row := range rows {
			if row.Key.DestCIDR != cidr {
				continue
			}
			pa := procMap[row.Key.Binary]
			if pa == nil {
				pa = &ProcessActivity{
					Binary:    row.Key.Binary,
					FirstSeen: row.Metrics.FirstSeen,
					LastSeen:  row.Metrics.LastSeen,
				}
				procMap[row.Key.Binary] = pa
			}
			pa.Connects += row.Metrics.Connects
			pa.BytesOut += row.Metrics.BytesOut
			pa.BytesIn += row.Metrics.BytesIn
			if !row.Metrics.FirstSeen.IsZero() &&
				(pa.FirstSeen.IsZero() || row.Metrics.FirstSeen.Before(pa.FirstSeen)) {
				pa.FirstSeen = row.Metrics.FirstSeen
			}
			if row.Metrics.LastSeen.After(pa.LastSeen) {
				pa.LastSeen = row.Metrics.LastSeen
			}
		}
		// Best-effort PID fill from connstate snapshot.
		if s.connstateSnap != nil {
			for _, c := range s.connstateSnap() {
				for _, pa := range procMap {
					if c.Comm == pa.Binary || c.Exe == pa.Binary {
						if pa.PID == 0 || c.PID > pa.PID {
							pa.PID = c.PID
						}
					}
				}
			}
		}
		for _, pa := range procMap {
			info.ProcessActivity = append(info.ProcessActivity, *pa)
		}
		sort.Slice(info.ProcessActivity, func(i, j int) bool {
			return info.ProcessActivity[i].BytesOut > info.ProcessActivity[j].BytesOut
		})

		// Related alerts (best-effort tail of alerts.jsonl).
		info.RelatedAlerts = tailRelatedAlerts(ip, 50)

		// Suspicion scoring (deterministic, explainable).
		info.Suspicion = computeSuspicion(info, rows, cidr)
	}

	// Whois only on explicit opt-in; the default page render stays fast.
	if r.URL.Query().Get("whois") == "1" && !info.IsPrivate && !info.IsLoopback {
		info.Whois = runWhois(r.Context(), ip)
	}

	writeJSONEgress(w, info)
}

// ── Phase-2 helpers (protocol/alerts/suspicion) ──────────────

// protocolOfFlow classifies an (port, protocol, sni) tuple into an
// app-level protocol name. Mirrors the client-side protocolOf() so
// the page can show consistent labels even before JS rendering.
func protocolOfFlow(port uint16, proto, sni string) string {
	p := strings.ToLower(proto)
	if sni != "" {
		return "HTTPS"
	}
	switch {
	case p == "tcp" && port == 443:
		return "HTTPS"
	case p == "tcp" && port == 80:
		return "HTTP"
	case p == "tcp" && port == 22:
		return "SSH"
	case (p == "tcp" || p == "udp") && port == 53:
		return "DNS"
	case p == "tcp" && (port == 25 || port == 465 || port == 587):
		return "SMTP"
	case p == "tcp" && (port == 143 || port == 993):
		return "IMAP"
	case p == "tcp" && (port == 110 || port == 995):
		return "POP3"
	case p == "tcp" && port == 3306:
		return "MySQL"
	case p == "tcp" && port == 5432:
		return "PostgreSQL"
	case p == "tcp" && port == 6379:
		return "Redis"
	case p == "udp" && port == 123:
		return "NTP"
	}
	return "Other"
}

// tailRelatedAlerts reads the last ~2MB of /var/log/xhelix/alerts.jsonl
// and returns alerts that reference this IP. Best-effort; a missing
// file or unreadable line is silently skipped (no error returned).
func tailRelatedAlerts(ip string, max int) []RelatedAlert {
	f, err := os.Open("/var/log/xhelix/alerts.jsonl")
	if err != nil {
		return nil
	}
	defer f.Close()
	if fi, ferr := f.Stat(); ferr == nil && fi.Size() > 2*1024*1024 {
		_, _ = f.Seek(fi.Size()-2*1024*1024, 0)
	}
	var out []RelatedAlert
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		// Fast pre-filter: skip lines that don't even contain the IP
		// as a substring. We still validate below that it's the real
		// dst_ip / src_ip — substring match alone is too loose.
		if !strings.Contains(line, ip) {
			continue
		}
		var raw map[string]any
		if json.Unmarshal([]byte(line), &raw) != nil {
			continue
		}
		// Extract dst_ip / src_ip from the alert envelope (tags map or
		// top-level event).
		var dstIP, srcIP string
		if ev, ok := raw["event"].(map[string]any); ok {
			if tags, ok := ev["tags"].(map[string]any); ok {
				if v, _ := tags["dst_ip"].(string); v != "" { dstIP = v }
				if v, _ := tags["src_ip"].(string); v != "" { srcIP = v }
			}
		}
		if dstIP == "" {
			if tags, ok := raw["tags"].(map[string]any); ok {
				if v, _ := tags["dst_ip"].(string); v != "" { dstIP = v }
				if v, _ := tags["src_ip"].(string); v != "" { srcIP = v }
			}
		}
		// Require structural match — substring hits in random fields
		// (paths, argv, cmdline, comm) don't count as "alert about
		// this IP".
		if dstIP != ip && srcIP != ip {
			continue
		}
		rid, _ := raw["rule_id"].(string)
		sev, _ := raw["severity"].(string)
		reason, _ := raw["reason"].(string)
		comm, _ := raw["comm"].(string)
		ts := time.Time{}
		if t, ok := raw["time"].(string); ok {
			ts, _ = time.Parse(time.RFC3339, t)
		}
		// Tag the relationship so the UI can show "src=this IP" vs
		// "dst=this IP" — important when the IP is a remote client.
		role := ""
		if dstIP == ip { role = "dst" } else if srcIP == ip { role = "src" }
		if reason != "" && role != "" {
			reason = "[" + role + "] " + reason
		}
		out = append(out, RelatedAlert{
			Time: ts, RuleID: rid, Severity: sev, Comm: comm, Reason: reason,
		})
	}
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

// computeSuspicion produces the deterministic, explainable suspicion
// score for this IP. Verdict bands: <20 normal, <50 watch, <80
// suspicious, ≥80 critical.
func computeSuspicion(info IPInfo, rows []egressledger.FlowRecord, cidr string) SuspicionScore {
	s := SuspicionScore{}
	add := func(cond string, delta int, detail string) {
		if delta == 0 {
			return
		}
		s.Contributions = append(s.Contributions, SuspicionContrib{
			Condition: cond, Delta: delta, Detail: detail,
		})
		s.Score += delta
	}

	// Direction awareness: when the majority of flows for this IP have
	// Role=="server", this host is the LISTENER and the remote IP is a
	// CLIENT connecting in. Several heuristics (non_standard_port,
	// unclassified, outbound_only, exfil_ratio) only make sense if WE
	// initiated. Skip them for inbound-dominant cases — otherwise every
	// legitimate inbound SSH/HTTPS client gets flagged as suspicious.
	var serverFlows, clientFlows int
	for _, r := range rows {
		if r.Key.DestCIDR != cidr {
			continue
		}
		switch r.Key.Role {
		case "server":
			serverFlows++
		case "client":
			clientFlows++
		}
	}
	inboundDominant := serverFlows > clientFlows && serverFlows > 0
	if inboundDominant {
		s.Contributions = append(s.Contributions, SuspicionContrib{
			Condition: "inbound_dominant",
			Delta:     0,
			Detail:    fmt.Sprintf("%d server-side flows vs %d client-side — this IP is a CLIENT to our local listener; outbound-shaped heuristics suppressed", serverFlows, clientFlows),
		})
	}

	if info.ThreatIntelHit != "" {
		add("threat_intel_hit", 60, info.ThreatIntelHit)
	}
	if isHighRiskCountry(info.Country) {
		add("high_risk_country", 20, info.Country)
	}
	if !inboundDominant && info.TotalBytesIn == 0 && info.TotalBytesOut > 0 {
		add("outbound_only", 25, "no inbound bytes observed (beacon shape)")
	}
	if info.ReverseDNS == "" && !info.IsPrivate && !info.IsLoopback && !info.IsLinkLocal {
		add("no_reverse_dns", 15, "raw-IP-only behavior")
	}
	if !info.FirstSeen.IsZero() && time.Since(info.FirstSeen) < 24*time.Hour {
		add("first_seen_recent", 10, "first observed less than 24h ago")
	}
	if info.CohortSize > 0 && info.CohortFraction < 0.1 {
		add("cohort_rare", 30, fmt.Sprintf("only %.0f%% of cohort peers also talk to this IP", info.CohortFraction*100))
	}
	if peak := peakHour(info.HourlyConnects); peak >= 2 && peak <= 5 {
		add("off_hours_pattern", 15, fmt.Sprintf("peak activity at %02d:00 local", peak))
	}
	if !inboundDominant && hasNonStandardPort(rows, cidr) {
		add("non_standard_port", 10, "connects to ports outside 80/443/53/22/25/465/587")
	}
	if !inboundDominant && (info.Class == "raw" || info.Class == "unknown" || info.Class == "") {
		add("unclassified", 15, "no destclass match (not cloud/cdn/known)")
	}
	if !inboundDominant && info.TotalBytesIn > 0 && info.TotalBytesOut > info.TotalBytesIn*5 {
		add("exfil_ratio", 15, fmt.Sprintf("bytes_out is %dx bytes_in", info.TotalBytesOut/info.TotalBytesIn))
	}
	for _, pa := range info.ProcessActivity {
		if isShellUtility(pa.Binary) {
			add("shell_utility_outbound", 35, pa.Binary+" should not initiate outbound")
			break
		}
	}

	switch {
	case s.Score < 20:
		s.Verdict = "normal"
	case s.Score < 50:
		s.Verdict = "watch"
	case s.Score < 80:
		s.Verdict = "suspicious"
	default:
		s.Verdict = "critical"
	}
	return s
}

// isHighRiskCountry is a hardcoded operator-tunable list. Honest
// non-promise: country attribution is at-best a hint; this is not
// a substitute for real threat intel.
func isHighRiskCountry(cc string) bool {
	high := map[string]bool{
		"CN": true, "RU": true, "IR": true, "KP": true,
		"BY": true, "SY": true, "VE": true, "CU": true,
	}
	return high[strings.ToUpper(cc)]
}

// isShellUtility matches binaries that should never initiate outbound
// traffic on their own. Match is on basename, case-insensitive.
func isShellUtility(name string) bool {
	base := strings.ToLower(filepath.Base(name))
	set := map[string]bool{
		"ls": true, "cat": true, "awk": true, "sed": true,
		"sort": true, "head": true, "tail": true, "find": true,
		"grep": true, "cut": true, "tr": true, "uniq": true,
		"wc": true, "xxd": true, "od": true, "base64": true,
		"ps": true, "top": true, "id": true, "whoami": true,
		"uname": true, "hostname": true, "cd": true, "pwd": true,
	}
	return set[base]
}

// hasNonStandardPort returns true if any flow row against cidr uses a
// port outside the conventional well-known set.
func hasNonStandardPort(rows []egressledger.FlowRecord, cidr string) bool {
	standard := map[uint16]bool{
		80: true, 443: true, 53: true, 22: true,
		25: true, 465: true, 587: true,
		143: true, 993: true, 110: true, 995: true,
		123: true, 3306: true, 5432: true, 6379: true,
		4318: true, 8090: true,
	}
	for _, r := range rows {
		if r.Key.DestCIDR != cidr {
			continue
		}
		if r.Key.DestPort > 0 && !standard[r.Key.DestPort] {
			return true
		}
	}
	return false
}

// peakHour returns the index of the hour bucket with the highest value,
// or -1 if the input isn't a 24-bucket slice.
func peakHour(hourly []uint64) int {
	if len(hourly) != 24 {
		return -1
	}
	var max uint64
	peak := -1
	for i, v := range hourly {
		if v > max {
			max = v
			peak = i
		}
	}
	return peak
}

// ── /api/egress/flow ──────────────────────────────────────────

func (s *Server) handleEgressFlow(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	binary := strings.TrimSpace(q.Get("binary"))
	destCIDR := strings.TrimSpace(q.Get("dest_cidr"))
	portStr := strings.TrimSpace(q.Get("port"))
	if binary == "" || destCIDR == "" {
		http.Error(w, "binary and dest_cidr params required", http.StatusBadRequest)
		return
	}
	var port uint16
	if portStr != "" {
		if n, err := strconv.Atoi(portStr); err == nil && n >= 0 && n <= 65535 {
			port = uint16(n)
		}
	}

	resp := FlowAnalysis{
		Binary:   binary,
		DestCIDR: destCIDR,
		DestPort: port,
	}
	if s.egress == nil {
		writeJSONEgress(w, resp)
		return
	}

	// Pull 7d of flows for this binary; we filter destCIDR/port locally
	// so we can also pick up "related flows" from the same query.
	end := time.Now()
	start := end.Add(-7 * 24 * time.Hour)
	rows := s.egress.QueryBinary(binary, start, end)

	hourly := map[int64]*FlowAnalysisTimePt{}
	otherDestsBytes := map[string]uint64{}
	otherDestsPort := map[string]uint16{}
	matched := false

	for _, row := range rows {
		if row.Key.DestCIDR == destCIDR && (port == 0 || row.Key.DestPort == port) {
			matched = true
			resp.TotalBytesOut += row.Metrics.BytesOut
			resp.TotalBytesIn += row.Metrics.BytesIn
			resp.TotalConnects += row.Metrics.Connects
			if row.Metrics.BytesOut > resp.PeakOutBytes {
				resp.PeakOutBytes = row.Metrics.BytesOut
			}
			if !row.Metrics.FirstSeen.IsZero() &&
				(resp.FirstSeen.IsZero() || row.Metrics.FirstSeen.Before(resp.FirstSeen)) {
				resp.FirstSeen = row.Metrics.FirstSeen
			}
			if row.Metrics.LastSeen.After(resp.LastSeen) {
				resp.LastSeen = row.Metrics.LastSeen
			}
			if resp.DestClass == "" && row.Key.DestClass != "" {
				resp.DestClass = row.Key.DestClass
			}
			h := row.Bucket.Truncate(time.Hour).Unix()
			tp := hourly[h]
			if tp == nil {
				tp = &FlowAnalysisTimePt{Hour: h}
				hourly[h] = tp
			}
			tp.BytesOut += row.Metrics.BytesOut
			tp.BytesIn += row.Metrics.BytesIn
			tp.Connects += row.Metrics.Connects
		} else {
			otherDestsBytes[row.Key.DestCIDR] += row.Metrics.BytesOut
			if _, ok := otherDestsPort[row.Key.DestCIDR]; !ok {
				otherDestsPort[row.Key.DestCIDR] = row.Key.DestPort
			}
		}
	}
	_ = matched // matched==false still returns a valid empty payload

	// Geo enrichment of the dest CIDR (best effort).
	if s.geoip != nil {
		if cc, _, _, ok := s.geoip.Lookup(firstHostIP(destCIDR)); ok {
			resp.DestCountry = cc
		}
	}

	// Timeline — sorted ascending by hour.
	for _, tp := range hourly {
		resp.Timeline = append(resp.Timeline, *tp)
	}
	sort.Slice(resp.Timeline, func(i, j int) bool { return resp.Timeline[i].Hour < resp.Timeline[j].Hour })

	// Live connections + initiator (filtered to this binary+dest).
	if s.connstateSnap != nil {
		conns := s.connstateSnap()
		var initiator *FlowInitiator
		for _, c := range conns {
			// Match by binary (exe or comm) + dest IP that bucketizes
			// into our destCIDR.
			if c.Exe != binary && c.Comm != binary {
				continue
			}
			ip := net.ParseIP(c.DstAddr)
			if ip == nil {
				continue
			}
			if cidrFor(ip) != destCIDR {
				continue
			}
			if port != 0 && c.DstPort != port {
				continue
			}
			resp.LiveConns = append(resp.LiveConns, c)
			if initiator == nil || c.OpenedAt < initiator.OpenedAt.Unix() {
				parentComm := ""
				if s.proctree != nil && c.PPID != 0 {
					parentComm = s.proctree.ParentComm(c.PPID)
				}
				initiator = &FlowInitiator{
					PID:        c.PID,
					PPID:       c.PPID,
					ParentComm: parentComm,
					OpenedAt:   time.Unix(c.OpenedAt, 0),
				}
			}
		}
		resp.Initiator = initiator
	}

	// Related: top 5 other dests this binary talks to.
	type relKV struct {
		cidr  string
		bytes uint64
	}
	rels := make([]relKV, 0, len(otherDestsBytes))
	for c, b := range otherDestsBytes {
		rels = append(rels, relKV{cidr: c, bytes: b})
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].bytes > rels[j].bytes })
	if len(rels) > 5 {
		rels = rels[:5]
	}
	for _, r := range rels {
		resp.RelatedFlows = append(resp.RelatedFlows, FlowAnalysisRelated{
			Binary:   binary,
			DestCIDR: r.cidr,
			DestPort: otherDestsPort[r.cidr],
			BytesOut: r.bytes,
			Reason:   "same binary, other destination",
		})
	}

	// Related: top 5 other binaries that talk to the same dest_cidr.
	// Needs a separate ledger pass scoped to the CIDR.
	tlRows := s.egress.QueryTimeline(start, end, egressledger.FlowFilter{
		UID: -1, CGroupID: -1, DestPort: -1,
		DestCIDR: destCIDR,
	})
	otherBins := map[string]uint64{}
	for _, row := range tlRows {
		if row.Key.Binary == binary {
			continue
		}
		otherBins[row.Key.Binary] += row.Metrics.BytesOut
	}
	binRels := make([]relKV, 0, len(otherBins))
	for b, by := range otherBins {
		binRels = append(binRels, relKV{cidr: b, bytes: by})
	}
	sort.Slice(binRels, func(i, j int) bool { return binRels[i].bytes > binRels[j].bytes })
	if len(binRels) > 5 {
		binRels = binRels[:5]
	}
	for _, r := range binRels {
		resp.RelatedFlows = append(resp.RelatedFlows, FlowAnalysisRelated{
			Binary:   r.cidr, // here `cidr` field re-used as binary name
			DestCIDR: destCIDR,
			BytesOut: r.bytes,
			Reason:   "same destination, other binary",
		})
	}

	// Source lineage: best-effort, from proctree using the initiator PID.
	if resp.Initiator != nil && s.proctree != nil {
		if pc := s.proctree.ParentComm(resp.Initiator.PID); pc != "" {
			resp.SourceLineage = append(resp.SourceLineage, pc)
		}
		if resp.Initiator.ParentComm != "" {
			resp.SourceLineage = append(resp.SourceLineage, resp.Initiator.ParentComm)
		}
	}

	writeJSONEgress(w, resp)
}
