// Package web — country drilldown handler. Given a country code
// (ISO 3166-1 alpha-2), aggregates every flow that landed in that
// country over the requested window, returning the data the
// dashboard's /egress/country detail page needs (timeline, top
// binaries, top ASNs, top destinations, ports).
package web

import (
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/egressledger"
)

// CountryDetail is the drilldown payload returned by /api/egress/country.
type CountryDetail struct {
	Country          string                       `json:"country"`
	Hours            int                          `json:"hours"`
	BytesOut         uint64                       `json:"bytes_out"`
	BytesIn          uint64                       `json:"bytes_in"`
	Connects         uint64                       `json:"connects"`
	DistinctDests    int                          `json:"distinct_dests"`
	DistinctBinaries int                          `json:"distinct_binaries"`
	DistinctASNs     int                          `json:"distinct_asns"`
	TopBinaries      []CountryDetailBinary        `json:"top_binaries"`
	TopASNs          []CountryDetailASN           `json:"top_asns"`
	TopDests         []CountryDetailDest          `json:"top_dests"`
	Ports            []CountryDetailPort          `json:"ports"`
	Timeline         []CountryDetailTimePt        `json:"timeline"`
	// BinaryDests maps each binary in this country to the IP+port rows
	// it touched. The drilldown UI expands a binary row to show this
	// data — the "which python is sending to HK and where" question.
	BinaryDests map[string][]BinaryDestRow `json:"binary_dests"`
	// Investigation is the "Who/what/when/why" summary card.
	Investigation InvestigationSummary `json:"investigation"`
	// LiveProcesses are currently-running processes (from connstate)
	// with an active socket to any destination in this country. PID,
	// parent, cmdline — the "which python is sending to HK" surface.
	LiveProcesses []LiveProcInfo `json:"live_processes,omitempty"`
	// RelatedAlerts are alerts from the daemon's ring whose dst_ip
	// matches any destination in this country (last ring window).
	RelatedAlerts []AlertSummary `json:"related_alerts,omitempty"`
	// ProcessInventory is the deep dive per binary: every currently-
	// running PID with cmdline, ancestors, systemd unit, etc.
	ProcessInventory []ProcessInventory `json:"process_inventory,omitempty"`
	// HistoricalPIDs records every PID that touched any country
	// destination during the requested window — including exited ones.
	// Sourced from the ledger's recent-events ring.
	HistoricalPIDs []HistoricalPID `json:"historical_pids,omitempty"`
}

// HistoricalPID is one (PID, binary, dest, time-range) row.
type HistoricalPID struct {
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid,omitempty"`
	Comm       string    `json:"comm"`
	Binary     string    `json:"binary"`
	ParentComm string    `json:"parent_comm,omitempty"`
	UID        uint32    `json:"uid"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Dests      []string  `json:"dests"`
	BytesOut   uint64    `json:"bytes_out"`
	BytesIn    uint64    `json:"bytes_in"`
	StillAlive bool      `json:"still_alive"`

	ContainerID    string `json:"container_id,omitempty"`
	ContainerClass string `json:"container_class,omitempty"`
	Unit           string `json:"unit,omitempty"`
	// Container is the display token for the "Container" cell: short
	// container id when ContainerClass=="container", else the class token.
	Container string `json:"container,omitempty"`
}

// containerCell renders the "Container" display token: the first 12 chars
// of the container id (full id if shorter) when class=="container",
// otherwise the class token (e.g. "user"/"system"). Empty for "unknown".
func containerCell(class, id string) string {
	if class == "container" {
		if len(id) > 12 {
			return id[:12]
		}
		return id
	}
	if class == "unknown" || class == "" {
		return ""
	}
	return class
}

// LiveProcInfo is one row in the "running processes with a socket to
// this country right now" table.
type LiveProcInfo struct {
	PID        uint32 `json:"pid"`
	PPID       uint32 `json:"ppid"`
	ParentComm string `json:"parent_comm,omitempty"`
	Comm       string `json:"comm"`
	Exe        string `json:"exe,omitempty"`
	DstAddr    string `json:"dst_addr"`
	DstPort    uint16 `json:"dst_port"`
	SNI        string `json:"sni,omitempty"`
	BytesOut   uint64 `json:"bytes_out"`
	BytesIn    uint64 `json:"bytes_in"`
	OpenedAt   int64  `json:"opened_at"` // unix seconds
	Unit       string `json:"unit,omitempty"`
	UserID     string `json:"user_id,omitempty"`
}

// BinaryDestRow is one (binary → IP:port) row for the expansion view.
type BinaryDestRow struct {
	CIDR      string    `json:"cidr"`
	Port      uint16    `json:"port"`
	Protocol  string    `json:"protocol,omitempty"`
	SNI       string    `json:"sni,omitempty"`
	DNSName   string    `json:"dns_name,omitempty"`
	BytesOut  uint64    `json:"bytes_out"`
	BytesIn   uint64    `json:"bytes_in"`
	Connects  uint64    `json:"connects"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// InvestigationSummary is the at-a-glance verdict card.
type InvestigationSummary struct {
	FirstContact    time.Time `json:"first_contact"`
	LastContact     time.Time `json:"last_contact"`
	BurstinessRatio float64   `json:"burstiness_ratio"` // stddev / mean of per-bucket bytes_out; >1.5 = bursty, <0.5 = sustained
	Pattern         string    `json:"pattern"`          // "sustained" | "bursty" | "one-shot" | "intermittent"
	SuggestedBlock  string    `json:"suggested_block,omitempty"`
	Notes           []string  `json:"notes,omitempty"`
}

// CountryDetailBinary is one row in the "top binaries" table.
type CountryDetailBinary struct {
	Binary   string `json:"binary"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	Connects uint64 `json:"connects"`
	Dests    int    `json:"dests"`
}

// CountryDetailASN is one row in the "top ASNs" table.
type CountryDetailASN struct {
	ASN      string `json:"asn"`
	Org      string `json:"org"`
	BytesOut uint64 `json:"bytes_out"`
	Dests    int    `json:"dests"`
}

// CountryDetailDest is one row in the "top destinations" table.
type CountryDetailDest struct {
	CIDR     string `json:"cidr"`
	Port     uint16 `json:"port"`
	SNI      string `json:"sni,omitempty"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	Connects uint64 `json:"connects"`
}

// CountryDetailPort aggregates by (port, protocol).
type CountryDetailPort struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	BytesOut uint64 `json:"bytes_out"`
	Flows    int    `json:"flows"`
}

// CountryDetailTimePt is one hourly bucket on the timeline.
type CountryDetailTimePt struct {
	Bucket   time.Time `json:"bucket"`
	BytesOut uint64    `json:"bytes_out"`
	BytesIn  uint64    `json:"bytes_in"`
	Connects uint64    `json:"connects"`
}

func (s *Server) handleEgressCountry(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, CountryDetail{})
		return
	}
	cc := strings.ToUpper(r.URL.Query().Get("country"))
	if cc == "" {
		http.Error(w, "country param required (ISO 3166-1 alpha-2)", http.StatusBadRequest)
		return
	}
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 720 {
			hours = n
		}
	}
	end := time.Now()
	start := end.Add(-time.Duration(hours) * time.Hour)
	rows := s.egress.QueryTimeline(start, end, egressledger.FlowFilter{
		UID: -1, CGroupID: -1, DestPort: -1,
	})

	out := CountryDetail{Country: cc, Hours: hours}

	type binAcc struct {
		bytesOut, bytesIn, connects uint64
		dests                       map[string]struct{}
	}
	type asnAcc struct {
		org      string
		bytesOut uint64
		dests    map[string]struct{}
	}
	type destAcc struct {
		cidr     string
		port     uint16
		sni      string
		bytesOut uint64
		bytesIn  uint64
		connects uint64
	}
	type portAcc struct {
		port     uint16
		proto    string
		bytesOut uint64
		flows    int
	}

	bins := map[string]*binAcc{}
	asns := map[string]*asnAcc{}
	dests := map[string]*destAcc{}
	ports := map[string]*portAcc{}
	timeline := map[time.Time]*CountryDetailTimePt{}
	distinctDestSet := map[string]struct{}{}
	// binaryDestAcc: binary -> (cidr|port) -> aggregated BinaryDestRow
	type bdKey struct{ cidr, sni, dns string; port uint16; proto string }
	binDestAcc := map[string]map[bdKey]*BinaryDestRow{}
	var firstContact, lastContact time.Time

	for _, rec := range rows {
		ip := firstHostIP(rec.Key.DestCIDR)
		var rowCC, rowASN, rowOrg string
		if s.geoip != nil {
			if c, a, o, ok := s.geoip.Lookup(ip); ok {
				rowCC, rowASN, rowOrg = c, a, o
			}
		}
		// When cc=="??", match rows where geoip lookup failed (rowCC=="").
		// Otherwise require an exact ISO code match.
		if cc == "??" {
			if rowCC != "" {
				continue
			}
		} else if rowCC != cc {
			continue
		}
		out.BytesOut += rec.Metrics.BytesOut
		out.BytesIn += rec.Metrics.BytesIn
		out.Connects += rec.Metrics.Connects
		distinctDestSet[rec.Key.DestCIDR] = struct{}{}

		if firstContact.IsZero() || rec.Metrics.FirstSeen.Before(firstContact) {
			firstContact = rec.Metrics.FirstSeen
		}
		if rec.Metrics.LastSeen.After(lastContact) {
			lastContact = rec.Metrics.LastSeen
		}

		// Per-binary destinations expansion.
		bm := binDestAcc[rec.Key.Binary]
		if bm == nil {
			bm = map[bdKey]*BinaryDestRow{}
			binDestAcc[rec.Key.Binary] = bm
		}
		bk := bdKey{cidr: rec.Key.DestCIDR, port: rec.Key.DestPort, proto: rec.Key.Protocol, sni: rec.Key.SNI, dns: rec.Key.DNSName}
		bd := bm[bk]
		if bd == nil {
			bd = &BinaryDestRow{
				CIDR: rec.Key.DestCIDR, Port: rec.Key.DestPort, Protocol: rec.Key.Protocol,
				SNI: rec.Key.SNI, DNSName: rec.Key.DNSName,
				FirstSeen: rec.Metrics.FirstSeen, LastSeen: rec.Metrics.LastSeen,
			}
			bm[bk] = bd
		}
		bd.BytesOut += rec.Metrics.BytesOut
		bd.BytesIn += rec.Metrics.BytesIn
		bd.Connects += rec.Metrics.Connects
		if rec.Metrics.FirstSeen.Before(bd.FirstSeen) || bd.FirstSeen.IsZero() {
			bd.FirstSeen = rec.Metrics.FirstSeen
		}
		if rec.Metrics.LastSeen.After(bd.LastSeen) {
			bd.LastSeen = rec.Metrics.LastSeen
		}

		// Binaries.
		b := bins[rec.Key.Binary]
		if b == nil {
			b = &binAcc{dests: map[string]struct{}{}}
			bins[rec.Key.Binary] = b
		}
		b.bytesOut += rec.Metrics.BytesOut
		b.bytesIn += rec.Metrics.BytesIn
		b.connects += rec.Metrics.Connects
		b.dests[rec.Key.DestCIDR] = struct{}{}

		// ASNs.
		akey := rowASN
		if akey == "" {
			akey = "unknown"
		}
		a := asns[akey]
		if a == nil {
			a = &asnAcc{org: rowOrg, dests: map[string]struct{}{}}
			asns[akey] = a
		}
		a.bytesOut += rec.Metrics.BytesOut
		a.dests[rec.Key.DestCIDR] = struct{}{}

		// Destinations.
		dk := rec.Key.DestCIDR + ":" + strconv.Itoa(int(rec.Key.DestPort))
		d := dests[dk]
		if d == nil {
			d = &destAcc{cidr: rec.Key.DestCIDR, port: rec.Key.DestPort, sni: rec.Key.SNI}
			dests[dk] = d
		}
		d.bytesOut += rec.Metrics.BytesOut
		d.bytesIn += rec.Metrics.BytesIn
		d.connects += rec.Metrics.Connects
		if d.sni == "" {
			d.sni = rec.Key.SNI
		}

		// Ports.
		proto := rec.Key.Protocol
		if proto == "" {
			proto = "—"
		}
		pk := strconv.Itoa(int(rec.Key.DestPort)) + "/" + proto
		p := ports[pk]
		if p == nil {
			p = &portAcc{port: rec.Key.DestPort, proto: proto}
			ports[pk] = p
		}
		p.bytesOut += rec.Metrics.BytesOut
		p.flows++

		// Timeline (hour-floored).
		bucket := rec.Bucket.Truncate(time.Hour)
		tp := timeline[bucket]
		if tp == nil {
			tp = &CountryDetailTimePt{Bucket: bucket}
			timeline[bucket] = tp
		}
		tp.BytesOut += rec.Metrics.BytesOut
		tp.BytesIn += rec.Metrics.BytesIn
		tp.Connects += rec.Metrics.Connects
	}

	out.DistinctDests = len(distinctDestSet)
	out.DistinctBinaries = len(bins)
	// DistinctASNs — exclude the synthetic "unknown" bucket from the
	// distinct count so the number tracks real ASNs, not "missing geo".
	for k := range asns {
		if k != "unknown" {
			out.DistinctASNs++
		}
	}

	for name, b := range bins {
		out.TopBinaries = append(out.TopBinaries, CountryDetailBinary{
			Binary:   name,
			BytesOut: b.bytesOut,
			BytesIn:  b.bytesIn,
			Connects: b.connects,
			Dests:    len(b.dests),
		})
	}
	sort.Slice(out.TopBinaries, func(i, j int) bool {
		return out.TopBinaries[i].BytesOut > out.TopBinaries[j].BytesOut
	})
	if len(out.TopBinaries) > 20 {
		out.TopBinaries = out.TopBinaries[:20]
	}

	for asn, a := range asns {
		out.TopASNs = append(out.TopASNs, CountryDetailASN{
			ASN: asn, Org: a.org, BytesOut: a.bytesOut, Dests: len(a.dests),
		})
	}
	sort.Slice(out.TopASNs, func(i, j int) bool {
		return out.TopASNs[i].BytesOut > out.TopASNs[j].BytesOut
	})
	if len(out.TopASNs) > 20 {
		out.TopASNs = out.TopASNs[:20]
	}

	for _, d := range dests {
		out.TopDests = append(out.TopDests, CountryDetailDest{
			CIDR: d.cidr, Port: d.port, SNI: d.sni,
			BytesOut: d.bytesOut, BytesIn: d.bytesIn, Connects: d.connects,
		})
	}
	sort.Slice(out.TopDests, func(i, j int) bool {
		return out.TopDests[i].BytesOut > out.TopDests[j].BytesOut
	})
	if len(out.TopDests) > 50 {
		out.TopDests = out.TopDests[:50]
	}

	for _, p := range ports {
		out.Ports = append(out.Ports, CountryDetailPort{
			Port: p.port, Protocol: p.proto, BytesOut: p.bytesOut, Flows: p.flows,
		})
	}
	sort.Slice(out.Ports, func(i, j int) bool {
		return out.Ports[i].BytesOut > out.Ports[j].BytesOut
	})
	if len(out.Ports) > 20 {
		out.Ports = out.Ports[:20]
	}

	for _, t := range timeline {
		out.Timeline = append(out.Timeline, *t)
	}
	sort.Slice(out.Timeline, func(i, j int) bool {
		return out.Timeline[i].Bucket.Before(out.Timeline[j].Bucket)
	})

	// BinaryDests: emit top 25 dests per binary, sorted by bytes_out desc.
	out.BinaryDests = map[string][]BinaryDestRow{}
	for bin, dm := range binDestAcc {
		rows := make([]BinaryDestRow, 0, len(dm))
		for _, r := range dm {
			rows = append(rows, *r)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].BytesOut > rows[j].BytesOut })
		if len(rows) > 25 {
			rows = rows[:25]
		}
		out.BinaryDests[bin] = rows
	}

	// Investigation: pattern classification from timeline burstiness.
	inv := InvestigationSummary{FirstContact: firstContact, LastContact: lastContact}
	if n := len(out.Timeline); n > 0 {
		var sum, sumSq uint64
		for _, t := range out.Timeline {
			sum += t.BytesOut
			sumSq += t.BytesOut * t.BytesOut
		}
		mean := float64(sum) / float64(n)
		var stddev float64
		if mean > 0 {
			variance := float64(sumSq)/float64(n) - mean*mean
			if variance > 0 {
				stddev = sqrtFloat(variance)
			}
			inv.BurstinessRatio = stddev / mean
		}
		switch {
		case n == 1:
			inv.Pattern = "one-shot"
		case inv.BurstinessRatio > 1.5:
			inv.Pattern = "bursty"
		case inv.BurstinessRatio < 0.5 && n >= 3:
			inv.Pattern = "sustained"
		default:
			inv.Pattern = "intermittent"
		}
	}
	// Suggested block: if all dests share a /24, propose it.
	if cc != "??" && len(out.TopDests) > 0 && len(out.TopDests) <= 50 {
		var pfx string
		all := true
		for i, d := range out.TopDests {
			ip := firstHostIP(d.CIDR)
			parts := strings.Split(ip, ".")
			if len(parts) < 4 {
				all = false
				break
			}
			p24 := parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
			if i == 0 {
				pfx = p24
			} else if pfx != p24 {
				all = false
				break
			}
		}
		if all && pfx != "" && len(out.TopDests) >= 2 {
			inv.SuggestedBlock = pfx
			inv.Notes = append(inv.Notes, "All "+strconv.Itoa(len(out.TopDests))+" destinations are in "+pfx+" — single safety-net block would cover them.")
		}
	}
	out.Investigation = inv

	// Build set of destination IPs (exact + /16/24 prefix-match) for
	// matching live conns and recent alerts.
	destIPSet := map[string]bool{}
	for cidr := range distinctDestSet {
		destIPSet[firstHostIP(cidr)] = true
	}

	// Live processes: current sockets to any country dest.
	if s.connstateSnap != nil && len(destIPSet) > 0 {
		conns := s.connstateSnap()
		seenPID := map[uint32]bool{}
		for _, c := range conns {
			if !destIPSet[c.DstAddr] {
				continue
			}
			if seenPID[c.PID] {
				continue
			}
			seenPID[c.PID] = true
			info := LiveProcInfo{
				PID: c.PID, PPID: c.PPID, Comm: c.Comm, Exe: c.Exe,
				DstAddr: c.DstAddr, DstPort: c.DstPort,
				SNI: c.SNI, BytesOut: c.BytesOut, BytesIn: c.BytesIn,
				OpenedAt: c.OpenedAt, Unit: c.Unit, UserID: c.UserID,
			}
			if s.proctree != nil {
				info.ParentComm = s.proctree.ParentComm(c.PID)
			}
			out.LiveProcesses = append(out.LiveProcesses, info)
		}
		sort.Slice(out.LiveProcesses, func(i, j int) bool {
			return out.LiveProcesses[i].BytesOut > out.LiveProcesses[j].BytesOut
		})
		if len(out.LiveProcesses) > 50 {
			out.LiveProcesses = out.LiveProcesses[:50]
		}
	}

	// Process inventory: per-binary /proc walk with cmdline, ancestors,
	// unit, listening ports + direction classification.
	for _, b := range out.TopBinaries {
		entries := procWalkByBinary(b.Binary)
		// Enrich each with ancestor chain + country-scoped dests from
		// live connstate snapshot.
		if s.procAnc != nil {
			for i := range entries {
				ans := s.procAnc.Ancestors(entries[i].PID, 5)
				for _, a := range ans {
					entries[i].Ancestors = append(entries[i].Ancestors, ProcessAnc{PID: a.PID, Comm: a.Comm, Exe: a.Exe})
				}
			}
		}
		// Map live conns by PID for country-scoped dst attribution.
		if s.connstateSnap != nil {
			conns := s.connstateSnap()
			byPID := map[uint32][]string{}
			for _, c := range conns {
				if destIPSet[c.DstAddr] {
					byPID[c.PID] = append(byPID[c.PID], c.DstAddr+":"+strconv.Itoa(int(c.DstPort)))
				}
			}
			for i := range entries {
				if d, ok := byPID[entries[i].PID]; ok {
					entries[i].CountryDests = d
				}
			}
		}
		inv := ProcessInventory{Binary: b.Binary, PIDs: entries}
		// Direction classifier from this binary's destinations.
		listenSet := map[uint16]bool{}
		for _, e := range entries {
			for _, p := range e.ListenPorts {
				listenSet[p] = true
			}
		}
		listens := make([]uint16, 0, len(listenSet))
		for p := range listenSet {
			listens = append(listens, p)
		}
		inv.Direction, inv.DirNote = classifyDirection(out.BinaryDests[b.Binary], listens)
		out.ProcessInventory = append(out.ProcessInventory, inv)
	}

	// Historical PIDs from the recent-events ring. Groups events by PID
	// and joins with proctree for parent_comm. Includes already-exited
	// processes (which the live /proc walk cannot reach).
	if len(destIPSet) > 0 {
		recent := s.egress.QueryRecent(start, destIPSet, "", 8192)
		type pidAgg struct {
			h     *HistoricalPID
			dests map[string]struct{}
		}
		byPID := map[uint32]*pidAgg{}
		for _, r := range recent {
			ag := byPID[r.PID]
			if ag == nil {
				ag = &pidAgg{h: &HistoricalPID{
					PID: r.PID, PPID: r.PPID, Comm: r.Comm,
					Binary: r.Binary, UID: r.UID,
					FirstSeen: r.Time, LastSeen: r.Time,
					ContainerID:    r.ContainerID,
					ContainerClass: r.ContainerClass,
					Unit:           r.Unit,
					Container:      containerCell(r.ContainerClass, r.ContainerID),
				}, dests: map[string]struct{}{}}
				byPID[r.PID] = ag
			}
			if r.Time.Before(ag.h.FirstSeen) {
				ag.h.FirstSeen = r.Time
			}
			if r.Time.After(ag.h.LastSeen) {
				ag.h.LastSeen = r.Time
			}
			ag.h.BytesOut += r.BytesOut
			ag.h.BytesIn += r.BytesIn
			ag.dests[r.DestIP+":"+strconv.Itoa(int(r.DestPort))] = struct{}{}
		}
		// Liveness check by looking for /proc/<pid>.
		for pid, ag := range byPID {
			for d := range ag.dests {
				ag.h.Dests = append(ag.h.Dests, d)
			}
			if len(ag.h.Dests) > 8 {
				ag.h.Dests = ag.h.Dests[:8]
			}
			if _, err := os.Stat("/proc/" + strconv.Itoa(int(pid))); err == nil {
				ag.h.StillAlive = true
			}
			if s.proctree != nil && ag.h.ParentComm == "" {
				ag.h.ParentComm = s.proctree.ParentComm(pid)
			}
			out.HistoricalPIDs = append(out.HistoricalPIDs, *ag.h)
		}
		sort.Slice(out.HistoricalPIDs, func(i, j int) bool {
			return out.HistoricalPIDs[i].BytesOut > out.HistoricalPIDs[j].BytesOut
		})
		if len(out.HistoricalPIDs) > 50 {
			out.HistoricalPIDs = out.HistoricalPIDs[:50]
		}
	}

	// Related alerts: filter ring snapshot for matching dst_ip.
	if s.alertSnap != nil && len(destIPSet) > 0 {
		alerts := s.alertSnap()
		for _, a := range alerts {
			if a.DstIP == "" || !destIPSet[a.DstIP] {
				continue
			}
			out.RelatedAlerts = append(out.RelatedAlerts, a)
		}
		sort.Slice(out.RelatedAlerts, func(i, j int) bool {
			return out.RelatedAlerts[i].Time.After(out.RelatedAlerts[j].Time)
		})
		if len(out.RelatedAlerts) > 50 {
			out.RelatedAlerts = out.RelatedAlerts[:50]
		}
	}

	writeJSONEgress(w, out)
}

// sqrtFloat avoids pulling math just for one sqrt call.
func sqrtFloat(x float64) float64 {
	if x <= 0 {
		return 0
	}
	z := x / 2
	for i := 0; i < 24; i++ {
		z = z - (z*z-x)/(2*z)
	}
	return z
}

