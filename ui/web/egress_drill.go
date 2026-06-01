// Package web — process / PID / verdict deep-drill endpoints.
//
// /api/egress/process_detail?binary=X — rich per-process page payload
// /api/egress/pid?pid=N              — per-PID forensic page payload
// /api/egress/verdict                — global posture summary
//
// All three lean on data already collected by the ledger (flow rows
// + recent ring), connstate (live conns), proctree (ancestor chain),
// /proc (cmdline/cwd/exe/unit) and alert ring.
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

// ── Process detail ────────────────────────────────────────────

// ProcessDetail is the payload returned by /api/egress/process_detail.
type ProcessDetail struct {
	Binary           string                `json:"binary"`
	BytesOut         uint64                `json:"bytes_out"`
	BytesIn          uint64                `json:"bytes_in"`
	Conns            uint64                `json:"conns"`
	Blocked          uint64                `json:"blocked"`
	DistinctDests    int                   `json:"distinct_dests"`
	DistinctCountries int                  `json:"distinct_countries"`
	DistinctASNs     int                   `json:"distinct_asns"`
	FirstSeen        time.Time             `json:"first_seen"`
	LastSeen         time.Time             `json:"last_seen"`
	Direction        string                `json:"direction"`
	DirectionNote    string                `json:"direction_note"`
	TopCountries     []ProcessCountry      `json:"top_countries"`
	TopASNs          []ProcessASN          `json:"top_asns"`
	TopDests         []ProcessDest         `json:"top_dests"`
	TopPorts         []ProcessPort         `json:"top_ports"`
	LivePIDs         []ProcessEntry        `json:"live_pids"`
	HistoricalPIDs   []HistoricalPID       `json:"historical_pids"`
	RelatedAlerts    []AlertSummary        `json:"related_alerts"`
	SuggestedBlock   string                `json:"suggested_block,omitempty"`
	Timeline         []ProcessTimePoint    `json:"timeline"`
}

type ProcessCountry struct {
	Country  string `json:"country"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	Dests    int    `json:"dests"`
}
type ProcessASN struct {
	ASN      string `json:"asn"`
	Org      string `json:"org"`
	BytesOut uint64 `json:"bytes_out"`
	Dests    int    `json:"dests"`
}
type ProcessDest struct {
	CIDR     string `json:"cidr"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Country  string `json:"country,omitempty"`
	ASN      string `json:"asn,omitempty"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	Conns    uint64 `json:"conns"`
}
type ProcessPort struct {
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	BytesOut uint64 `json:"bytes_out"`
	Flows    int    `json:"flows"`
}
type ProcessTimePoint struct {
	Bucket   time.Time `json:"bucket"`
	BytesOut uint64    `json:"bytes_out"`
	BytesIn  uint64    `json:"bytes_in"`
}

func (s *Server) handleEgressProcessDetail(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil {
		writeJSONEgress(w, ProcessDetail{})
		return
	}
	binary := r.URL.Query().Get("binary")
	if binary == "" {
		http.Error(w, "binary required", http.StatusBadRequest)
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
		Binary: binary, UID: -1, CGroupID: -1, DestPort: -1,
	})

	out := ProcessDetail{Binary: binary}

	cMap := map[string]*ProcessCountry{}
	aMap := map[string]*ProcessASN{}
	aOrg := map[string]string{}
	dMap := map[string]*ProcessDest{}
	pMap := map[string]*ProcessPort{}
	cDests := map[string]map[string]struct{}{}
	aDests := map[string]map[string]struct{}{}
	destSet := map[string]struct{}{}
	tlMap := map[time.Time]*ProcessTimePoint{}
	var ports []uint16

	for _, r := range rows {
		k := r.Key
		m := r.Metrics
		out.BytesOut += m.BytesOut
		out.BytesIn += m.BytesIn
		out.Conns += m.Connects
		out.Blocked += m.DenyEvents
		destSet[k.DestCIDR] = struct{}{}
		ports = append(ports, k.DestPort)
		if out.FirstSeen.IsZero() || m.FirstSeen.Before(out.FirstSeen) {
			out.FirstSeen = m.FirstSeen
		}
		if m.LastSeen.After(out.LastSeen) {
			out.LastSeen = m.LastSeen
		}
		// Country + ASN via geoip on first host of CIDR.
		var cc, asn, org string
		if s.geoip != nil {
			cc, asn, org, _ = s.geoip.Lookup(firstHostIP(k.DestCIDR))
		}
		if cc != "" {
			c := cMap[cc]
			if c == nil { c = &ProcessCountry{Country: cc}; cMap[cc] = c }
			c.BytesOut += m.BytesOut
			c.BytesIn += m.BytesIn
			if cDests[cc] == nil { cDests[cc] = map[string]struct{}{} }
			cDests[cc][k.DestCIDR] = struct{}{}
		}
		if asn != "" {
			a := aMap[asn]
			if a == nil { a = &ProcessASN{ASN: asn}; aMap[asn] = a }
			a.BytesOut += m.BytesOut
			if aOrg[asn] == "" { aOrg[asn] = org }
			if aDests[asn] == nil { aDests[asn] = map[string]struct{}{} }
			aDests[asn][k.DestCIDR] = struct{}{}
		}
		// Destinations.
		dk := k.DestCIDR + ":" + strconv.Itoa(int(k.DestPort))
		d := dMap[dk]
		if d == nil {
			d = &ProcessDest{CIDR: k.DestCIDR, Port: k.DestPort, Protocol: k.Protocol, SNI: k.SNI, Country: cc, ASN: asn}
			dMap[dk] = d
		}
		d.BytesOut += m.BytesOut
		d.BytesIn += m.BytesIn
		d.Conns += m.Connects
		// Ports.
		pk := strconv.Itoa(int(k.DestPort)) + "/" + k.Protocol
		p := pMap[pk]
		if p == nil { p = &ProcessPort{Port: k.DestPort, Protocol: k.Protocol}; pMap[pk] = p }
		p.BytesOut += m.BytesOut
		p.Flows++
		// Timeline.
		bk := r.Bucket.Truncate(time.Hour)
		t := tlMap[bk]
		if t == nil { t = &ProcessTimePoint{Bucket: bk}; tlMap[bk] = t }
		t.BytesOut += m.BytesOut
		t.BytesIn += m.BytesIn
	}
	out.DistinctDests = len(destSet)
	out.DistinctCountries = len(cMap)
	out.DistinctASNs = len(aMap)

	for cc, c := range cMap {
		c.Dests = len(cDests[cc])
		out.TopCountries = append(out.TopCountries, *c)
	}
	sort.Slice(out.TopCountries, func(i, j int) bool { return out.TopCountries[i].BytesOut > out.TopCountries[j].BytesOut })
	if len(out.TopCountries) > 20 { out.TopCountries = out.TopCountries[:20] }

	for asn, a := range aMap {
		a.Dests = len(aDests[asn])
		a.Org = aOrg[asn]
		out.TopASNs = append(out.TopASNs, *a)
	}
	sort.Slice(out.TopASNs, func(i, j int) bool { return out.TopASNs[i].BytesOut > out.TopASNs[j].BytesOut })
	if len(out.TopASNs) > 20 { out.TopASNs = out.TopASNs[:20] }

	for _, d := range dMap { out.TopDests = append(out.TopDests, *d) }
	sort.Slice(out.TopDests, func(i, j int) bool { return out.TopDests[i].BytesOut > out.TopDests[j].BytesOut })
	if len(out.TopDests) > 50 { out.TopDests = out.TopDests[:50] }

	for _, p := range pMap { out.TopPorts = append(out.TopPorts, *p) }
	sort.Slice(out.TopPorts, func(i, j int) bool { return out.TopPorts[i].BytesOut > out.TopPorts[j].BytesOut })
	if len(out.TopPorts) > 15 { out.TopPorts = out.TopPorts[:15] }

	for _, t := range tlMap { out.Timeline = append(out.Timeline, *t) }
	sort.Slice(out.Timeline, func(i, j int) bool { return out.Timeline[i].Bucket.Before(out.Timeline[j].Bucket) })

	// Live PIDs via /proc walk.
	out.LivePIDs = procWalkByBinary(binary)
	if s.procAnc != nil {
		for i := range out.LivePIDs {
			ans := s.procAnc.Ancestors(out.LivePIDs[i].PID, 5)
			for _, a := range ans {
				out.LivePIDs[i].Ancestors = append(out.LivePIDs[i].Ancestors, ProcessAnc{PID: a.PID, Comm: a.Comm, Exe: a.Exe})
			}
		}
	}

	// Historical PIDs from recent ring.
	if rec := s.egress.QueryRecent(start, nil, binary, 4096); len(rec) > 0 {
		type pidAgg struct {
			h     *HistoricalPID
			dests map[string]struct{}
		}
		byPID := map[uint32]*pidAgg{}
		for _, e := range rec {
			ag := byPID[e.PID]
			if ag == nil {
				ag = &pidAgg{h: &HistoricalPID{PID: e.PID, PPID: e.PPID, Comm: e.Comm, Binary: e.Binary, UID: e.UID, FirstSeen: e.Time, LastSeen: e.Time, ContainerID: e.ContainerID, ContainerClass: e.ContainerClass, Unit: e.Unit, Container: containerCell(e.ContainerClass, e.ContainerID)}, dests: map[string]struct{}{}}
				byPID[e.PID] = ag
			}
			if e.Time.Before(ag.h.FirstSeen) { ag.h.FirstSeen = e.Time }
			if e.Time.After(ag.h.LastSeen)   { ag.h.LastSeen = e.Time }
			ag.h.BytesOut += e.BytesOut
			ag.h.BytesIn  += e.BytesIn
			ag.dests[e.DestIP+":"+strconv.Itoa(int(e.DestPort))] = struct{}{}
		}
		for pid, ag := range byPID {
			for d := range ag.dests { ag.h.Dests = append(ag.h.Dests, d) }
			if len(ag.h.Dests) > 6 { ag.h.Dests = ag.h.Dests[:6] }
			if _, err := os.Stat("/proc/" + strconv.Itoa(int(pid))); err == nil { ag.h.StillAlive = true }
			if s.proctree != nil && ag.h.ParentComm == "" {
				ag.h.ParentComm = s.proctree.ParentComm(pid)
			}
			out.HistoricalPIDs = append(out.HistoricalPIDs, *ag.h)
		}
		sort.Slice(out.HistoricalPIDs, func(i, j int) bool { return out.HistoricalPIDs[i].BytesOut > out.HistoricalPIDs[j].BytesOut })
		if len(out.HistoricalPIDs) > 30 { out.HistoricalPIDs = out.HistoricalPIDs[:30] }
	}

	// Direction classifier — reuse the country-page heuristic.
	listenSet := map[uint16]bool{}
	for _, e := range out.LivePIDs {
		for _, p := range e.ListenPorts { listenSet[p] = true }
	}
	listens := make([]uint16, 0, len(listenSet))
	for p := range listenSet { listens = append(listens, p) }
	bdr := make([]BinaryDestRow, 0, len(out.TopDests))
	for _, d := range out.TopDests {
		bdr = append(bdr, BinaryDestRow{CIDR: d.CIDR, Port: d.Port, Protocol: d.Protocol, SNI: d.SNI, BytesOut: d.BytesOut, BytesIn: d.BytesIn, Connects: d.Conns})
	}
	out.Direction, out.DirectionNote = classifyDirection(bdr, listens)

	// Related alerts.
	if s.alertSnap != nil {
		cutoff := time.Now().Add(-24 * time.Hour)
		for _, a := range s.alertSnap() {
			if a.Time.Before(cutoff) { continue }
			if a.Binary == binary {
				out.RelatedAlerts = append(out.RelatedAlerts, a)
			}
		}
		sort.Slice(out.RelatedAlerts, func(i, j int) bool { return out.RelatedAlerts[i].Time.After(out.RelatedAlerts[j].Time) })
		if len(out.RelatedAlerts) > 20 { out.RelatedAlerts = out.RelatedAlerts[:20] }
	}

	// Suggested /24 block when all dest IPs collapse to one /24.
	if len(out.TopDests) >= 2 && len(out.TopDests) <= 50 {
		var pfx string
		all := true
		for i, d := range out.TopDests {
			ip := firstHostIP(d.CIDR)
			parts := strings.Split(ip, ".")
			if len(parts) < 4 { all = false; break }
			p24 := parts[0]+"."+parts[1]+"."+parts[2]+".0/24"
			if i == 0 { pfx = p24 } else if pfx != p24 { all = false; break }
		}
		if all && pfx != "" { out.SuggestedBlock = pfx }
	}

	writeJSONEgress(w, out)
}

// ── PID detail ────────────────────────────────────────────────

// PIDDetail is the payload for /api/egress/pid?pid=N.
type PIDDetail struct {
	PID            uint32          `json:"pid"`
	Found          bool            `json:"found"`
	Live           bool            `json:"live"`
	Comm           string          `json:"comm,omitempty"`
	Exe            string          `json:"exe,omitempty"`
	Cmdline        string          `json:"cmdline,omitempty"`
	CWD            string          `json:"cwd,omitempty"`
	UID            uint32          `json:"uid"`
	Username       string          `json:"username,omitempty"`
	PPID           uint32          `json:"ppid,omitempty"`
	ParentComm     string          `json:"parent_comm,omitempty"`
	Unit           string          `json:"unit,omitempty"`
	CgroupPath     string          `json:"cgroup_path,omitempty"`
	StartedAt      time.Time       `json:"started_at,omitempty"`
	AgeSeconds     int64           `json:"age_seconds,omitempty"`
	Ancestors      []ProcessAnc    `json:"ancestors,omitempty"`
	OpenSockets    int             `json:"open_sockets,omitempty"`
	ListenPorts    []uint16        `json:"listen_ports,omitempty"`
	LiveDests      []PIDLiveDest   `json:"live_dests,omitempty"`
	HistoricalDests []PIDHistDest  `json:"historical_dests,omitempty"`
	RelatedAlerts  []AlertSummary  `json:"related_alerts,omitempty"`
}

type PIDLiveDest struct {
	DstAddr  string `json:"dst_addr"`
	DstPort  uint16 `json:"dst_port"`
	Country  string `json:"country,omitempty"`
	ASN      string `json:"asn,omitempty"`
	SNI      string `json:"sni,omitempty"`
	State    string `json:"state,omitempty"`
	BytesOut uint64 `json:"bytes_out"`
	BytesIn  uint64 `json:"bytes_in"`
	OpenedAt int64  `json:"opened_at,omitempty"`
}
type PIDHistDest struct {
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
	Country   string    `json:"country,omitempty"`
	BytesOut  uint64    `json:"bytes_out"`
	BytesIn   uint64    `json:"bytes_in"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

func (s *Server) handleEgressPID(w http.ResponseWriter, r *http.Request) {
	pidStr := r.URL.Query().Get("pid")
	if pidStr == "" { http.Error(w, "pid required", http.StatusBadRequest); return }
	pid64, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil { http.Error(w, "bad pid", http.StatusBadRequest); return }
	pid := uint32(pid64)
	out := PIDDetail{PID: pid}

	// /proc walk if alive.
	if _, err := os.Stat("/proc/" + pidStr); err == nil {
		out.Live = true
		out.Found = true
		// reuse procWalkByBinary's per-entry enrich by calling its internals directly.
		// We don't know the comm yet, so read it.
		comm := strings.TrimSpace(readSmall("/proc/" + pidStr + "/comm"))
		exe, _ := os.Readlink("/proc/" + pidStr + "/exe")
		e := ProcessEntry{PID: pid, Comm: comm, Exe: exe}
		if cl := readSmall("/proc/" + pidStr + "/cmdline"); cl != "" {
			e.Cmdline = strings.ReplaceAll(strings.TrimRight(cl, "\x00"), "\x00", " ")
		}
		if cwd, err := os.Readlink("/proc/" + pidStr + "/cwd"); err == nil { e.CWD = cwd }
		readStatus(pidStr, &e)
		if cg := readSmall("/proc/" + pidStr + "/cgroup"); cg != "" {
			e.CgroupPath = strings.TrimSpace(cg)
			e.Unit = parseSystemdUnit(e.CgroupPath)
		}
		e.StartedAt = readStartTime(pidStr)
		if !e.StartedAt.IsZero() { e.AgeSeconds = int64(time.Since(e.StartedAt).Seconds()) }
		e.OpenSockets, e.ListenPorts = countSocketsAndListens(pidStr)
		if names := loadUIDNames(); names != nil {
			if u, ok := names[e.UID]; ok { e.Username = u }
		}
		out.Comm = e.Comm; out.Exe = e.Exe; out.Cmdline = e.Cmdline; out.CWD = e.CWD
		out.UID = e.UID; out.Username = e.Username; out.PPID = e.PPID; out.Unit = e.Unit
		out.CgroupPath = e.CgroupPath; out.StartedAt = e.StartedAt; out.AgeSeconds = e.AgeSeconds
		out.OpenSockets = e.OpenSockets; out.ListenPorts = e.ListenPorts
	}

	// Ancestor chain from proctree (works even for exited PIDs in some cases).
	if s.procAnc != nil {
		for _, a := range s.procAnc.Ancestors(pid, 8) {
			out.Ancestors = append(out.Ancestors, ProcessAnc{PID: a.PID, Comm: a.Comm, Exe: a.Exe})
		}
		if out.ParentComm == "" && len(out.Ancestors) > 0 {
			out.ParentComm = out.Ancestors[0].Comm
		}
	} else if s.proctree != nil {
		out.ParentComm = s.proctree.ParentComm(pid)
	}

	// Live destinations via connstate.
	if s.connstateSnap != nil {
		for _, c := range s.connstateSnap() {
			if c.PID != pid { continue }
			cc := ""
			asn := ""
			if s.geoip != nil { cc, asn, _, _ = s.geoip.Lookup(c.DstAddr) }
			out.LiveDests = append(out.LiveDests, PIDLiveDest{
				DstAddr: c.DstAddr, DstPort: c.DstPort,
				Country: cc, ASN: asn, SNI: c.SNI, State: c.State,
				BytesOut: c.BytesOut, BytesIn: c.BytesIn, OpenedAt: c.OpenedAt,
			})
		}
		sort.Slice(out.LiveDests, func(i, j int) bool { return out.LiveDests[i].BytesOut > out.LiveDests[j].BytesOut })
	}

	// Historical destinations via recent ring (filter by PID).
	if s.egress != nil {
		recent := s.egress.QueryRecent(time.Now().Add(-24*time.Hour), nil, "", 8192)
		type key struct{ ip string; port uint16 }
		agg := map[key]*PIDHistDest{}
		for _, e := range recent {
			if e.PID != pid { continue }
			out.Found = true
			if out.Comm == "" { out.Comm = e.Comm }
			k := key{e.DestIP, e.DestPort}
			d := agg[k]
			if d == nil {
				cc := ""
				if s.geoip != nil { cc, _, _, _ = s.geoip.Lookup(e.DestIP) }
				d = &PIDHistDest{DstIP: e.DestIP, DstPort: e.DestPort, Country: cc, FirstSeen: e.Time, LastSeen: e.Time}
				agg[k] = d
			}
			d.BytesOut += e.BytesOut
			d.BytesIn  += e.BytesIn
			if e.Time.Before(d.FirstSeen) { d.FirstSeen = e.Time }
			if e.Time.After(d.LastSeen)   { d.LastSeen = e.Time }
		}
		for _, d := range agg { out.HistoricalDests = append(out.HistoricalDests, *d) }
		sort.Slice(out.HistoricalDests, func(i, j int) bool { return out.HistoricalDests[i].BytesOut > out.HistoricalDests[j].BytesOut })
		if len(out.HistoricalDests) > 50 { out.HistoricalDests = out.HistoricalDests[:50] }
	}

	// Related alerts (match by PID).
	if s.alertSnap != nil {
		cutoff := time.Now().Add(-24 * time.Hour)
		for _, a := range s.alertSnap() {
			if a.Time.Before(cutoff) { continue }
			if a.PID == pid {
				out.RelatedAlerts = append(out.RelatedAlerts, a)
				out.Found = true
			}
		}
	}

	writeJSONEgress(w, out)
}

// ── Global verdict / posture ─────────────────────────────────

// VerdictResp is the payload for /api/egress/verdict — one-glance
// health summary of the host's network posture.
type VerdictResp struct {
	HealthScore       int                    `json:"health_score"`      // 0-100, 100 = clean
	Verdict           string                 `json:"verdict"`            // "good" | "watch" | "concerning" | "critical"
	Notes             []string               `json:"notes,omitempty"`
	TotalApps         int                    `json:"total_apps"`
	ActiveApps        int                    `json:"active_apps"`
	BytesOut1h        uint64                 `json:"bytes_out_1h"`
	BytesIn1h         uint64                 `json:"bytes_in_1h"`
	BytesOut24h       uint64                 `json:"bytes_out_24h"`
	BytesIn24h        uint64                 `json:"bytes_in_24h"`
	InboundReplyPct   float64                `json:"inbound_reply_pct"`
	OutboundPct       float64                `json:"outbound_pct"`
	UnknownDirPct     float64                `json:"unknown_dir_pct"`
	DistinctCountries int                    `json:"distinct_countries"`
	TopCountriesPct   []VerdictCountryShare  `json:"top_countries_pct"`
	BlockedCount24h   uint64                 `json:"blocked_count_24h"`
	OpenAlertsCount   int                    `json:"open_alerts_count"`
	AlertsByClass     map[int]int            `json:"alerts_by_class,omitempty"`
	TopRiskApps       []VerdictRiskApp       `json:"top_risk_apps,omitempty"`
}

type VerdictCountryShare struct {
	Country string  `json:"country"`
	Pct     float64 `json:"pct"`
	Bytes   uint64  `json:"bytes"`
}
type VerdictRiskApp struct {
	Binary   string `json:"binary"`
	Reason   string `json:"reason"`
	Bytes    uint64 `json:"bytes"`
	Alerts   int    `json:"alerts"`
	Blocked  uint64 `json:"blocked"`
}

func (s *Server) handleEgressVerdict(w http.ResponseWriter, r *http.Request) {
	if s.egress == nil { writeJSONEgress(w, VerdictResp{}); return }
	resp := VerdictResp{AlertsByClass: map[int]int{}}

	// Live (1h) for app counts + direction breakdown.
	live := s.egress.QueryLive(egressledger.FlowFilter{UID:-1, CGroupID:-1, DestPort:-1, Visibility:"public"})
	bins := map[string]struct{}{}
	var serverBytes, clientBytes, unknownBytes uint64
	for _, r := range live {
		bins[r.Key.Binary] = struct{}{}
		resp.BytesOut1h += r.Metrics.BytesOut
		resp.BytesIn1h  += r.Metrics.BytesIn
		switch r.Key.Role {
		case "server": serverBytes += r.Metrics.BytesOut
		case "client": clientBytes += r.Metrics.BytesOut
		default:       unknownBytes += r.Metrics.BytesOut
		}
	}
	resp.TotalApps = len(bins)
	total := serverBytes + clientBytes + unknownBytes
	if total > 0 {
		resp.InboundReplyPct = float64(serverBytes) / float64(total) * 100
		resp.OutboundPct     = float64(clientBytes) / float64(total) * 100
		resp.UnknownDirPct   = float64(unknownBytes) / float64(total) * 100
	}

	// Active app count from connstate.
	if s.connstateSnap != nil {
		activeBins := map[string]struct{}{}
		for _, c := range s.connstateSnap() {
			if c.Comm != "" { activeBins[c.Comm] = struct{}{} }
		}
		resp.ActiveApps = len(activeBins)
	}

	// 24h totals + countries + blocked.
	end := time.Now()
	start24 := end.Add(-24 * time.Hour)
	tl := s.egress.QueryTimeline(start24, end, egressledger.FlowFilter{UID:-1, CGroupID:-1, DestPort:-1, Visibility:"public"})
	ctryBytes := map[string]uint64{}
	binBytes  := map[string]uint64{}
	binBlocked := map[string]uint64{}
	for _, r := range tl {
		resp.BytesOut24h += r.Metrics.BytesOut
		resp.BytesIn24h  += r.Metrics.BytesIn
		resp.BlockedCount24h += r.Metrics.DenyEvents
		binBytes[r.Key.Binary] += r.Metrics.BytesOut
		binBlocked[r.Key.Binary] += r.Metrics.DenyEvents
		if s.geoip != nil {
			cc, _, _, _ := s.geoip.Lookup(firstHostIP(r.Key.DestCIDR))
			if cc != "" { ctryBytes[cc] += r.Metrics.BytesOut }
		}
	}
	resp.DistinctCountries = len(ctryBytes)
	totalC := uint64(0)
	for _, b := range ctryBytes { totalC += b }
	type cb struct { cc string; b uint64 }
	var ctries []cb
	for c, b := range ctryBytes { ctries = append(ctries, cb{c, b}) }
	sort.Slice(ctries, func(i, j int) bool { return ctries[i].b > ctries[j].b })
	for i, c := range ctries {
		if i >= 5 { break }
		pct := 0.0
		if totalC > 0 { pct = float64(c.b) / float64(totalC) * 100 }
		resp.TopCountriesPct = append(resp.TopCountriesPct, VerdictCountryShare{Country: c.cc, Bytes: c.b, Pct: pct})
	}

	// Alert breakdown.
	binAlerts := map[string]int{}
	if s.alertSnap != nil {
		cutoff := time.Now().Add(-24 * time.Hour)
		for _, a := range s.alertSnap() {
			if a.Time.Before(cutoff) { continue }
			resp.OpenAlertsCount++
			resp.AlertsByClass[a.Class]++
			if a.Binary != "" { binAlerts[a.Binary]++ }
		}
	}

	// Top risk apps: rank by (alerts * 30 + blocked * 5 + bytes/1MB).
	type risk struct { bin string; score float64; bytes uint64; alerts int; blocked uint64 }
	var risks []risk
	for b, by := range binBytes {
		score := float64(by) / float64(1024*1024)
		alerts := binAlerts[b]
		score += float64(alerts) * 30
		blocked := binBlocked[b]
		score += float64(blocked) * 5
		if alerts == 0 && blocked == 0 && by < 5*1024*1024 { continue }
		risks = append(risks, risk{b, score, by, alerts, blocked})
	}
	sort.Slice(risks, func(i, j int) bool { return risks[i].score > risks[j].score })
	for i, r := range risks {
		if i >= 5 { break }
		reason := ""
		if r.alerts > 0  { reason = strconv.Itoa(r.alerts) + " alerts" }
		if r.blocked > 0 { if reason != "" { reason += ", " }; reason += strconv.FormatUint(r.blocked, 10) + " blocked" }
		if reason == ""  { reason = "high volume" }
		resp.TopRiskApps = append(resp.TopRiskApps, VerdictRiskApp{Binary: r.bin, Reason: reason, Bytes: r.bytes, Alerts: r.alerts, Blocked: r.blocked})
	}

	// Compute health score.
	score := 100
	notes := []string{}
	if resp.OpenAlertsCount > 0 {
		score -= 10 * resp.AlertsByClass[1] // hard invariant
		score -= 5  * resp.AlertsByClass[2]
		score -= 2  * resp.AlertsByClass[3]
		notes = append(notes, strconv.Itoa(resp.OpenAlertsCount)+" active alerts in last 24h")
	}
	if resp.BlockedCount24h > 0 {
		score -= int(resp.BlockedCount24h / 10)
		notes = append(notes, strconv.FormatUint(resp.BlockedCount24h, 10)+" blocked attempts 24h")
	}
	if resp.UnknownDirPct > 30 {
		score -= 5
		notes = append(notes, "many flows unclassified (server/client unknown)")
	}
	if len(resp.TopCountriesPct) > 0 && resp.TopCountriesPct[0].Pct > 70 {
		notes = append(notes, "traffic heavily concentrated in "+resp.TopCountriesPct[0].Country+" ("+strconv.FormatFloat(resp.TopCountriesPct[0].Pct, 'f', 0, 64)+"%)")
	}
	if score < 0 { score = 0 }
	resp.HealthScore = score
	switch {
	case score >= 85: resp.Verdict = "good"
	case score >= 60: resp.Verdict = "watch"
	case score >= 30: resp.Verdict = "concerning"
	default:          resp.Verdict = "critical"
	}
	if len(notes) == 0 { notes = append(notes, "no anomalies detected") }
	resp.Notes = notes

	writeJSONEgress(w, resp)
}
