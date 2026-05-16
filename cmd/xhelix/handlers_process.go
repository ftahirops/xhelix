package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/verdict"
)

// processesList aggregates connstate by pid and returns one row per
// process with totals + top destinations + anomaly heuristic + the
// worst-action verdict the engine assigned to any of its flows.
func processesList(tab *connstate.Table, vctx *verdictCtx, ph *procHistory) (any, error) {
	if tab == nil {
		return map[string]any{"processes": []any{}}, nil
	}
	snap := tab.Snapshot()

	type acc struct {
		pid       uint32
		ppid      uint32
		comm      string
		exe       string
		exeSHA    string
		unit      string
		userID    string
		class     uint8
		live      int
		closed    int
		bytesIn   uint64
		bytesOut  uint64
		firstSeen time.Time
		lastSeen  time.Time
		dsts      map[string]int    // host:port -> count
		ports     map[uint16]int    // port -> count
		dnsNames  map[string]int    // dns qname -> count
		// Worst verdict observed for this pid's flows. "Worst" = deny
		// > prompt > allow; ties broken by higher confidence.
		worstAction     string
		worstConfidence int
		worstLayer      string
		worstNote       string
		// Counts of each verdict action across this pid's flows.
		actCount map[string]int
	}
	byPID := map[uint32]*acc{}
	for _, c := range snap {
		a, ok := byPID[c.PID]
		if !ok {
			a = &acc{
				pid: c.PID, ppid: c.PPID, comm: c.Comm,
				exe: c.Exe, exeSHA: c.ExeSHA,
				unit: c.Unit, userID: c.UserID, class: uint8(c.CGroupClass),
				firstSeen: c.OpenedAt, lastSeen: c.OpenedAt,
				dsts: map[string]int{}, ports: map[uint16]int{}, dnsNames: map[string]int{},
				actCount: map[string]int{},
			}
			byPID[c.PID] = a
		}
		if c.OpenedAt.Before(a.firstSeen) {
			a.firstSeen = c.OpenedAt
		}
		if c.OpenedAt.After(a.lastSeen) {
			a.lastSeen = c.OpenedAt
		}
		a.bytesIn += c.BytesIn
		a.bytesOut += c.BytesOut
		switch c.State {
		case connstate.StateClosed, connstate.StateReset, connstate.StateTimeout:
			a.closed++
		default:
			a.live++
		}
		dst := c.Tuple.DstAddr.String()
		if dst != "" {
			key := fmt.Sprintf("%s:%d", dst, c.Tuple.DstPort)
			a.dsts[key]++
		}
		if c.Tuple.DstPort != 0 {
			a.ports[c.Tuple.DstPort]++
		}
		if c.DNSName != "" {
			a.dnsNames[c.DNSName]++
		}

		// Verdict tagging — cheap (cached). Record per-flow action
		// and bubble the "worst" up to the row for the UI badge.
		if vctx != nil {
			v := vctx.decideForConn(c)
			a.actCount[string(v.Action)]++
			if isWorseAction(string(v.Action), a.worstAction) ||
				(string(v.Action) == a.worstAction && int(v.Confidence) > a.worstConfidence) {
				a.worstAction = string(v.Action)
				a.worstConfidence = int(v.Confidence)
				a.worstLayer = v.Layer
				if len(v.Reasons) > 0 {
					a.worstNote = v.Reasons[len(v.Reasons)-1].Note
				}
			}
		}
	}

	out := make([]map[string]any, 0, len(byPID))
	for _, a := range byPID {
		// Pull live /proc info — cheap, gives us cmdline + alive flag.
		cmdline := readProcLine(a.pid, "cmdline")
		alive := pidExists(a.pid)
		state := readProcState(a.pid)
		group := classifyProcess(a.exe, a.comm, a.unit)
		var rate5s uint64
		if ph != nil {
			rate5s = ph.RecentRate(a.pid, 30*time.Second)
		}

		topDsts := topN(a.dsts, 5)
		topPorts := topPortsN(a.ports, 5)
		topDNS := topN(a.dnsNames, 3)

		// Anomaly heuristic — cheap deterministic flags. The real
		// verdict engine (Phase F2) will replace this.
		flags := anomalyFlags(len(a.dsts), a.live+a.closed, len(a.dnsNames), a.ports)

		out = append(out, map[string]any{
			"pid":                a.pid,
			"ppid":               a.ppid,
			"comm":               a.comm,
			"exe":                a.exe,
			"exe_sha":            a.exeSHA,
			"cmdline":            cmdline,
			"unit":               a.unit,
			"user":               a.userID,
			"class":              a.class,
			"group":              group,
			"state":              state,
			"alive":              alive,
			"rate_30s_bytes":     rate5s,
			"live_flows":         a.live,
			"closed_flows":       a.closed,
			"total_flows":        a.live + a.closed,
			"bytes_in":           a.bytesIn,
			"bytes_out":          a.bytesOut,
			"first_seen":         a.firstSeen.Format(time.RFC3339),
			"last_seen":          a.lastSeen.Format(time.RFC3339),
			"top_dsts":           topDsts,
			"top_ports":          topPorts,
			"top_dns":            topDNS,
			"anomaly":            len(flags) > 0,
			"flags":              flags,
			"verdict_action":     a.worstAction,
			"verdict_layer":      a.worstLayer,
			"verdict_note":       a.worstNote,
			"verdict_confidence": a.worstConfidence,
			"verdict_counts":     a.actCount,
		})
	}
	// Sort: alive first, then by total flows desc.
	sort.Slice(out, func(i, j int) bool {
		ai := out[i]["alive"].(bool)
		aj := out[j]["alive"].(bool)
		if ai != aj {
			return ai
		}
		return out[i]["total_flows"].(int) > out[j]["total_flows"].(int)
	})
	return map[string]any{"processes": out, "count": len(out)}, nil
}

// processDetail returns deep info for one pid: flows + tree + proc + DNS.
func processDetail(tab *connstate.Table, vctx *verdictCtx, ph *procHistory, raw json.RawMessage) (any, error) {
	var req struct {
		PID uint32 `json:"pid"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if req.PID == 0 {
		return nil, fmt.Errorf("pid required")
	}

	flows := []map[string]any{}
	if tab != nil {
		for _, c := range tab.SnapshotByPID(req.PID) {
			row := map[string]any{
				"src_port":  c.Tuple.SrcPort,
				"dst_ip":    c.Tuple.DstAddr.String(),
				"dst_port":  c.Tuple.DstPort,
				"proto":     c.Tuple.Proto.String(),
				"state":     c.State.String(),
				"bytes_in":  c.BytesIn,
				"bytes_out": c.BytesOut,
				"dns_name":  c.DNSName,
				"sni":       c.SNI,
				"opened_at": c.OpenedAt.Format(time.RFC3339),
				"closed_at": c.ClosedAt.Format(time.RFC3339),
			}
			if vctx != nil {
				v := vctx.decideForConn(c)
				row["verdict_action"] = string(v.Action)
				row["verdict_layer"] = v.Layer
				row["verdict_confidence"] = int(v.Confidence)
				row["verdict_reasons"] = v.Reasons
			}
			flows = append(flows, row)
		}
	}

	tree := procTree(req.PID)
	openSockets := readOpenSockets(req.PID)
	limits := readProcLimits(req.PID)
	status := readProcStatus(req.PID)

	var history []map[string]any
	if ph != nil {
		for _, s := range ph.Snapshot(req.PID) {
			history = append(history, map[string]any{
				"t":          s.At.Format(time.RFC3339),
				"bytes_in":   s.BytesIn,
				"bytes_out":  s.BytesOut,
				"io_read":    s.IORead,
				"io_write":   s.IOWrite,
				"live_flows": s.LiveFlows,
			})
		}
	}

	return map[string]any{
		"pid":          req.PID,
		"alive":        pidExists(req.PID),
		"state":        readProcState(req.PID),
		"group":        classifyProcess(readProcSymlink(req.PID, "exe"), "", ""),
		"cmdline":      readProcLine(req.PID, "cmdline"),
		"exe":          readProcSymlink(req.PID, "exe"),
		"cwd":          readProcSymlink(req.PID, "cwd"),
		"status":       status,
		"tree":         tree,
		"flows":        flows,
		"open_sockets": openSockets,
		"limits":       limits,
		"history":      history,
		"as_of":        time.Now().Format(time.RFC3339),
	}, nil
}

// --- helpers ---

func topN(m map[string]int, n int) []map[string]any {
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	if len(list) > n {
		list = list[:n]
	}
	out := make([]map[string]any, len(list))
	for i, e := range list {
		out[i] = map[string]any{"key": e.k, "count": e.v}
	}
	return out
}

func topPortsN(m map[uint16]int, n int) []map[string]any {
	type kv struct {
		k uint16
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	if len(list) > n {
		list = list[:n]
	}
	out := make([]map[string]any, len(list))
	for i, e := range list {
		out[i] = map[string]any{"port": e.k, "count": e.v}
	}
	return out
}

func pidExists(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

func readProcLine(pid uint32, name string) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return ""
	}
	// /proc/PID/cmdline uses NUL separators; normalise to spaces.
	s := strings.ReplaceAll(strings.TrimRight(string(b), "\x00\n"), "\x00", " ")
	if len(s) > 512 {
		s = s[:512] + "…"
	}
	return s
}

func readProcSymlink(pid uint32, name string) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/%s", pid, name))
	if err != nil {
		return ""
	}
	return link
}

type procStatus struct {
	UID      string `json:"uid"`
	GID      string `json:"gid"`
	State    string `json:"state"`
	RSSKB    uint64 `json:"rss_kb"`
	Threads  int    `json:"threads"`
	CapEff   string `json:"cap_eff"`
}

func readProcStatus(pid uint32) procStatus {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return procStatus{}
	}
	var s procStatus
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Uid":
			s.UID = firstField(v)
		case "Gid":
			s.GID = firstField(v)
		case "State":
			s.State = v
		case "VmRSS":
			s.RSSKB = parseKB(v)
		case "Threads":
			s.Threads, _ = strconv.Atoi(firstField(v))
		case "CapEff":
			s.CapEff = firstField(v)
		}
	}
	return s
}

func firstField(s string) string {
	for _, f := range strings.Fields(s) {
		return f
	}
	return ""
}

func parseKB(v string) uint64 {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseUint(fields[0], 10, 64)
	return n
}

type treeNode struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe"`
}

// procTree walks /proc/PID/status PPid: lines back to PID 1.
func procTree(pid uint32) []treeNode {
	tree := []treeNode{}
	cur := pid
	for depth := 0; depth < 20 && cur > 0; depth++ {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", cur))
		if err != nil {
			break
		}
		var comm string
		var ppid uint32
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "Name:") {
				comm = strings.TrimSpace(line[5:])
			} else if strings.HasPrefix(line, "PPid:") {
				v := strings.TrimSpace(line[5:])
				n, _ := strconv.ParseUint(v, 10, 32)
				ppid = uint32(n)
			}
		}
		exe := readProcSymlink(cur, "exe")
		tree = append(tree, treeNode{PID: cur, PPID: ppid, Comm: comm, Exe: exe})
		if cur == 1 || ppid == 0 || ppid == cur {
			break
		}
		cur = ppid
	}
	return tree
}

type openSocket struct {
	Proto    string `json:"proto"`
	LocalIP  string `json:"local_ip"`
	LocalPort uint16 `json:"local_port"`
	RemoteIP  string `json:"remote_ip"`
	RemotePort uint16 `json:"remote_port"`
	State    string `json:"state"`
}

// readOpenSockets parses /proc/PID/net/{tcp,tcp6,udp,udp6} for the
// process's sockets. Returns a deduped list.
func readOpenSockets(pid uint32) []openSocket {
	out := []openSocket{}
	for _, fn := range []struct{ proto, path string }{
		{"tcp", "tcp"}, {"tcp", "tcp6"},
		{"udp", "udp"}, {"udp", "udp6"},
	} {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, fn.path))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			s, ok := parseProcNetLine(line, fn.proto, fn.path == "tcp6" || fn.path == "udp6")
			if !ok {
				continue
			}
			out = append(out, s)
			if len(out) >= 200 {
				return out
			}
		}
	}
	return out
}

func parseProcNetLine(line, proto string, v6 bool) (openSocket, bool) {
	f := strings.Fields(line)
	if len(f) < 4 {
		return openSocket{}, false
	}
	lip, lport, ok1 := parseProcAddr(f[1], v6)
	rip, rport, ok2 := parseProcAddr(f[2], v6)
	if !ok1 || !ok2 {
		return openSocket{}, false
	}
	state := tcpStateName(f[3])
	if proto == "udp" {
		state = ""
	}
	return openSocket{
		Proto: proto, LocalIP: lip, LocalPort: lport,
		RemoteIP: rip, RemotePort: rport, State: state,
	}, true
}

func parseProcAddr(s string, v6 bool) (string, uint16, bool) {
	addr, port, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return "", 0, false
	}
	if v6 {
		// 32 hex chars, little-endian per 32-bit word
		if len(addr) != 32 {
			return "", 0, false
		}
		var b [16]byte
		for i := 0; i < 4; i++ {
			word := addr[i*8 : i*8+8]
			// reverse byte order within the 4-byte word
			for j := 0; j < 4; j++ {
				hex := word[(3-j)*2 : (3-j)*2+2]
				n, err := strconv.ParseUint(hex, 16, 8)
				if err != nil {
					return "", 0, false
				}
				b[i*4+j] = byte(n)
			}
		}
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
			uint16(b[0])<<8|uint16(b[1]),
			uint16(b[2])<<8|uint16(b[3]),
			uint16(b[4])<<8|uint16(b[5]),
			uint16(b[6])<<8|uint16(b[7]),
			uint16(b[8])<<8|uint16(b[9]),
			uint16(b[10])<<8|uint16(b[11]),
			uint16(b[12])<<8|uint16(b[13]),
			uint16(b[14])<<8|uint16(b[15])), uint16(p), true
	}
	// IPv4: 8 hex chars little-endian
	if len(addr) != 8 {
		return "", 0, false
	}
	var bs [4]byte
	for i := 0; i < 4; i++ {
		n, err := strconv.ParseUint(addr[(3-i)*2:(3-i)*2+2], 16, 8)
		if err != nil {
			return "", 0, false
		}
		bs[i] = byte(n)
	}
	return fmt.Sprintf("%d.%d.%d.%d", bs[0], bs[1], bs[2], bs[3]), uint16(p), true
}

func tcpStateName(hex string) string {
	n, err := strconv.ParseUint(hex, 16, 8)
	if err != nil {
		return hex
	}
	switch n {
	case 0x01:
		return "ESTABLISHED"
	case 0x02:
		return "SYN_SENT"
	case 0x03:
		return "SYN_RECV"
	case 0x04:
		return "FIN_WAIT1"
	case 0x05:
		return "FIN_WAIT2"
	case 0x06:
		return "TIME_WAIT"
	case 0x07:
		return "CLOSE"
	case 0x08:
		return "CLOSE_WAIT"
	case 0x09:
		return "LAST_ACK"
	case 0x0A:
		return "LISTEN"
	case 0x0B:
		return "CLOSING"
	}
	return fmt.Sprintf("0x%x", n)
}

// readProcLimits returns a small subset of /proc/PID/limits.
func readProcLimits(pid uint32) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "Max open files"):
			out["max_open_files"] = strings.TrimSpace(line[len("Max open files"):])
		case strings.HasPrefix(line, "Max processes"):
			out["max_processes"] = strings.TrimSpace(line[len("Max processes"):])
		}
	}
	return out
}

// anomalyFlags returns short reason strings for cheap heuristics.
// Placeholder until pkg/verdict lands.
func anomalyFlags(numDsts, totalFlows, numDNS int, ports map[uint16]int) []string {
	var flags []string
	if numDsts > 100 {
		flags = append(flags, fmt.Sprintf("high-fanout=%d_dests", numDsts))
	}
	suspicious := map[uint16]bool{4444: true, 6666: true, 31337: true, 1337: true, 9001: true}
	for p := range ports {
		if suspicious[p] {
			flags = append(flags, fmt.Sprintf("known-bad-port=%d", p))
		}
	}
	if totalFlows > 20 && numDNS == 0 {
		flags = append(flags, "no-dns-hint")
	}
	return flags
}

// isWorseAction returns true if a is more severe than b, ordered
// deny > prompt > allow > "" (empty).
func isWorseAction(a, b string) bool {
	rank := map[string]int{"": 0, "allow": 1, "prompt": 2, "deny": 3}
	return rank[a] > rank[b]
}

// verdictExplain answers "what would the engine decide for this
// (exe, dst, port, sni) tuple?" — for the UI's "would this be
// blocked?" view.
func verdictExplain(vctx *verdictCtx, raw json.RawMessage) (any, error) {
	if vctx == nil {
		return nil, fmt.Errorf("verdict engine unavailable")
	}
	var req struct {
		PID     uint32 `json:"pid"`
		Exe     string `json:"exe"`
		ExeSHA  string `json:"exe_sha"`
		Comm    string `json:"comm"`
		DstIP   string `json:"dst_ip"`
		DstPort uint16 `json:"dst_port"`
		DNSName string `json:"dns_name"`
		SNI     string `json:"sni"`
		Country string `json:"country"`
		ASN     uint32 `json:"asn"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	v := vctx.engine.Decide(verdict.Conn{
		PID: req.PID, Comm: req.Comm,
		Exe: req.Exe, ExeSHA: req.ExeSHA,
		DstIP: req.DstIP, DstPort: req.DstPort,
		DNSName: req.DNSName, SNI: req.SNI,
		Country: req.Country, ASN: req.ASN,
	})
	return map[string]any{
		"action":     string(v.Action),
		"confidence": int(v.Confidence),
		"layer":      v.Layer,
		"reasons":    v.Reasons,
		"as_of":      v.AnalysedAt.Format(time.RFC3339),
	}, nil
}

// processInvestigate runs bounded strace + read /proc info for one pid.
// Caller must have CAP_SYS_PTRACE (xhelix has it).
func processInvestigate(ctx context.Context, raw json.RawMessage) (any, error) {
	var req struct {
		PID     uint32 `json:"pid"`
		Seconds int    `json:"seconds"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	if req.PID == 0 {
		return nil, fmt.Errorf("pid required")
	}
	if req.Seconds <= 0 || req.Seconds > 30 {
		req.Seconds = 5
	}
	if !pidExists(req.PID) {
		return nil, fmt.Errorf("pid %d not alive", req.PID)
	}
	// Run strace for the bounded interval. We trace network + file
	// syscalls; that's plenty for triage without overwhelming the
	// daemon. Output is captured line-by-line.
	lines, err := runStrace(ctx, req.PID, time.Duration(req.Seconds)*time.Second)
	if err != nil {
		return map[string]any{
			"pid":     req.PID,
			"seconds": req.Seconds,
			"error":   err.Error(),
		}, nil
	}
	return map[string]any{
		"pid":          req.PID,
		"seconds":      req.Seconds,
		"syscall_count": len(lines),
		"syscalls":     lines,
		"as_of":        time.Now().Format(time.RFC3339),
	}, nil
}
