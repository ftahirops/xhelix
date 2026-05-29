// Process inventory helpers for the country drilldown.
//
// The egress ledger stores aggregated (binary, UID, cgroup) flow rows
// — it does NOT carry PIDs. To answer "which python is sending to
// HK, who spawned it, when, why?" we walk /proc directly and join with
// the live connstate snapshot and the in-memory proctree.
//
// Output is the deep-dive payload rendered by the Country detail page.
package web

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProcessInventory is the per-binary deep dive: one entry per
// currently-running PID whose comm/exe matches the binary name.
type ProcessInventory struct {
	Binary    string         `json:"binary"`
	PIDs      []ProcessEntry `json:"pids"`
	Direction string         `json:"direction"`            // "outbound" | "inbound_reply" | "mixed" | "unknown"
	DirNote   string         `json:"direction_note"`       // human-readable why
}

// ProcessEntry describes one live PID.
type ProcessEntry struct {
	PID         uint32       `json:"pid"`
	PPID        uint32       `json:"ppid"`
	Comm        string       `json:"comm"`
	Exe         string       `json:"exe,omitempty"`
	Cmdline     string       `json:"cmdline,omitempty"`
	CWD         string       `json:"cwd,omitempty"`
	UID         uint32       `json:"uid"`
	Username    string       `json:"username,omitempty"`
	Unit        string       `json:"unit,omitempty"`
	CgroupPath  string       `json:"cgroup_path,omitempty"`
	StartedAt   time.Time    `json:"started_at"`
	AgeSeconds  int64        `json:"age_seconds"`
	OpenSockets int          `json:"open_sockets"`
	ListenPorts []uint16     `json:"listen_ports,omitempty"`
	Ancestors   []ProcessAnc `json:"ancestors,omitempty"`
	// Country-scoped: dst IPs in the current country this PID is talking to.
	CountryDests []string `json:"country_dests,omitempty"`
}

// ProcessAnc is one ancestor entry (parent → grandparent → …).
type ProcessAnc struct {
	PID  uint32 `json:"pid"`
	Comm string `json:"comm"`
	Exe  string `json:"exe,omitempty"`
}

// ProcAncestry is the interface the daemon implements via proctree.
// Returns parent chain newest-first, up to depth.
type ProcAncestry interface {
	Ancestors(pid uint32, depth int) []AncestorNode
}

// AncestorNode is what ProcAncestry returns. Mirrors the model
// projection we want without pulling in pkg/model.
type AncestorNode struct {
	PID  uint32
	Comm string
	Exe  string
}

// SetProcAncestry wires the proctree ancestry provider (separate from
// ProcTreeLookup which only gives ParentComm).
func (s *Server) SetProcAncestry(p ProcAncestry) { s.procAnc = p }

// procWalkByBinary returns all live PIDs whose comm or basename(exe)
// matches binaryName. Bounded by /proc availability — Linux-only.
//
// We accept either the comm (typically 15-char truncated) or the
// basename of /proc/<pid>/exe.
func procWalkByBinary(binaryName string) []ProcessEntry {
	if binaryName == "" {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	want := binaryName
	if i := strings.LastIndexByte(want, '/'); i >= 0 {
		want = want[i+1:]
	}
	wantTrunc := want
	if len(wantTrunc) > 15 {
		wantTrunc = wantTrunc[:15] // kernel comm truncation
	}
	out := []ProcessEntry{}
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		name := de.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid64, err := strconv.ParseUint(name, 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		comm := strings.TrimSpace(readSmall("/proc/" + name + "/comm"))
		exe, _ := os.Readlink("/proc/" + name + "/exe")
		exeBase := exe
		if i := strings.LastIndexByte(exeBase, '/'); i >= 0 {
			exeBase = exeBase[i+1:]
		}
		// Match comm (or its truncation) OR the basename of exe.
		if comm != want && comm != wantTrunc && exeBase != want {
			continue
		}
		e := ProcessEntry{
			PID: pid, Comm: comm, Exe: exe,
		}
		// cmdline (null-separated).
		if cl := readSmall("/proc/" + name + "/cmdline"); cl != "" {
			e.Cmdline = strings.ReplaceAll(strings.TrimRight(cl, "\x00"), "\x00", " ")
		}
		// cwd.
		if cwd, err := os.Readlink("/proc/" + name + "/cwd"); err == nil {
			e.CWD = cwd
		}
		// status: PPid, Uid.
		readStatus(name, &e)
		// cgroup → systemd unit.
		if cg := readSmall("/proc/" + name + "/cgroup"); cg != "" {
			e.CgroupPath = strings.TrimSpace(cg)
			e.Unit = parseSystemdUnit(e.CgroupPath)
		}
		// start time from /proc/<pid>/stat.
		e.StartedAt = readStartTime(name)
		if !e.StartedAt.IsZero() {
			e.AgeSeconds = int64(time.Since(e.StartedAt).Seconds())
		}
		// Count open sockets + listening TCP ports from /proc/<pid>/fd
		// + /proc/<pid>/net/tcp. Bounded — bail early on big counts.
		e.OpenSockets, e.ListenPorts = countSocketsAndListens(name)
		// Username from /etc/passwd cache.
		if names := loadUIDNames(); names != nil {
			if u, ok := names[e.UID]; ok {
				e.Username = u
			}
		}
		out = append(out, e)
	}
	return out
}

func readSmall(path string) string {
	const max = 8192
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return string(buf[:n])
}

func readStatus(pidStr string, e *ProcessEntry) {
	body := readSmall("/proc/" + pidStr + "/status")
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "PPid:") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				e.PPID = uint32(n)
			}
		}
		if strings.HasPrefix(line, "Uid:") {
			fs := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fs) > 0 {
				if n, err := strconv.ParseUint(fs[0], 10, 32); err == nil {
					e.UID = uint32(n)
				}
			}
		}
	}
}

// readStartTime parses /proc/<pid>/stat for the 22nd field (starttime
// in clock ticks since boot) and converts to absolute time.
func readStartTime(pidStr string) time.Time {
	body := readSmall("/proc/" + pidStr + "/stat")
	if body == "" {
		return time.Time{}
	}
	// comm field can contain spaces inside parens, so find the closing paren.
	rp := strings.LastIndexByte(body, ')')
	if rp < 0 || rp+2 >= len(body) {
		return time.Time{}
	}
	rest := body[rp+2:]
	fields := strings.Fields(rest)
	// rest[0]=state, ... fields[19] is starttime (22nd overall — 2 already consumed).
	if len(fields) < 20 {
		return time.Time{}
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}
	}
	hz := uint64(100) // USER_HZ — overwhelmingly 100 on Linux.
	sinceBoot := time.Duration(ticks) * time.Second / time.Duration(hz)
	boot := readBootTime()
	if boot.IsZero() {
		return time.Time{}
	}
	return boot.Add(sinceBoot)
}

var bootTimeCache time.Time

func readBootTime() time.Time {
	if !bootTimeCache.IsZero() {
		return bootTimeCache
	}
	body := readSmall("/proc/stat")
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "btime ") {
			v := strings.TrimSpace(strings.TrimPrefix(line, "btime "))
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				bootTimeCache = time.Unix(n, 0)
				return bootTimeCache
			}
		}
	}
	return time.Time{}
}

// parseSystemdUnit extracts the .service / .scope name from a cgroup
// v2 path line like:
//   0::/system.slice/nginx.service
//   0::/user.slice/user-1000.slice/user@1000.service/.../foo.scope
func parseSystemdUnit(cgroup string) string {
	for _, suffix := range []string{".service", ".scope", ".socket", ".target"} {
		if i := strings.LastIndex(cgroup, suffix); i > 0 {
			// Find the segment containing this suffix.
			start := strings.LastIndexByte(cgroup[:i], '/')
			if start < 0 {
				start = 0
			} else {
				start++
			}
			return cgroup[start : i+len(suffix)]
		}
	}
	return ""
}

// countSocketsAndListens enumerates /proc/<pid>/fd for socket inodes
// then reads /proc/<pid>/net/tcp{,6} for listening sockets whose inode
// is in that fd set. /proc/<pid>/net/tcp shows the WHOLE netns table,
// so filtering by the PID's own socket inodes is essential — without
// it every PID in the root netns appears to "listen" on every port.
func countSocketsAndListens(pidStr string) (int, []uint16) {
	fdDir := "/proc/" + pidStr + "/fd"
	entries, err := os.ReadDir(fdDir)
	socks := 0
	ownInodes := map[string]bool{}
	if err == nil {
		for _, e := range entries {
			tgt, err := os.Readlink(filepath.Join(fdDir, e.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(tgt, "socket:[") && strings.HasSuffix(tgt, "]") {
				socks++
				ownInodes[tgt[len("socket:[") : len(tgt)-1]] = true
			}
		}
	}
	listens := []uint16{}
	seen := map[uint16]bool{}
	for _, p := range []string{"/proc/" + pidStr + "/net/tcp", "/proc/" + pidStr + "/net/tcp6"} {
		body := readSmall(p)
		lines := strings.Split(body, "\n")
		for i, line := range lines {
			if i == 0 || len(listens) > 32 {
				continue
			}
			fs := strings.Fields(line)
			if len(fs) < 10 {
				continue
			}
			// fs[1] = local_address HEX_IP:HEX_PORT
			// fs[3] = state; 0A = LISTEN
			// fs[9] = inode
			if fs[3] != "0A" {
				continue
			}
			if !ownInodes[fs[9]] {
				continue
			}
			la := fs[1]
			c := strings.IndexByte(la, ':')
			if c < 0 {
				continue
			}
			pv, err := strconv.ParseUint(la[c+1:], 16, 16)
			if err != nil {
				continue
			}
			pp := uint16(pv)
			if !seen[pp] {
				seen[pp] = true
				listens = append(listens, pp)
			}
		}
	}
	return socks, listens
}

// classifyDirection inspects the per-binary destinations to decide
// whether the bytes attributed to this binary in this country are
// outbound (binary initiates) or inbound replies (binary is the server).
//
// Heuristic:
//   - If most dest ports are ephemeral (>=32768) AND the binary has
//     a listening socket on a well-known service port, → "inbound_reply".
//   - If most dest ports are well-known service ports (443, 80, 53,
//     22, 5432, 6379, 3306, ...), → "outbound".
//   - Mixed → "mixed".
//
// Note: this is a heuristic. The kernel-level direction tag carried
// on the connstate would be authoritative; this is a fallback for
// ledger rows where that info wasn't preserved.
func classifyDirection(dests []BinaryDestRow, listenPorts []uint16) (string, string) {
	if len(dests) == 0 {
		return "unknown", ""
	}
	serverPort := map[uint16]bool{
		22: true, 25: true, 53: true, 80: true, 110: true, 143: true,
		443: true, 465: true, 587: true, 993: true, 995: true,
		3306: true, 5432: true, 6379: true, 9200: true, 27017: true,
		8080: true, 8443: true,
	}
	// Signal 1: does the binary listen on a service port?
	listensOnService := false
	listenSvc := []uint16{}
	for _, p := range listenPorts {
		if serverPort[p] {
			listensOnService = true
			listenSvc = append(listenSvc, p)
		}
	}
	// Signal 2: most dest ports look like clients (non-well-known, >1024).
	clientPortCount, svcPortCount := 0, 0
	for _, d := range dests {
		if serverPort[d.Port] {
			svcPortCount++
		} else if d.Port > 1024 {
			clientPortCount++
		}
	}
	// If binary listens on a service port AND dest ports look like client
	// ephemerals → bytes are replies to inbound clients.
	if listensOnService && clientPortCount > svcPortCount {
		ls := []string{}
		for _, p := range listenSvc {
			ls = append(ls, strconv.Itoa(int(p)))
		}
		return "inbound_reply", "This binary is a server listening on [" + strings.Join(ls, ",") + "]. The bytes attributed here are replies to inbound clients connecting from ephemeral ports, NOT outbound exfiltration. The ledger's eBPF tcp_connect kprobe also fires on accept-side sockets — that's why these rows appear under egress."
	}
	if svcPortCount > clientPortCount {
		return "outbound", "Destinations target well-known service ports (HTTPS / DNS / SSH / DB). The binary is initiating outbound connections."
	}
	if clientPortCount > 0 && !listensOnService {
		return "outbound", "Destinations target non-standard ports and the binary does not listen on any service port. Outbound P2P / control-plane / custom protocol."
	}
	return "mixed", "Destination ports do not show a clean inbound/outbound signature."
}
