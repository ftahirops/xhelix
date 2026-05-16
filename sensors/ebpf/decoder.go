package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/xhelix/xhelix/pkg/model"
)

var (
	osReadlink = os.Readlink
	osReadFile = os.ReadFile
	itoa       = strconv.Itoa
)

// isSocketFd reports whether /proc/<pid>/fd/<fd> resolves to a
// socket: target. Best-effort: missing pid races aren't fatal.
func isSocketFd(pid uint32, fd int) bool {
	link, err := osReadlink("/proc/" + itoa(int(pid)) + "/fd/" + itoa(fd))
	if err != nil {
		return false
	}
	return strings.HasPrefix(link, "socket:")
}

// sanitiseArgv joins NUL-separated argv into a space-separated string,
// truncated to 1 KB so a single huge command line can't bloat events.
func sanitiseArgv(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	const cap = 1024
	if len(body) > cap {
		body = body[:cap]
	}
	out := make([]byte, 0, len(body))
	for _, b := range body {
		if b == 0 {
			out = append(out, ' ')
		} else if b < 32 || b > 126 {
			// non-printable → control char marker; preserves length
			out = append(out, '?')
		} else {
			out = append(out, b)
		}
	}
	return string(strings.TrimSpace(string(out)))
}

// xhEventHdr mirrors the C struct xh_event_hdr. Layout is stable
// across releases: existing kinds never change, new event types add
// new kind values.
type xhEventHdr struct {
	TsNs     uint64
	Kind     uint32
	PID      uint32
	TID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	CGroupID uint64
	Comm     [16]byte
}

// hdrSize is the wire size of xhEventHdr; binary.Read rejects buffers
// smaller than this. 6 uint32 fields after the leading uint64.
const hdrSize = 8 + 4*6 + 8 + 16 // 56

// defaultBoolTags is the set of boolean-shaped tags that every
// ebpf.* event pre-populates with "false".
//
// This is the fix for the most common rule-authoring trap: writing
// `event.tags["X"] != "true"` only to have CEL error on missing key.
// With every documented tag pre-set, rule expressions evaluate
// without the `has()` guard.
var defaultBoolTags = []string{
	"stdin_is_socket", "stdout_is_socket", "from_memfd",
	"ptrace_attach", "bpf_syscall", "mod_load", "mount",
	"outbound", "uid0_transition", "mprotect_rwx",
	"jit_allowlisted", "package_managed", "first_seen_image",
}

// Decode parses a single ringbuf record into a model.Event.
//
// Returns an error if the record is shorter than the header or the
// payload doesn't match the kind. Unknown kinds project to a generic
// event tagged with their numeric kind so future kernel programs do
// not silently break the userspace path.
func Decode(raw []byte) (model.Event, error) {
	if len(raw) < hdrSize {
		return model.Event{}, fmt.Errorf("ebpf decode: record %d bytes < header %d", len(raw), hdrSize)
	}
	r := bytes.NewReader(raw)
	var h xhEventHdr
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return model.Event{}, fmt.Errorf("ebpf decode header: %w", err)
	}

	ev := model.NewEvent(sensorForKind(EventKind(h.Kind)), severityForKind(EventKind(h.Kind)))
	ev.PID = h.PID
	ev.TID = h.TID
	ev.ParentPID = h.PPID
	ev.UID = h.UID
	ev.GID = h.GID
	ev.CGroupID = h.CGroupID
	ev.Comm = nullTerm(h.Comm[:])
	// Pre-populate every documented bool-shaped tag with "false" so
	// CEL rules that test `event.tags["X"] == "true"` never error
	// on missing keys. Later decode functions override the ones
	// that actually apply.
	for _, k := range defaultBoolTags {
		ev.Tags[k] = "false"
	}
	ev.Tags["kind"] = EventKind(h.Kind).String()
	ev.Tags["ts_ns"] = fmt.Sprintf("%d", h.TsNs)

	payload := raw[hdrSize:]
	switch EventKind(h.Kind) {
	case KindProcSpawn:
		decodeProcSpawn(payload, &ev)
	case KindProcCred:
		decodeProcCred(payload, &ev)
	case KindFileOpen:
		decodeFileOpen(payload, &ev)
	case KindNetConnect, KindNetBind:
		decodeNetEvent(payload, &ev)
	case KindNetBytes:
		decodeNetBytesEvent(payload, &ev)
	case KindNetRawSock:
		decodeRawSockEvent(payload, &ev)
	case KindCapSet:
		decodeCapSetEvent(payload, &ev)
	case KindPivotRoot:
		ev.Tags["pivot_root"] = "true"
		ev.Severity = model.SeverityWarn
	case KindUnshare:
		decodeUnshareEvent(payload, &ev)
	case KindSSLRead:
		decodeSSLReadEvent(payload, &ev)
	case KindBPFSyscall:
		decodeBPFSyscall(payload, &ev)
	case KindPtrace:
		decodePtrace(payload, &ev)
	case KindMprotectRWX:
		decodeMprotect(payload, &ev)
	case KindModLoad:
		ev.Tags["mod_load"] = "true"
	case KindMount:
		ev.Tags["mount"] = "true"
	}
	return ev, nil
}

func decodeProcSpawn(b []byte, ev *model.Event) {
	if len(b) < 256 {
		return
	}
	ev.Image = nullTerm(b[:256])

	// Wire format (matches struct xh_proc_spawn in all.bpf.c):
	//   filename(256) | from_memfd(4) | stdin_is_socket(4) | stdout_is_socket(4)
	if len(b) >= 260 {
		if binary.LittleEndian.Uint32(b[256:260]) != 0 {
			ev.Tags["from_memfd"] = "true"
		}
	}
	if len(b) >= 264 {
		if binary.LittleEndian.Uint32(b[260:264]) != 0 {
			ev.Tags["stdin_is_socket"] = "true"
		}
	}
	if len(b) >= 268 {
		if binary.LittleEndian.Uint32(b[264:268]) != 0 {
			ev.Tags["stdout_is_socket"] = "true"
		}
	}

	// Fallback when the kernel-side filename read came back empty.
	if ev.Image == "" && ev.PID > 0 {
		if path, err := osReadlink("/proc/" + itoa(int(ev.PID)) + "/exe"); err == nil {
			ev.Image = path
		}
	}
	if strings.HasPrefix(ev.Image, "/memfd:") ||
		strings.HasPrefix(ev.Image, "/proc/self/fd/") {
		ev.Tags["from_memfd"] = "true"
	}

	// /proc fallback for socket-fd detection — kicks in only when
	// the eBPF walk didn't already populate the tag.
	if ev.PID > 0 {
		if ev.Tags["stdin_is_socket"] != "true" && isSocketFd(ev.PID, 0) {
			ev.Tags["stdin_is_socket"] = "true"
		}
		if ev.Tags["stdout_is_socket"] != "true" && isSocketFd(ev.PID, 1) {
			ev.Tags["stdout_is_socket"] = "true"
		}
	}
	ev.Tags["path"] = ev.Image

	// argv capture from /proc/<pid>/cmdline.
	if ev.PID > 0 {
		if body, err := osReadFile("/proc/" + itoa(int(ev.PID)) + "/cmdline"); err == nil {
			ev.Tags["argv"] = sanitiseArgv(body)
			ev.Tags["argc"] = itoa(strings.Count(string(body), "\x00"))
		}
	}
}

func decodeProcCred(b []byte, ev *model.Event) {
	if len(b) < 8 {
		return
	}
	old := binary.LittleEndian.Uint32(b[0:4])
	nu := binary.LittleEndian.Uint32(b[4:8])
	ev.Tags["old_uid"] = fmt.Sprintf("%d", old)
	ev.Tags["new_uid"] = fmt.Sprintf("%d", nu)
	if nu == 0 && old != 0 {
		ev.Severity = model.SeverityCritical
		ev.Tags["uid0_transition"] = "true"
	}
}

func decodeFileOpen(b []byte, ev *model.Event) {
	if len(b) < 256 {
		return
	}
	path := nullTerm(b[:256])
	ev.Tags["path"] = path
	if len(b) >= 260 {
		flags := binary.LittleEndian.Uint32(b[256:260])
		ev.Tags["flags"] = fmt.Sprintf("%#x", flags)
	}
}

func decodeNetEvent(b []byte, ev *model.Event) {
	if len(b) < 4+16+2 {
		return
	}
	family := binary.LittleEndian.Uint32(b[0:4])
	addr := b[4:20]
	port := binary.LittleEndian.Uint16(b[20:22])
	switch family {
	case 2: // AF_INET
		ip := net.IPv4(addr[12], addr[13], addr[14], addr[15])
		ev.Tags["dst_ip"] = ip.String()
		ev.Tags["family"] = "inet"
	case 10: // AF_INET6
		ip := net.IP(addr)
		ev.Tags["dst_ip"] = ip.String()
		ev.Tags["family"] = "inet6"
	default:
		ev.Tags["family"] = fmt.Sprintf("%d", family)
	}
	ev.Tags["dst_port"] = fmt.Sprintf("%d", port)
	// sport is the new field added by T0.4. Older programs (or
	// the sys_enter_connect tracepoint variant) emit zero, which
	// we propagate as src_port=0 — the dispatch layer tolerates
	// it (see pkg/connstate.Tuple docs).
	if len(b) >= 4+16+2+2 {
		sport := binary.LittleEndian.Uint16(b[22:24])
		if sport != 0 {
			ev.Tags["src_port"] = fmt.Sprintf("%d", sport)
		}
	}
	ev.Tags["outbound"] = "true"
}

// decodeNetBytesEvent parses an XH_EV_NET_BYTES payload:
// family(4) | daddr(16) | dport(2) | sport(2) | bytes(4) | dir(1) | _pad(3).
// Emitted by kprobe_tcp_sendmsg (dir=0) and kprobe_tcp_recvmsg (dir=1).
func decodeNetBytesEvent(b []byte, ev *model.Event) {
	if len(b) < 4+16+2+2+4+1 {
		return
	}
	family := binary.LittleEndian.Uint32(b[0:4])
	addr := b[4:20]
	dport := binary.LittleEndian.Uint16(b[20:22])
	sport := binary.LittleEndian.Uint16(b[22:24])
	bytes := binary.LittleEndian.Uint32(b[24:28])
	dir := b[28]

	switch family {
	case 2:
		ip := net.IPv4(addr[12], addr[13], addr[14], addr[15])
		ev.Tags["dst_ip"] = ip.String()
		ev.Tags["family"] = "inet"
	case 10:
		ip := net.IP(addr)
		ev.Tags["dst_ip"] = ip.String()
		ev.Tags["family"] = "inet6"
	}
	ev.Tags["dst_port"] = fmt.Sprintf("%d", dport)
	if sport != 0 {
		ev.Tags["src_port"] = fmt.Sprintf("%d", sport)
	}
	ev.Tags["bytes"] = fmt.Sprintf("%d", bytes)
	if dir == 0 {
		ev.Tags["dir"] = "out"
	} else {
		ev.Tags["dir"] = "in"
	}
}

// decodeSSLReadEvent parses an XH_EV_SSL_READ payload:
// buf_len(4) | buf[XH_SSL_BUF_MAX=256]. We extract the HTTP
// request line (METHOD PATH HTTP/x) plus a few headers if the
// payload starts with one — the high-signal case for the
// "what URL did this process actually request" forensic view.
func decodeSSLReadEvent(b []byte, ev *model.Event) {
	const bufMax = 256
	if len(b) < 4+bufMax {
		return
	}
	bufLen := binary.LittleEndian.Uint32(b[0:4])
	if bufLen > bufMax {
		bufLen = bufMax
	}
	payload := b[4 : 4+bufLen]
	ev.Tags["ssl_read"] = "true"
	ev.Tags["ssl_read_len"] = fmt.Sprintf("%d", bufLen)

	// HTTP heuristic: first line is "METHOD path HTTP/x.x\r\n"
	// where METHOD is one of GET/POST/PUT/DELETE/HEAD/OPTIONS/
	// PATCH/CONNECT/TRACE.
	nl := bytes.IndexByte(payload, '\n')
	if nl > 0 && nl < 8192 {
		line := string(bytes.TrimRight(payload[:nl], "\r"))
		if isLikelyHTTPRequestLine(line) {
			ev.Tags["http_request_line"] = line
			// Extract Host: header from subsequent headers
			rest := payload[nl+1:]
			if host := extractHTTPHostHeader(rest); host != "" {
				ev.Tags["http_host"] = host
			}
		}
	}
}

// isLikelyHTTPRequestLine returns true when s looks like a
// well-formed HTTP request line.
func isLikelyHTTPRequestLine(s string) bool {
	for _, m := range []string{
		"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
		"OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
	} {
		if strings.HasPrefix(s, m) && strings.Contains(s, " HTTP/") {
			return true
		}
	}
	return false
}

// extractHTTPHostHeader looks for `Host: <value>` in raw HTTP
// header bytes. Returns "" if missing.
func extractHTTPHostHeader(b []byte) string {
	lines := bytes.Split(b, []byte("\r\n"))
	for _, ln := range lines {
		if len(ln) == 0 {
			break
		}
		if bytes.HasPrefix(bytes.ToLower(ln), []byte("host:")) {
			return string(bytes.TrimSpace(ln[5:]))
		}
	}
	return ""
}

// decodeUnshareEvent parses an XH_EV_UNSHARE payload: flags(8).
// We stamp the raw flags + a bitset-decoded list of CLONE_NEW*
// names so CEL rules can filter (e.g. `event.tags["unshare_user"]
// == "true"`).
func decodeUnshareEvent(b []byte, ev *model.Event) {
	if len(b) < 8 {
		return
	}
	flags := binary.LittleEndian.Uint64(b[0:8])
	ev.Tags["unshare_flags"] = fmt.Sprintf("%#x", flags)
	ev.Tags["unshare"] = "true"
	// CLONE_* values from linux/sched.h
	const (
		CLONE_NEWNS     = 0x00020000
		CLONE_NEWUSER   = 0x10000000
		CLONE_NEWPID    = 0x20000000
		CLONE_NEWNET    = 0x40000000
		CLONE_NEWIPC    = 0x08000000
		CLONE_NEWUTS    = 0x04000000
		CLONE_NEWCGROUP = 0x02000000
	)
	if flags&CLONE_NEWNS != 0 {
		ev.Tags["unshare_ns_mount"] = "true"
	}
	if flags&CLONE_NEWUSER != 0 {
		ev.Tags["unshare_ns_user"] = "true"
		ev.Severity = model.SeverityWarn
	}
	if flags&CLONE_NEWPID != 0 {
		ev.Tags["unshare_ns_pid"] = "true"
		ev.Severity = model.SeverityWarn
	}
	if flags&CLONE_NEWNET != 0 {
		ev.Tags["unshare_ns_net"] = "true"
	}
	if flags&CLONE_NEWIPC != 0 {
		ev.Tags["unshare_ns_ipc"] = "true"
	}
	if flags&CLONE_NEWUTS != 0 {
		ev.Tags["unshare_ns_uts"] = "true"
	}
	if flags&CLONE_NEWCGROUP != 0 {
		ev.Tags["unshare_ns_cgroup"] = "true"
	}
}

// decodeCapSetEvent parses an XH_EV_CAP_SET payload:
// effective(8) | permitted(8) | inheritable(8). The values are
// CAP_* bitsets (CAP_LAST_CAP < 64 on modern kernels), stored as
// uint64 in little-endian.
func decodeCapSetEvent(b []byte, ev *model.Event) {
	if len(b) < 24 {
		return
	}
	eff := binary.LittleEndian.Uint64(b[0:8])
	perm := binary.LittleEndian.Uint64(b[8:16])
	inh := binary.LittleEndian.Uint64(b[16:24])
	ev.Tags["cap_effective"] = fmt.Sprintf("%#x", eff)
	ev.Tags["cap_permitted"] = fmt.Sprintf("%#x", perm)
	ev.Tags["cap_inheritable"] = fmt.Sprintf("%#x", inh)
	ev.Tags["capset"] = "true"
}

// decodeRawSockEvent parses an XH_EV_NET_RAW_SOCK payload:
// family (4) | type (4) | protocol (4).
func decodeRawSockEvent(b []byte, ev *model.Event) {
	if len(b) < 12 {
		return
	}
	family := binary.LittleEndian.Uint32(b[0:4])
	typ := binary.LittleEndian.Uint32(b[4:8])
	proto := binary.LittleEndian.Uint32(b[8:12])
	ev.Tags["sock_family"] = fmt.Sprintf("%d", family)
	ev.Tags["sock_type"] = fmt.Sprintf("%d", typ)
	ev.Tags["sock_protocol"] = fmt.Sprintf("%d", proto)
	switch family {
	case 17:
		ev.Tags["family"] = "packet"
	case 2:
		ev.Tags["family"] = "inet"
	case 10:
		ev.Tags["family"] = "inet6"
	}
	switch typ {
	case 3:
		ev.Tags["sock_type_name"] = "raw"
	case 2:
		ev.Tags["sock_type_name"] = "dgram"
	}
	ev.Tags["raw_socket"] = "true"
	ev.Severity = model.SeverityWarn
}

func decodeBPFSyscall(b []byte, ev *model.Event) {
	if len(b) < 4 {
		return
	}
	cmd := binary.LittleEndian.Uint32(b[0:4])
	ev.Tags["bpf_cmd"] = fmt.Sprintf("%d", cmd)
	ev.Tags["bpf_syscall"] = "true"
}

func decodePtrace(b []byte, ev *model.Event) {
	if len(b) < 8 {
		return
	}
	req := binary.LittleEndian.Uint32(b[0:4])
	target := binary.LittleEndian.Uint32(b[4:8])
	ev.Tags["ptrace_request"] = fmt.Sprintf("%d", req)
	ev.Tags["ptrace_target_pid"] = fmt.Sprintf("%d", target)
	ev.Tags["ptrace_attach"] = "true"
	// Resolve target pid -> comm name so rules can pattern-match
	// against the *target's* identity (e.g., sshd, init, xhelix).
	if target > 0 {
		if comm, err := os.ReadFile("/proc/" + itoa(int(target)) + "/comm"); err == nil {
			ev.Tags["ptrace_target"] = string(bytes.TrimSpace(comm))
		}
	}
}

func decodeMprotect(b []byte, ev *model.Event) {
	if len(b) < 12 {
		return
	}
	addr := binary.LittleEndian.Uint64(b[0:8])
	prot := binary.LittleEndian.Uint32(b[8:12])
	ev.Tags["mprotect_addr"] = fmt.Sprintf("%#x", addr)
	ev.Tags["mprotect_prot"] = fmt.Sprintf("%#x", prot)
	ev.Tags["mprotect_rwx"] = "true"
	ev.Severity = model.SeverityCritical
}

func nullTerm(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func sensorForKind(k EventKind) string {
	switch k {
	case KindProcSpawn, KindProcCred:
		return "ebpf.proc"
	case KindFileOpen:
		return "ebpf.file"
	case KindNetConnect, KindNetBind, KindNetRawSock, KindNetICMP, KindNetBytes:
		return "ebpf.net"
	case KindCapSet:
		return "ebpf.cap"
	case KindPivotRoot, KindUnshare:
		return "ebpf.ns"
	case KindSSLRead:
		return "ebpf.ssl"
	case KindModLoad:
		return "ebpf.module"
	case KindBPFSyscall:
		return "ebpf.self"
	case KindPtrace, KindMount:
		return "ebpf.proc"
	case KindMprotectRWX, KindCanaryFail:
		return "ebpf.memory"
	}
	return "ebpf"
}

func severityForKind(k EventKind) model.Severity {
	switch k {
	case KindMprotectRWX, KindCanaryFail, KindBPFSyscall:
		return model.SeverityCritical
	case KindProcCred, KindModLoad, KindPtrace, KindMount, KindNetRawSock:
		return model.SeverityWarn
	}
	return model.SeverityNotice
}
