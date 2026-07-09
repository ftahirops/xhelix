package ebpf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
)

// buildHdr writes an xh_event_hdr matching the C layout.
func buildHdr(kind EventKind, pid, ppid, uid uint32, comm string) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint64(0xdeadbeef)) // ts_ns
	binary.Write(&buf, binary.LittleEndian, uint32(kind))
	binary.Write(&buf, binary.LittleEndian, pid)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // tid
	binary.Write(&buf, binary.LittleEndian, ppid)
	binary.Write(&buf, binary.LittleEndian, uid)
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // gid
	binary.Write(&buf, binary.LittleEndian, uint64(0)) // cgroup_id
	var c [16]byte
	copy(c[:], comm)
	buf.Write(c[:])
	return buf.Bytes()
}

func TestDecodeShortRecord(t *testing.T) {
	if _, err := Decode([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short record")
	}
}

func TestDecodeProcSpawn(t *testing.T) {
	hdr := buildHdr(KindProcSpawn, 1234, 1, 0, "bash")
	var path [256]byte
	copy(path[:], "/usr/bin/bash")
	hdr = append(hdr, path[:]...)
	hdr = append(hdr, 0, 0, 0, 0) // from_memfd = 0

	ev, err := Decode(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Sensor != "ebpf.proc" {
		t.Errorf("sensor = %q", ev.Sensor)
	}
	if ev.PID != 1234 {
		t.Errorf("pid = %d", ev.PID)
	}
	if ev.Comm != "bash" {
		t.Errorf("comm = %q", ev.Comm)
	}
	if ev.Image != "/usr/bin/bash" {
		t.Errorf("image = %q", ev.Image)
	}
}

func TestDecodeNetConnectV4(t *testing.T) {
	hdr := buildHdr(KindNetConnect, 999, 1, 1000, "curl")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(2)) // AF_INET
	addr := [16]byte{}
	addr[12], addr[13], addr[14], addr[15] = 1, 2, 3, 4
	payload.Write(addr[:])
	binary.Write(&payload, binary.LittleEndian, uint16(443))

	ev, err := Decode(append(hdr, payload.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Tags["dst_ip"] != "1.2.3.4" {
		t.Errorf("dst_ip = %q", ev.Tags["dst_ip"])
	}
	if ev.Tags["dst_port"] != "443" {
		t.Errorf("dst_port = %q", ev.Tags["dst_port"])
	}
	if ev.Tags["outbound"] != "true" {
		t.Errorf("outbound tag missing")
	}
}

func TestDecodeProcCredUidEscalation(t *testing.T) {
	hdr := buildHdr(KindProcCred, 100, 1, 1000, "exploit")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(1000)) // old
	binary.Write(&payload, binary.LittleEndian, uint32(0))    // new (root)

	ev, err := Decode(append(hdr, payload.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical", ev.Severity)
	}
	if ev.Tags["uid0_transition"] != "true" {
		t.Errorf("uid0_transition tag missing")
	}
}

func TestDecodeMprotectIsCritical(t *testing.T) {
	hdr := buildHdr(KindMprotectRWX, 100, 1, 1000, "evil")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint64(0x7fff00000000))
	binary.Write(&payload, binary.LittleEndian, uint32(0x7)) // R|W|X

	ev, err := Decode(append(hdr, payload.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Severity != model.SeverityCritical {
		t.Errorf("severity = %v, want critical", ev.Severity)
	}
	if !strings.Contains(ev.Tags["mprotect_prot"], "0x7") {
		t.Errorf("mprotect_prot = %q", ev.Tags["mprotect_prot"])
	}
}

func TestDecodeNetConnectWithSrcPort(t *testing.T) {
	hdr := buildHdr(KindNetConnect, 1001, 1, 1000, "curl")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(2)) // AF_INET
	addr := [16]byte{}
	addr[12], addr[13], addr[14], addr[15] = 8, 8, 8, 8
	payload.Write(addr[:])
	binary.Write(&payload, binary.LittleEndian, uint16(443))   // dport
	binary.Write(&payload, binary.LittleEndian, uint16(49152)) // sport

	ev, err := Decode(append(hdr, payload.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Tags["dst_ip"] != "8.8.8.8" {
		t.Errorf("dst_ip = %q", ev.Tags["dst_ip"])
	}
	if ev.Tags["src_port"] != "49152" {
		t.Errorf("src_port = %q", ev.Tags["src_port"])
	}
}

func TestDecodeRawSocketAFPacket(t *testing.T) {
	hdr := buildHdr(KindNetRawSock, 777, 1, 0, "tcpdump")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(17))     // AF_PACKET
	binary.Write(&payload, binary.LittleEndian, uint32(3))      // SOCK_RAW
	binary.Write(&payload, binary.LittleEndian, uint32(0x0003)) // ETH_P_ALL

	ev, err := Decode(append(hdr, payload.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Sensor != "ebpf.net" {
		t.Errorf("sensor = %q", ev.Sensor)
	}
	if ev.Tags["raw_socket"] != "true" {
		t.Errorf("raw_socket missing: %+v", ev.Tags)
	}
	if ev.Tags["family"] != "packet" {
		t.Errorf("family = %q", ev.Tags["family"])
	}
	if ev.Tags["sock_type_name"] != "raw" {
		t.Errorf("sock_type_name = %q", ev.Tags["sock_type_name"])
	}
	if ev.Severity != model.SeverityWarn {
		t.Errorf("severity = %v, want warn", ev.Severity)
	}
}

func TestDecodeRawSocketInetRaw(t *testing.T) {
	hdr := buildHdr(KindNetRawSock, 888, 1, 0, "nmap")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(2)) // AF_INET
	binary.Write(&payload, binary.LittleEndian, uint32(3)) // SOCK_RAW
	binary.Write(&payload, binary.LittleEndian, uint32(1)) // IPPROTO_ICMP

	ev, err := Decode(append(hdr, payload.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Tags["family"] != "inet" {
		t.Errorf("family = %q", ev.Tags["family"])
	}
	if ev.Tags["sock_protocol"] != "1" {
		t.Errorf("protocol = %q", ev.Tags["sock_protocol"])
	}
}

func TestDecodeSSLReadHTTP(t *testing.T) {
	hdr := buildHdr(KindSSLRead, 4321, 1, 1000, "firefox")
	const bufMax = 256
	body := []byte("GET /search?q=test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(len(body)))
	buf := make([]byte, bufMax)
	copy(buf, body)
	payload.Write(buf)

	ev, err := Decode(append(hdr, payload.Bytes()...))
	if err != nil {
		t.Fatal(err)
	}
	if ev.Sensor != "ebpf.ssl" {
		t.Errorf("sensor = %q", ev.Sensor)
	}
	if ev.Tags["http_request_line"] == "" {
		t.Errorf("request line missing: %+v", ev.Tags)
	}
	if ev.Tags["http_host"] != "example.com" {
		t.Errorf("host = %q", ev.Tags["http_host"])
	}
}

func TestDecodeSSLReadNonHTTP(t *testing.T) {
	hdr := buildHdr(KindSSLRead, 4321, 1, 1000, "firefox")
	const bufMax = 256
	// Binary payload — should not be flagged as HTTP.
	body := []byte("\x00\x01\x02\x03binary garbage no newline easily")
	var payload bytes.Buffer
	binary.Write(&payload, binary.LittleEndian, uint32(len(body)))
	buf := make([]byte, bufMax)
	copy(buf, body)
	payload.Write(buf)

	ev, _ := Decode(append(hdr, payload.Bytes()...))
	if ev.Tags["http_request_line"] != "" {
		t.Errorf("should not detect HTTP in binary payload; got %q",
			ev.Tags["http_request_line"])
	}
	if ev.Tags["ssl_read"] != "true" {
		t.Errorf("ssl_read tag missing")
	}
}

// TestDecodeBPFSyscallProgLoad guards the 2026-06-15 fix: the bpf()
// decoder must derive the security-relevant boolean tags from the cmd
// number, so ebpf_program_load_unexpected (which gates on bpf_prog_load)
// can fire. Before the fix only the raw bpf_cmd was set and the tag was
// never produced -> dead rule. (The kernel-side cmd-capture bug is fixed
// separately in all.bpf.c and verified by `make ebpf` + live.)
func TestDecodeBPFSyscallProgLoad(t *testing.T) {
	cases := []struct {
		cmd     uint32
		wantTag string
	}{
		{5, "bpf_prog_load"},
		{8, "bpf_prog_attach"},
		{28, "bpf_link_create"},
		{18, "bpf_btf_load"},
		{0, ""}, // BPF_MAP_CREATE — benign, no security tag
	}
	for _, tc := range cases {
		hdr := buildHdr(KindBPFSyscall, 4242, 1, 0, "rootkit")
		var payload bytes.Buffer
		binary.Write(&payload, binary.LittleEndian, tc.cmd)
		ev, err := Decode(append(hdr, payload.Bytes()...))
		if err != nil {
			t.Fatalf("cmd=%d: decode: %v", tc.cmd, err)
		}
		if ev.Tags["bpf_syscall"] != "true" {
			t.Errorf("cmd=%d: bpf_syscall tag missing", tc.cmd)
		}
		if tc.wantTag != "" && ev.Tags[tc.wantTag] != "true" {
			t.Errorf("cmd=%d: expected tag %q=true, tags=%v", tc.cmd, tc.wantTag, ev.Tags)
		}
		if tc.wantTag == "" {
			for _, k := range []string{"bpf_prog_load", "bpf_prog_attach", "bpf_link_create", "bpf_btf_load"} {
				if ev.Tags[k] == "true" {
					t.Errorf("cmd=%d (benign): unexpected tag %q set", tc.cmd, k)
				}
			}
		}
	}
}

// fcgiRecord builds a v1 FastCGI record: 8-byte header + content.
func fcgiRecord(typ byte, reqID uint16, content []byte) []byte {
	h := []byte{1, typ, byte(reqID >> 8), byte(reqID), byte(len(content) >> 8), byte(len(content)), 0, 0}
	return append(h, content...)
}

// buildFCGITestPayload constructs an XH_EV_FCGI_REQUEST payload:
// buf_len(4 LE) | BEGIN_REQUEST(reqID=1) + PARAMS stream (short-form lengths).
func buildFCGITestPayload(t *testing.T) []byte {
	t.Helper()
	begin := fcgiRecord(1 /*BEGIN_REQUEST*/, 1, []byte{0x00, 0x01, 0x01, 0, 0, 0, 0, 0})
	var params []byte
	add := func(k, v string) {
		params = append(params, byte(len(k)), byte(len(v)))
		params = append(params, []byte(k)...)
		params = append(params, []byte(v)...)
	}
	// Order deterministic (map iteration would not be) so the stream is stable.
	add("REQUEST_METHOD", "POST")
	add("REQUEST_URI", "/wp-login.php")
	add("HTTP_HOST", "site-a.com")
	add("SCRIPT_FILENAME", "/var/www/site-a/wp-login.php")
	stream := append(begin, fcgiRecord(4 /*PARAMS*/, 1, params)...)

	buf := make([]byte, 4+len(stream))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(stream)))
	copy(buf[4:], stream)
	return buf
}

func TestDecodeFCGIRequest(t *testing.T) {
	payload := buildFCGITestPayload(t)
	ev := model.Event{Tags: map[string]string{}}
	decodeFCGIRequestEvent(&ev, payload)
	if ev.Tags["kind"] != "fcgi_request" {
		t.Fatalf("kind = %q", ev.Tags["kind"])
	}
	if ev.Tags["http_host"] != "site-a.com" || ev.Tags["http_uri"] != "/wp-login.php" {
		t.Errorf("host/uri = %q/%q", ev.Tags["http_host"], ev.Tags["http_uri"])
	}
	if ev.Tags["http_method"] != "POST" {
		t.Errorf("method = %q", ev.Tags["http_method"])
	}
	if ev.Tags["script_filename"] != "/var/www/site-a/wp-login.php" {
		t.Errorf("script = %q", ev.Tags["script_filename"])
	}
	if ev.Tags["fcgi_request_id"] != "1" {
		t.Errorf("request_id = %q", ev.Tags["fcgi_request_id"])
	}
	if ev.Tags["fidelity"] != "coarse" {
		t.Error("fcgi_request must be tagged coarse")
	}
}

func TestDecodeFCGIRequestRejectsNonFCGI(t *testing.T) {
	stream := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	buf := make([]byte, 4+len(stream))
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(stream)))
	copy(buf[4:], stream)
	ev := model.Event{Tags: map[string]string{}}
	decodeFCGIRequestEvent(&ev, buf)
	if ev.Tags["kind"] != "fcgi_request" {
		t.Fatalf("kind = %q", ev.Tags["kind"])
	}
	if ev.Tags["fidelity"] == "coarse" {
		t.Error("plain HTTP must not be classified as a FastCGI request")
	}
	if ev.Tags["http_host"] != "" {
		t.Errorf("unexpected host tag %q", ev.Tags["http_host"])
	}
}

func TestSSLReadStampsRequestID(t *testing.T) {
	ev := model.Event{PID: 4242, Tags: map[string]string{
		"http_host":         "site-a.com",
		"http_request_line": "GET /wp-login.php HTTP/1.1",
	}}
	stampWebRequestID(&ev) // the new helper
	if ev.Tags["request_id"] == "" {
		t.Fatal("request_id not stamped")
	}
	// Stable within an event, distinct across request-lines.
	first := ev.Tags["request_id"]
	ev.Tags["request_id"] = ""
	ev.Tags["http_request_line"] = "GET /other HTTP/1.1"
	stampWebRequestID(&ev)
	if ev.Tags["request_id"] == first {
		t.Error("distinct request-lines must yield distinct request_id")
	}
}
