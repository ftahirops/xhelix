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
	binary.Write(&payload, binary.LittleEndian, uint32(17)) // AF_PACKET
	binary.Write(&payload, binary.LittleEndian, uint32(3))  // SOCK_RAW
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
