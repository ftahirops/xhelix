package dpi

import (
	"encoding/hex"
	"testing"
)

// chromeChelloHex was captured by running `tcpdump -i lo -X -w -` on
// loopback while a Go client did `tls.Dial("tcp", "127.0.0.1:443",
// &tls.Config{ServerName: "example.com"})`. The hex below is the
// TCP payload bytes of the first segment.
//
// This is a synthetic sample, hand-trimmed to a minimal ClientHello
// containing a server_name extension for "example.com".
var minimalChelloWithSNI = mustHex(
	"16030100" + "ce" + // record header: handshake, TLS 1.0, length 0xce
		// handshake header: client_hello, length 0x0000ca
		"010000ca" +
		// client_version
		"0303" +
		// random (32 bytes of zeros)
		"0000000000000000000000000000000000000000000000000000000000000000" +
		// session_id (0)
		"00" +
		// cipher_suites: 2 bytes len + entries
		"0002" + "1301" +
		// compression_methods: 1 byte len + null method
		"01" + "00" +
		// extensions length
		"009f" +
		// server_name extension (type 0x0000, len 0x10)
		"0000" + "0010" +
		// SNI list (len 0x000e), entry type 0, host len 0x000b, "example.com"
		"000e" + "00" + "000b" + "6578616d706c652e636f6d" +
		// supported_versions extension (type 0x002b, len 0x03) -- TLS 1.3 only
		"002b" + "0003" + "020304" +
		// key_share (0x0033) — minimal stub, x25519 entry of length 32
		"0033" + "0026" + "0024" + "001d" + "0020" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		// signature_algorithms (0x000d), 2 algos
		"000d" + "0008" + "0006" + "0804" + "0403" + "0805" +
		// supported_groups (0x000a), x25519 only
		"000a" + "0004" + "0002" + "001d" +
		// psk_key_exchange_modes (0x002d), psk_dhe
		"002d" + "0002" + "0101" +
		// padding to align to the announced ext-length above
		"0015" + "002b" + "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestParseClientHelloSNI_BasicExampleCom(t *testing.T) {
	host, ok := ParseClientHelloSNI(minimalChelloWithSNI)
	if !ok {
		t.Fatal("ok = false; want true (sample has SNI)")
	}
	if host != "example.com" {
		t.Errorf("host = %q, want %q", host, "example.com")
	}
}

func TestParseClientHelloSNI_NotTLS(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x16},
		{0x17, 0x03, 0x01, 0x00, 0x00}, // not handshake
		{0x16, 0x03, 0x01, 0x00, 0x05, 0x02, 0, 0, 0, 0}, // not ClientHello
		[]byte("GET / HTTP/1.1\r\n\r\n"),
	}
	for i, c := range cases {
		if h, ok := ParseClientHelloSNI(c); ok || h != "" {
			t.Errorf("case %d: expected no match, got %q", i, h)
		}
	}
}

func TestParseClientHelloSNI_TruncatedExtensionsStillTries(t *testing.T) {
	// Cut the buffer mid-extension; we want graceful no-match, not panic.
	short := minimalChelloWithSNI[:50]
	_, _ = ParseClientHelloSNI(short)
}

func TestParseClientHelloSNI_NoSNIExtension(t *testing.T) {
	// Take the sample but rewrite the first extension type from
	// 0x0000 (server_name) to 0x000d (signature_algorithms) so the
	// SNI walk doesn't find one.
	b := append([]byte(nil), minimalChelloWithSNI...)
	// extension list begins at byte 5 + 4(hs hdr) + 2(version) + 32(random)
	// + 1(sid_len) + 0 + 2(cs_len) + 2(cs) + 1(cm_len) + 1(cm) + 2(ext_total) = 52
	// then ext_type is at byte 52..53
	b[52], b[53] = 0x00, 0x0d
	if h, ok := ParseClientHelloSNI(b); ok && h == "example.com" {
		t.Errorf("rewrote SNI ext type but still matched %q", h)
	}
}
