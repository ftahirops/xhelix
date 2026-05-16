package ja3

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildHello constructs a synthetic ClientHello body (handshake
// payload, not including record header or handshake header).
func buildHello(version uint16, ciphers []uint16, ext map[uint16][]byte) []byte {
	var b []byte
	// version(2)
	v := make([]byte, 2)
	binary.BigEndian.PutUint16(v, version)
	b = append(b, v...)
	// random(32)
	b = append(b, make([]byte, 32)...)
	// session_id_len(1) + session_id (none)
	b = append(b, 0x00)
	// cipher_suites_len(2) + ciphers
	cs := make([]byte, 2+len(ciphers)*2)
	binary.BigEndian.PutUint16(cs[:2], uint16(len(ciphers)*2))
	for i, c := range ciphers {
		binary.BigEndian.PutUint16(cs[2+i*2:], c)
	}
	b = append(b, cs...)
	// compression_methods_len(1) + 0x00 (null)
	b = append(b, 0x01, 0x00)
	// extensions
	if len(ext) > 0 {
		var exts []byte
		for typ, body := range ext {
			hdr := make([]byte, 4)
			binary.BigEndian.PutUint16(hdr[:2], typ)
			binary.BigEndian.PutUint16(hdr[2:], uint16(len(body)))
			exts = append(exts, hdr...)
			exts = append(exts, body...)
		}
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(len(exts)))
		b = append(b, l...)
		b = append(b, exts...)
	} else {
		// empty extensions block
		b = append(b, 0x00, 0x00)
	}
	return b
}

func sniExt(name string) []byte {
	body := make([]byte, 5+len(name))
	binary.BigEndian.PutUint16(body[:2], uint16(3+len(name))) // list_len
	body[2] = 0x00                                            // host_name
	binary.BigEndian.PutUint16(body[3:5], uint16(len(name)))
	copy(body[5:], name)
	return body
}

func u16Vec(values ...uint16) []byte {
	body := make([]byte, 2+len(values)*2)
	binary.BigEndian.PutUint16(body[:2], uint16(len(values)*2))
	for i, v := range values {
		binary.BigEndian.PutUint16(body[2+i*2:], v)
	}
	return body
}

func alpnExt(protos ...string) []byte {
	var inner []byte
	for _, p := range protos {
		inner = append(inner, byte(len(p)))
		inner = append(inner, []byte(p)...)
	}
	out := make([]byte, 2+len(inner))
	binary.BigEndian.PutUint16(out[:2], uint16(len(inner)))
	copy(out[2:], inner)
	return out
}

func TestParseMinimalHello(t *testing.T) {
	body := buildHello(0x0303,
		[]uint16{0x1301, 0x1302},
		map[uint16][]byte{
			0x0000: sniExt("example.com"),
			0x000a: u16Vec(29, 23),
			0x0010: alpnExt("h2", "http/1.1"),
		})
	fp, err := ParseRaw(body)
	if err != nil {
		t.Fatal(err)
	}
	if fp.SNI != "example.com" {
		t.Errorf("sni = %q", fp.SNI)
	}
	if len(fp.ALPN) != 2 || fp.ALPN[0] != "h2" {
		t.Errorf("alpn = %v", fp.ALPN)
	}
	if fp.TLSVersion != 0x0303 {
		t.Errorf("version = %#x", fp.TLSVersion)
	}
	if fp.JA3 == "" || fp.JA3Hash == "" {
		t.Errorf("ja3 missing: %+v", fp)
	}
	if fp.JA4 == "" {
		t.Errorf("ja4 missing")
	}
}

func TestJA3IsDeterministic(t *testing.T) {
	body := buildHello(0x0303, []uint16{0x1301, 0x1302},
		map[uint16][]byte{0x0000: sniExt("a.example")})
	fp1, _ := ParseRaw(body)
	fp2, _ := ParseRaw(body)
	if fp1.JA3Hash != fp2.JA3Hash {
		t.Fatal("JA3 must be deterministic")
	}
}

func TestDifferentCiphersDifferentJA3(t *testing.T) {
	a, _ := ParseRaw(buildHello(0x0303, []uint16{0x1301}, nil))
	b, _ := ParseRaw(buildHello(0x0303, []uint16{0x1302}, nil))
	if a.JA3Hash == b.JA3Hash {
		t.Fatal("different ciphers should produce different JA3 hashes")
	}
}

func TestGREASEFiltered(t *testing.T) {
	withoutGrease := buildHello(0x0303, []uint16{0x1301, 0x1302}, nil)
	withGrease := buildHello(0x0303, []uint16{0x1301, 0x0a0a, 0x1302}, nil)
	a, _ := ParseRaw(withoutGrease)
	b, _ := ParseRaw(withGrease)
	if a.JA3 != b.JA3 {
		t.Fatalf("GREASE not filtered: %q vs %q", a.JA3, b.JA3)
	}
}

func TestALPNExtraction(t *testing.T) {
	body := buildHello(0x0303, []uint16{0x1301}, map[uint16][]byte{
		0x0010: alpnExt("h2"),
	})
	fp, _ := ParseRaw(body)
	if len(fp.ALPN) != 1 || fp.ALPN[0] != "h2" {
		t.Fatalf("alpn = %v", fp.ALPN)
	}
}

func TestSNIMissingHandled(t *testing.T) {
	body := buildHello(0x0303, []uint16{0x1301}, nil)
	fp, _ := ParseRaw(body)
	if fp.SNI != "" {
		t.Fatalf("expected empty SNI; got %q", fp.SNI)
	}
}

func TestParseRecordWrapper(t *testing.T) {
	hello := buildHello(0x0303, []uint16{0x1301}, nil)
	// Wrap in handshake header (4) + record header (5)
	hs := append([]byte{0x01, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}, hello...)
	rec := append([]byte{0x16, 0x03, 0x03, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	fp, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	if fp.TLSVersion != 0x0303 {
		t.Errorf("version = %#x", fp.TLSVersion)
	}
}

func TestParseShortInputErrors(t *testing.T) {
	if _, err := Parse([]byte{0x16, 0x03}); err == nil {
		t.Fatal("short input should error")
	}
	if _, err := Parse(nil); err == nil {
		t.Fatal("nil input should error")
	}
}

func TestParseNonHandshakeErrors(t *testing.T) {
	// type 0x17 = application_data, not handshake
	rec := []byte{0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5}
	if _, err := Parse(rec); err == nil {
		t.Fatal("non-handshake record should error")
	}
}

func TestJA4FormatStable(t *testing.T) {
	body := buildHello(0x0303, []uint16{0x1301, 0x1302},
		map[uint16][]byte{
			0x0000: sniExt("a.example"),
			0x0010: alpnExt("h2"),
		})
	fp, _ := ParseRaw(body)
	// JA4 should start with "t12" (TLS 1.2 short) and contain "d" (SNI present).
	if !strings.HasPrefix(fp.JA4, "t12d") {
		t.Fatalf("ja4 prefix = %q", fp.JA4[:4])
	}
	// And contain two _-separated hashes.
	if strings.Count(fp.JA4, "_") != 2 {
		t.Fatalf("ja4 hash count: %q", fp.JA4)
	}
}

func TestTLSVerShort(t *testing.T) {
	cases := map[uint16]string{
		0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13", 0x9999: "00",
	}
	for in, want := range cases {
		if got := tlsVerShort(in); got != want {
			t.Errorf("tlsVerShort(%#x) = %q, want %q", in, got, want)
		}
	}
}
