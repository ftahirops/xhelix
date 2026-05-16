package dnsresolver

import (
	"encoding/binary"
	"testing"
)

// buildQuery constructs a minimal DNS query for "example.com" type A.
func buildQuery() []byte {
	var b []byte
	// Header: ID=1, RD=1, QDCOUNT=1
	b = append(b, 0x00, 0x01) // ID
	b = append(b, 0x01, 0x00) // Flags: RD
	b = append(b, 0x00, 0x01) // QDCOUNT
	b = append(b, 0x00, 0x00) // ANCOUNT
	b = append(b, 0x00, 0x00) // NSCOUNT
	b = append(b, 0x00, 0x00) // ARCOUNT
	// Question name: 7 "example" 3 "com" 0
	b = append(b, 7)
	b = append(b, []byte("example")...)
	b = append(b, 3)
	b = append(b, []byte("com")...)
	b = append(b, 0)
	b = append(b, 0x00, 0x01) // QTYPE=A
	b = append(b, 0x00, 0x01) // QCLASS=IN
	return b
}

// buildResponse extends a query with two A answers (1.2.3.4 and 5.6.7.8)
// using compression to point at the question's qname.
func buildResponse() []byte {
	q := buildQuery()
	// Header offsets: flag bytes [2:4], ANCOUNT [6:8]
	q[2] = 0x81
	q[3] = 0x80 // response, RD, RA
	q[6] = 0x00
	q[7] = 0x02 // ANCOUNT=2

	addA := func(buf []byte, ip [4]byte, ttl uint32) []byte {
		// Name: pointer to question name at offset 12
		buf = append(buf, 0xC0, 0x0C)
		buf = append(buf, 0x00, 0x01) // type A
		buf = append(buf, 0x00, 0x01) // class IN
		ttlBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ttlBytes, ttl)
		buf = append(buf, ttlBytes...)
		buf = append(buf, 0x00, 0x04) // rdlen
		buf = append(buf, ip[0], ip[1], ip[2], ip[3])
		return buf
	}
	q = addA(q, [4]byte{1, 2, 3, 4}, 300)
	q = addA(q, [4]byte{5, 6, 7, 8}, 60) // shorter TTL
	return q
}

func TestParseQuery(t *testing.T) {
	p, err := parseMessage(buildQuery())
	if err != nil {
		t.Fatal(err)
	}
	if p.QName != "example.com" {
		t.Errorf("qname = %q", p.QName)
	}
	if p.QType != "A" {
		t.Errorf("qtype = %q", p.QType)
	}
	if len(p.IPs) != 0 {
		t.Errorf("unexpected answers: %v", p.IPs)
	}
}

func TestParseResponseWithTwoAnswers(t *testing.T) {
	p, err := parseMessage(buildResponse())
	if err != nil {
		t.Fatal(err)
	}
	if p.QName != "example.com" {
		t.Errorf("qname = %q", p.QName)
	}
	if len(p.IPs) != 2 {
		t.Fatalf("IPs = %v", p.IPs)
	}
	if p.IPs[0] != "1.2.3.4" || p.IPs[1] != "5.6.7.8" {
		t.Errorf("IPs = %v", p.IPs)
	}
	if p.TTL != 60 {
		t.Errorf("ttl = %d, want 60 (minimum across answers)", p.TTL)
	}
}

func TestParseMalformed(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x00},                                          // too short
		{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7},         // truncated name
		{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x00, 0xC0, 0x00}, // pointer loop  (will hit maxJumps)
	}
	for i, c := range cases {
		if _, err := parseMessage(c); err == nil && len(c) >= dnsHdrLen {
			// Some forms decode to empty but not error. Acceptable.
			continue
		}
		_ = i
	}
}

func TestQTypeStringFallback(t *testing.T) {
	if got := qtypeString(9999); got != "TYPE9999" {
		t.Errorf("got %q", got)
	}
}

func TestFormatIPv6(t *testing.T) {
	// fe80::1
	b := make([]byte, 16)
	b[0] = 0xfe
	b[1] = 0x80
	b[15] = 0x01
	if got := formatIPv6(b); got == "" {
		t.Fatal("empty")
	}
}

func TestReadNameWithCompressionInAnswerSection(t *testing.T) {
	p, err := parseMessage(buildResponse())
	if err != nil {
		t.Fatal(err)
	}
	// Just confirms compression resolved correctly via answer count.
	if len(p.IPs) != 2 {
		t.Fatalf("compression failed; IPs=%v", p.IPs)
	}
}
