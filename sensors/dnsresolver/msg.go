package dnsresolver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Minimal DNS message reader. Only the subset xhelix needs:
//   - decode the question (qname, qtype)
//   - decode A / AAAA answers (rdata = 4 / 16 bytes)
// Everything else (CNAME, MX, SRV, NSEC, OPT, etc.) is parsed for
// length and skipped. DNS name compression is handled.
//
// We don't construct or sign messages — the forwarder copies the
// query payload to the upstream verbatim, and the response payload
// back to the client verbatim. Decoding is read-only and only used
// to extract qname + answer IPs for Observation emission.

// dnsHeader is 12 bytes at the front of every DNS message.
type dnsHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

const dnsHdrLen = 12

// errMalformed is returned on any truncated or bad-pointer message.
var errMalformed = errors.New("dnsresolver: malformed DNS message")

// parsed holds the extracted summary of a DNS message.
type parsed struct {
	QName string
	QType string
	IPs   []string
	TTL   uint32 // minimum TTL across A/AAAA records, 0 if no answers
}

// parseMessage parses one DNS UDP datagram.
func parseMessage(buf []byte) (parsed, error) {
	var out parsed
	if len(buf) < dnsHdrLen {
		return out, errMalformed
	}
	h := dnsHeader{
		ID:      binary.BigEndian.Uint16(buf[0:2]),
		Flags:   binary.BigEndian.Uint16(buf[2:4]),
		QDCount: binary.BigEndian.Uint16(buf[4:6]),
		ANCount: binary.BigEndian.Uint16(buf[6:8]),
		NSCount: binary.BigEndian.Uint16(buf[8:10]),
		ARCount: binary.BigEndian.Uint16(buf[10:12]),
	}

	off := dnsHdrLen

	// Question section. We expect exactly one question; if there
	// are zero (some answer-only packets) or more than one, fall
	// through with empty QName.
	if h.QDCount >= 1 {
		name, n, err := readName(buf, off)
		if err != nil {
			return out, err
		}
		off += n
		if off+4 > len(buf) {
			return out, errMalformed
		}
		qtype := binary.BigEndian.Uint16(buf[off : off+2])
		off += 4 // qtype(2) + qclass(2)
		out.QName = name
		out.QType = qtypeString(qtype)
	}

	// Answer section. Skip remaining QDCount-1 questions if any.
	for i := uint16(1); i < h.QDCount; i++ {
		_, n, err := readName(buf, off)
		if err != nil {
			return out, err
		}
		off += n + 4
	}

	minTTL := uint32(0)
	for i := uint16(0); i < h.ANCount; i++ {
		_, n, err := readName(buf, off)
		if err != nil {
			return out, err
		}
		off += n
		// type(2) class(2) ttl(4) rdlength(2) rdata(rdlength)
		if off+10 > len(buf) {
			return out, errMalformed
		}
		rrType := binary.BigEndian.Uint16(buf[off : off+2])
		ttl := binary.BigEndian.Uint32(buf[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
		off += 10
		if off+rdlen > len(buf) {
			return out, errMalformed
		}
		switch rrType {
		case 1: // A
			if rdlen == 4 {
				out.IPs = append(out.IPs, fmt.Sprintf("%d.%d.%d.%d",
					buf[off], buf[off+1], buf[off+2], buf[off+3]))
				if minTTL == 0 || ttl < minTTL {
					minTTL = ttl
				}
			}
		case 28: // AAAA
			if rdlen == 16 {
				out.IPs = append(out.IPs, formatIPv6(buf[off:off+16]))
				if minTTL == 0 || ttl < minTTL {
					minTTL = ttl
				}
			}
		}
		off += rdlen
	}
	out.TTL = minTTL
	return out, nil
}

// readName decodes a DNS name starting at off, returning the dotted
// representation and the number of bytes consumed *from off* (i.e.
// not counting bytes reached via compression jumps).
//
// We follow up to 32 compression pointers to defend against loops.
func readName(buf []byte, off int) (string, int, error) {
	const maxJumps = 32
	var parts []string
	jumps := 0
	consumed := -1 // length when we return to the caller, set on first pointer

	cur := off
	for {
		if cur >= len(buf) {
			return "", 0, errMalformed
		}
		l := int(buf[cur])
		switch {
		case l == 0:
			cur++
			if consumed < 0 {
				consumed = cur - off
			}
			return strings.Join(parts, "."), consumed, nil
		case l&0xC0 == 0xC0: // compression pointer
			if cur+1 >= len(buf) {
				return "", 0, errMalformed
			}
			ptr := int(binary.BigEndian.Uint16(buf[cur:cur+2])) & 0x3FFF
			cur += 2
			if consumed < 0 {
				consumed = cur - off
			}
			jumps++
			if jumps > maxJumps {
				return "", 0, errMalformed
			}
			cur = ptr
		case l&0xC0 == 0: // normal label
			cur++
			if cur+l > len(buf) {
				return "", 0, errMalformed
			}
			parts = append(parts, string(buf[cur:cur+l]))
			cur += l
		default:
			return "", 0, errMalformed
		}
	}
}

func qtypeString(t uint16) string {
	switch t {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 35:
		return "NAPTR"
	case 41:
		return "OPT"
	case 65:
		return "HTTPS"
	}
	return fmt.Sprintf("TYPE%d", t)
}

func formatIPv6(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	// Stdlib net.IP{}.String() does best-effort collapsing. We
	// avoid importing net in this file to keep msg.go side-effect
	// free; the manual form below is fine for record-string use.
	var parts [8]string
	for i := 0; i < 8; i++ {
		parts[i] = fmt.Sprintf("%x", binary.BigEndian.Uint16(b[i*2:i*2+2]))
	}
	return strings.Join(parts[:], ":")
}
