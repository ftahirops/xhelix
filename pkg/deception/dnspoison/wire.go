package dnspoison

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Minimal DNS wire-format read/write. RFC 1035 plus a handful of
// later extensions (we recognize EDNS0 OPT records but ignore most
// of them — sufficient for the question section we care about).
//
// We intentionally do NOT implement compression-pointer writing —
// our responses always use full names. Reading a question with
// compressed names works (RFC 1035 §4.1.4).

type message struct {
	id       uint16
	flags    uint16
	question dnsName
	qtype    uint16
	qclass   uint16
}

type dnsName struct {
	labels []string
}

func (n dnsName) String() string {
	return strings.Join(n.labels, ".")
}

// parseQuery decodes the first question from a DNS query packet.
// Returns just enough to classify + reply; ignores any AR/AN/NS
// sections (typically empty in queries anyway).
func parseQuery(b []byte) (*message, error) {
	if len(b) < 12 {
		return nil, errors.New("dnspoison: short header")
	}
	m := &message{
		id:    binary.BigEndian.Uint16(b[0:2]),
		flags: binary.BigEndian.Uint16(b[2:4]),
	}
	qdcount := binary.BigEndian.Uint16(b[4:6])
	if qdcount == 0 {
		return nil, errors.New("dnspoison: no question")
	}

	name, off, err := readName(b, 12)
	if err != nil {
		return nil, err
	}
	if off+4 > len(b) {
		return nil, errors.New("dnspoison: short question footer")
	}
	m.question = name
	m.qtype = binary.BigEndian.Uint16(b[off : off+2])
	m.qclass = binary.BigEndian.Uint16(b[off+2 : off+4])
	return m, nil
}

// readName decodes a DNS name with compression-pointer support.
// Returns the labels + the byte offset PAST the name in the
// caller's buffer (when no compression, otherwise +2 for the
// pointer).
func readName(b []byte, off int) (dnsName, int, error) {
	var labels []string
	jumped := false
	end := off
	for safety := 0; safety < 128; safety++ {
		if off >= len(b) {
			return dnsName{}, 0, errors.New("dnspoison: name overrun")
		}
		ln := b[off]
		if ln == 0 {
			if !jumped {
				end = off + 1
			}
			return dnsName{labels: labels}, end, nil
		}
		if ln&0xC0 == 0xC0 {
			// Compression pointer — 14-bit offset into the start of the message.
			if off+1 >= len(b) {
				return dnsName{}, 0, errors.New("dnspoison: short pointer")
			}
			target := int(binary.BigEndian.Uint16(b[off:off+2]) & 0x3FFF)
			if !jumped {
				end = off + 2
				jumped = true
			}
			off = target
			continue
		}
		off++
		if off+int(ln) > len(b) {
			return dnsName{}, 0, errors.New("dnspoison: label overrun")
		}
		labels = append(labels, string(b[off:off+int(ln)]))
		off += int(ln)
	}
	return dnsName{}, 0, errors.New("dnspoison: name loop")
}

// encodeAResponse builds a DNS response packet to the given query
// with one A record pointing to ip (a 4-byte IPv4 address). TTL is
// in seconds. The query bytes are echoed verbatim into the
// question section — saves the encoding work.
func encodeAResponse(query []byte, ip [4]byte, ttl uint32) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("dnspoison: bad query length")
	}
	qcount := binary.BigEndian.Uint16(query[4:6])
	if qcount == 0 {
		return nil, errors.New("dnspoison: query has no question")
	}

	// Find end of the question section.
	_, qend, err := readName(query, 12)
	if err != nil {
		return nil, err
	}
	qend += 4 // qtype + qclass

	out := make([]byte, 0, qend+16)
	out = append(out, query[:qend]...)

	// Overwrite the header for a response: flags QR=1 RA=1, ANCOUNT=1.
	binary.BigEndian.PutUint16(out[2:4], 0x8180) // QR=1, RD=1, RA=1
	binary.BigEndian.PutUint16(out[6:8], 1)      // ANCOUNT=1
	binary.BigEndian.PutUint16(out[8:10], 0)     // NSCOUNT
	binary.BigEndian.PutUint16(out[10:12], 0)    // ARCOUNT

	// Answer: pointer back to QNAME at offset 12 + TYPE A + CLASS IN
	// + TTL + RDLENGTH + RDATA.
	answer := make([]byte, 16)
	binary.BigEndian.PutUint16(answer[0:2], 0xC00C) // ptr to offset 12
	binary.BigEndian.PutUint16(answer[2:4], 1)      // TYPE A
	binary.BigEndian.PutUint16(answer[4:6], 1)      // CLASS IN
	binary.BigEndian.PutUint32(answer[6:10], ttl)
	binary.BigEndian.PutUint16(answer[10:12], 4) // RDLENGTH
	answer[12] = ip[0]
	answer[13] = ip[1]
	answer[14] = ip[2]
	answer[15] = ip[3]

	out = append(out, answer...)
	return out, nil
}

// encodeNXDomain builds an NXDOMAIN response to the query — used
// when poisoning AAAA / CNAME / TXT requests we don't fake.
func encodeNXDomain(query []byte) ([]byte, error) {
	if len(query) < 12 {
		return nil, errors.New("dnspoison: bad query length")
	}
	_, qend, err := readName(query, 12)
	if err != nil {
		return nil, err
	}
	qend += 4

	out := make([]byte, 0, qend)
	out = append(out, query[:qend]...)

	// Flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN).
	binary.BigEndian.PutUint16(out[2:4], 0x8183)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out, nil
}
