// Package ja3 parses TLS ClientHello bytes and produces JA3 +
// JA4 fingerprints — process-agnostic identifiers of the TLS
// stack a client uses.
//
// Why it matters: malware C2 over TLS is unreadable by content
// (encrypted), but the *handshake* still leaks the implementation
// (Go crypto/tls vs Boringssl vs NSS vs custom). Cobalt Strike's
// default Go HTTP client has a distinct JA3; commodity stagers
// using openssl-binary defaults have another. Operators block or
// alert by fingerprint without ever decrypting payload.
//
// JA3 (Salesforce 2017):
//
//	MD5( SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats )
//
// JA4 (FoxIO 2023): newer, more granular; we emit the JA4 string
// without the cipher-sorted hash variants (JA4_A, JA4_B, JA4_C):
//
//	JA4 = [t/q][version][SNI?d/i][cipher-count][ext-count][alpn]_
//	      hash12(sorted-ciphers)_hash12(sorted-exts,SignatureAlgs)
//
// Pure-Go: encoding/binary + crypto/md5 + crypto/sha256 only.
package ja3

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Fingerprint is the parsed-and-fingerprinted result.
type Fingerprint struct {
	JA3       string // canonical "771,4865-4866,...,29-23,0" form
	JA3Hash   string // MD5 hex of JA3
	JA4       string // canonical JA4 string
	SNI       string // server_name extension, when present
	ALPN      []string
	TLSVersion uint16
}

// errBadHello is returned for truncated or malformed messages.
var errBadHello = errors.New("ja3: malformed or non-ClientHello bytes")

// GREASE values per RFC 8701 — ignored by JA3/JA4.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// Parse takes the raw bytes of a TLS record carrying a
// ClientHello and returns the parsed Fingerprint. The input must
// start at the TLS record header (`0x16 0x03 0x0X len_hi len_lo
// 0x01 ...`).
func Parse(record []byte) (Fingerprint, error) {
	// TLS record header: type(1) version(2) length(2)
	if len(record) < 5 {
		return Fingerprint{}, errBadHello
	}
	if record[0] != 0x16 { // handshake
		return Fingerprint{}, errBadHello
	}
	// Strip record header
	hs := record[5:]
	if len(hs) < 4 {
		return Fingerprint{}, errBadHello
	}
	if hs[0] != 0x01 { // ClientHello
		return Fingerprint{}, errBadHello
	}
	// Handshake header: type(1) length(3)
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	body := hs[4:]
	if hsLen > len(body) {
		hsLen = len(body)
	}
	body = body[:hsLen]
	return parseClientHello(body)
}

// ParseRaw takes the ClientHello handshake body directly (without
// the TLS record header or the 4-byte handshake header). Useful
// when the caller has already peeled those layers.
func ParseRaw(body []byte) (Fingerprint, error) {
	return parseClientHello(body)
}

func parseClientHello(b []byte) (Fingerprint, error) {
	if len(b) < 2+32+1 {
		return Fingerprint{}, errBadHello
	}
	offset := 0
	tlsVer := binary.BigEndian.Uint16(b[offset : offset+2])
	offset += 2
	// Random (32) + session_id_len (1) + session_id (n)
	offset += 32
	if offset >= len(b) {
		return Fingerprint{}, errBadHello
	}
	sidLen := int(b[offset])
	offset++
	offset += sidLen
	if offset+2 > len(b) {
		return Fingerprint{}, errBadHello
	}

	// Cipher suites
	csLen := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	if offset+csLen > len(b) || csLen%2 != 0 {
		return Fingerprint{}, errBadHello
	}
	ciphers := make([]uint16, 0, csLen/2)
	for i := 0; i < csLen; i += 2 {
		v := binary.BigEndian.Uint16(b[offset+i : offset+i+2])
		if !greaseValues[v] {
			ciphers = append(ciphers, v)
		}
	}
	offset += csLen

	// Compression methods
	if offset >= len(b) {
		return Fingerprint{}, errBadHello
	}
	compLen := int(b[offset])
	offset++
	offset += compLen

	// Extensions (length-prefixed)
	var (
		extIDs       []uint16
		curves       []uint16
		ecFormats    []uint8
		sigAlgs      []uint16
		alpn         []string
		sni          string
	)
	if offset+2 <= len(b) {
		extTotal := int(binary.BigEndian.Uint16(b[offset : offset+2]))
		offset += 2
		end := offset + extTotal
		if end > len(b) {
			end = len(b)
		}
		for offset+4 <= end {
			extType := binary.BigEndian.Uint16(b[offset : offset+2])
			extLen := int(binary.BigEndian.Uint16(b[offset+2 : offset+4]))
			offset += 4
			if offset+extLen > end {
				break
			}
			extBody := b[offset : offset+extLen]
			offset += extLen
			if greaseValues[extType] {
				continue
			}
			extIDs = append(extIDs, extType)
			switch extType {
			case 0x0000: // server_name
				sni = parseSNI(extBody)
			case 0x000a: // supported_groups / elliptic curves
				curves = parseUint16Vec(extBody)
				curves = filterGreaseU16(curves)
			case 0x000b: // ec_point_formats
				ecFormats = parseUint8Vec(extBody)
			case 0x000d: // signature_algorithms
				sigAlgs = parseUint16Vec(extBody)
				sigAlgs = filterGreaseU16(sigAlgs)
			case 0x0010: // ALPN
				alpn = parseALPN(extBody)
			}
		}
	}

	// JA3 canonical string
	ja3 := buildJA3(tlsVer, ciphers, extIDs, curves, ecFormats)
	sum := md5.Sum([]byte(ja3))
	ja3Hash := hex.EncodeToString(sum[:])

	ja4 := buildJA4(tlsVer, sni, ciphers, extIDs, sigAlgs, alpn)

	return Fingerprint{
		JA3:        ja3,
		JA3Hash:    ja3Hash,
		JA4:        ja4,
		SNI:        sni,
		ALPN:       alpn,
		TLSVersion: tlsVer,
	}, nil
}

// ── helpers ───────────────────────────────────────────────────

func parseUint16Vec(b []byte) []uint16 {
	if len(b) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if n+2 > len(b) || n%2 != 0 {
		return nil
	}
	out := make([]uint16, n/2)
	for i := 0; i < n; i += 2 {
		out[i/2] = binary.BigEndian.Uint16(b[2+i : 2+i+2])
	}
	return out
}

func parseUint8Vec(b []byte) []uint8 {
	if len(b) < 1 {
		return nil
	}
	n := int(b[0])
	if n+1 > len(b) {
		return nil
	}
	out := make([]uint8, n)
	copy(out, b[1:1+n])
	return out
}

func parseSNI(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	// list_len(2) + entry_type(1) + name_len(2) + name
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	if listLen+2 > len(b) {
		return ""
	}
	if b[2] != 0x00 { // host_name
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+nameLen > len(b) {
		return ""
	}
	return string(b[5 : 5+nameLen])
}

func parseALPN(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	end := 2 + listLen
	if end > len(b) {
		end = len(b)
	}
	var out []string
	for i := 2; i < end; {
		if i >= len(b) {
			break
		}
		l := int(b[i])
		i++
		if i+l > len(b) {
			break
		}
		out = append(out, string(b[i:i+l]))
		i += l
	}
	return out
}

func filterGreaseU16(in []uint16) []uint16 {
	out := in[:0]
	for _, v := range in {
		if !greaseValues[v] {
			out = append(out, v)
		}
	}
	return out
}

func buildJA3(ver uint16, ciphers, exts, curves []uint16, ecFmts []uint8) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d,", ver)
	sb.WriteString(joinU16(ciphers, "-"))
	sb.WriteString(",")
	sb.WriteString(joinU16(exts, "-"))
	sb.WriteString(",")
	sb.WriteString(joinU16(curves, "-"))
	sb.WriteString(",")
	sb.WriteString(joinU8(ecFmts, "-"))
	return sb.String()
}

func buildJA4(ver uint16, sni string, ciphers, exts, sigAlgs []uint16, alpn []string) string {
	// JA4 format (simplified): t<ver-short>[d|i][cipher-count][ext-count][alpn-first2]_<hash12-ciphers>_<hash12-exts+sigalgs>
	verShort := tlsVerShort(ver)
	sniFlag := "i"
	if sni != "" {
		sniFlag = "d"
	}
	cipCount := minInt(len(ciphers), 99)
	extCount := minInt(len(exts), 99)
	alpnFirst := "00"
	if len(alpn) > 0 && len(alpn[0]) >= 2 {
		alpnFirst = alpn[0][:2]
	}

	// Sort ciphers + exts; hash truncated to 12 hex.
	cs := append([]uint16(nil), ciphers...)
	sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
	hCipher := hashTrunc12(joinU16(cs, ","))

	es := append([]uint16(nil), exts...)
	sort.Slice(es, func(i, j int) bool { return es[i] < es[j] })
	sa := append([]uint16(nil), sigAlgs...)
	sort.Slice(sa, func(i, j int) bool { return sa[i] < sa[j] })
	hExt := hashTrunc12(joinU16(es, ",") + "_" + joinU16(sa, ","))

	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s",
		verShort, sniFlag, cipCount, extCount, alpnFirst,
		hCipher, hExt,
	)
}

func tlsVerShort(v uint16) string {
	switch v {
	case 0x0301:
		return "10"
	case 0x0302:
		return "11"
	case 0x0303:
		return "12"
	case 0x0304:
		return "13"
	}
	return "00"
}

func hashTrunc12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:6])
}

func joinU16(vs []uint16, sep string) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func joinU8(vs []uint8, sep string) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
