// Package dpi performs deep packet inspection on captured frames.
// Current scope: TLS ClientHello SNI extraction. The parser walks
// the TLS record layer and the handshake message defensively — any
// malformed input returns ok=false with no allocation surprises.
//
// References (public protocol specs only):
//   RFC 5246 §6.2 (TLS record layer)
//   RFC 8446 §4 (handshake)
//   RFC 6066 §3 (server_name extension)
package dpi

import "encoding/binary"

// ParseClientHelloSNI walks a TCP-payload byte slice and returns the
// SNI hostname if it contains a TLS ClientHello with a server_name
// extension. Returns ok=false on any unexpected shape; never panics.
//
// Caller should pass at least the first ~512 bytes of the first
// application-data segment of a new TCP connection. Larger inputs
// are fine — we read only what we need.
func ParseClientHelloSNI(buf []byte) (host string, ok bool) {
	// TLS record layer: type(1) + version(2) + length(2)
	if len(buf) < 5 {
		return "", false
	}
	if buf[0] != 0x16 { // ContentType handshake
		return "", false
	}
	// We accept any TLS version byte; some clients send 0x0301 in the
	// record-layer version even when negotiating TLS 1.3.
	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if recLen < 4 || 5+recLen > len(buf) {
		// We don't strictly need the full record — the ClientHello
		// fits within ~512 bytes for almost everyone, and the SNI
		// extension lives near the start. Don't fail just because
		// the record claims more bytes than we have; cap to what we got.
		recLen = len(buf) - 5
		if recLen < 4 {
			return "", false
		}
	}
	body := buf[5 : 5+recLen]

	// Handshake: msg_type(1) + length(3)
	if body[0] != 0x01 { // ClientHello
		return "", false
	}
	// handshake length is body[1..4] big-endian 24-bit
	if len(body) < 4 {
		return "", false
	}
	off := 4
	// client_version(2) + random(32)
	if off+34 > len(body) {
		return "", false
	}
	off += 34
	// session_id: u8 len + bytes
	if off >= len(body) {
		return "", false
	}
	sidLen := int(body[off])
	off++
	if off+sidLen > len(body) {
		return "", false
	}
	off += sidLen
	// cipher_suites: u16 len + bytes
	if off+2 > len(body) {
		return "", false
	}
	csLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if off+csLen > len(body) {
		return "", false
	}
	off += csLen
	// compression_methods: u8 len + bytes
	if off+1 > len(body) {
		return "", false
	}
	cmLen := int(body[off])
	off++
	if off+cmLen > len(body) {
		return "", false
	}
	off += cmLen
	// extensions: u16 len + bytes
	if off+2 > len(body) {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2
	if off+extLen > len(body) {
		// truncated — still try the bit we have
		extLen = len(body) - off
	}
	exts := body[off : off+extLen]

	// Walk extensions looking for type 0x0000 (server_name).
	i := 0
	for i+4 <= len(exts) {
		eType := binary.BigEndian.Uint16(exts[i:])
		eLen := int(binary.BigEndian.Uint16(exts[i+2:]))
		i += 4
		if i+eLen > len(exts) {
			return "", false
		}
		if eType == 0x0000 {
			return parseSNIExtension(exts[i : i+eLen])
		}
		i += eLen
	}
	return "", false
}

// parseSNIExtension decodes the body of a server_name extension.
// Shape (RFC 6066): u16 list-length, then entries of {u8 name_type,
// u16 host-length, host-bytes}. We use the first host_name (type 0).
func parseSNIExtension(b []byte) (string, bool) {
	if len(b) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(b))
	if listLen+2 > len(b) {
		return "", false
	}
	rest := b[2 : 2+listLen]
	i := 0
	for i+3 <= len(rest) {
		nameType := rest[i]
		nameLen := int(binary.BigEndian.Uint16(rest[i+1:]))
		i += 3
		if i+nameLen > len(rest) {
			return "", false
		}
		if nameType == 0 && nameLen > 0 {
			return string(rest[i : i+nameLen]), true
		}
		i += nameLen
	}
	return "", false
}
