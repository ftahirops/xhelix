// Package fastcgi is the coarse FastCGI request adapter for the L7 per-request
// root emitter. Given the leading bytes php-fpm receives on a FastCGI
// connection, it extracts the request identity (method, URI, host, script) and
// the FastCGI requestId from BEGIN_REQUEST + PARAMS records — WITHOUT a full
// FastCGI server implementation.
//
// Honest limit: COARSE by construction. It reads the leading bytes of one recv,
// walks record headers, and extracts a fixed set of PARAMS keys. It does not
// reassemble multi-recv PARAMS streams or STDIN bodies.
package fastcgi

const (
	typeBeginRequest = 1
	typeParams       = 4
)

// Result is the coarse per-request classification of a FastCGI request.
type Result struct {
	RequestID      uint16
	IsBeginRequest bool
	Method         string
	URI            string
	Host           string // HTTP_HOST
	ServerName     string // SERVER_NAME (nginx vhost) — host fallback
	Script         string
}

// IsFastCGI reports whether b begins with a plausible v1 FastCGI record header
// of a known type. Cheap gate for the eBPF-capture decode path.
func IsFastCGI(b []byte) bool {
	if len(b) < 8 || b[0] != 1 {
		return false
	}
	switch b[1] {
	case typeBeginRequest, typeParams, 5 /*STDIN*/, 9 /*GET_VALUES*/ :
		return true
	}
	return false
}

// Parse walks the FastCGI records in b, recognizing BEGIN_REQUEST (request
// boundary) and PARAMS (identity). Returns (Result, true) when at least one such
// record was recognized. Best-effort and panic-free on truncated input.
func Parse(b []byte) (Result, bool) {
	var r Result
	var recognized bool
	off := 0
	for off+8 <= len(b) {
		if b[off] != 1 { // version must be 1
			break
		}
		typ := b[off+1]
		reqID := uint16(b[off+2])<<8 | uint16(b[off+3])
		contentLen := int(b[off+4])<<8 | int(b[off+5])
		padLen := int(b[off+6])
		contentStart := off + 8
		contentEnd := contentStart + contentLen
		if contentEnd > len(b) {
			contentEnd = len(b) // truncated: parse what we have
		}
		switch typ {
		case typeBeginRequest:
			r.IsBeginRequest = true
			r.RequestID = reqID
			recognized = true
		case typeParams:
			r.RequestID = reqID
			parseParams(b[contentStart:contentEnd], &r)
			recognized = true
		}
		next := contentEnd + padLen
		if next <= off { // no forward progress (malformed) — stop
			break
		}
		off = next
	}
	return r, recognized
}

// parseParams walks FastCGI name-value pairs and fills the identity fields.
func parseParams(b []byte, r *Result) {
	off := 0
	for off < len(b) {
		nameLen, n, ok := readLen(b, off)
		if !ok {
			return
		}
		off += n
		valLen, n, ok := readLen(b, off)
		if !ok {
			return
		}
		off += n
		if off+nameLen+valLen > len(b) {
			return
		}
		name := string(b[off : off+nameLen])
		val := string(b[off+nameLen : off+nameLen+valLen])
		off += nameLen + valLen
		switch name {
		case "REQUEST_METHOD":
			r.Method = val
		case "REQUEST_URI":
			r.URI = val
		case "HTTP_HOST":
			r.Host = val
		case "SERVER_NAME":
			r.ServerName = val
		case "SCRIPT_FILENAME":
			r.Script = val
		}
	}
}

// ParseParams parses a raw FastCGI PARAMS name-value content block — the bytes
// of ONE PARAMS record's content, WITHOUT the 8-byte record header. This is what
// the app-tier recv-side capture emits: php-fpm reads a record's header and its
// content in separate recv() calls, so the captured bytes are the name-value
// pairs directly (not a record stream). Returns (Result, true) when any identity
// field was extracted. Panic-free on truncated/padded input.
func ParseParams(b []byte) (Result, bool) {
	var r Result
	parseParams(b, &r)
	ok := r.Host != "" || r.ServerName != "" || r.URI != "" || r.Method != "" || r.Script != ""
	return r, ok
}

// readLen decodes a FastCGI length field: 1 byte if high bit clear, else 4 bytes
// big-endian with the high bit of the first byte masked off. Returns the length,
// bytes consumed, and ok=false on truncation.
func readLen(b []byte, off int) (length, consumed int, ok bool) {
	if off >= len(b) {
		return 0, 0, false
	}
	if b[off]&0x80 == 0 {
		return int(b[off]), 1, true
	}
	if off+4 > len(b) {
		return 0, 0, false
	}
	return int(b[off]&0x7f)<<24 | int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3]), 4, true
}
