// Package tlsledger captures decoded TLS plaintext from the existing
// eBPF SSL_read/SSL_write uprobes. Disabled by default — operator
// opts in per-binary via Options.AllowedBinaries.
//
// Hard safety rails (built into the package, not the operator's job):
//   - Authorization / Cookie / Set-Cookie / X-Auth-* headers are
//     ALWAYS redacted, regardless of operator config.
//   - JSON bodies have common-secret-field values redacted via a
//     fixed regex (password, token, api_key, etc.).
//   - Body capped at MaxBodyKB per record (default 4 KB).
//   - Ring buffer caps at RingSize entries (default 500); oldest
//     evicted; no persistence to disk.
//   - Every List / Get is fed through the AuditLogger.
//
// This is plaintext OF LOCAL PROCESSES, captured via libssl uprobes
// BEFORE encryption. It is NOT a MITM of traffic passing through
// the host — that would require key extraction we don't do.
package tlsledger

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Record is one decoded TLS read/write event.
type Record struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Binary    string    `json:"binary"`
	PID       uint32    `json:"pid"`
	Direction string    `json:"direction"` // "write" (request) | "read" (response)
	PeerSNI   string    `json:"peer_sni,omitempty"`
	PeerIP    string    `json:"peer_ip,omitempty"`
	PeerPort  uint16    `json:"peer_port,omitempty"`

	HTTPMethod string            `json:"http_method,omitempty"`
	HTTPPath   string            `json:"http_path,omitempty"`
	HTTPStatus int               `json:"http_status,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`

	BodyBytes int    `json:"body_bytes"`
	BodyText  string `json:"body_text"`
	Truncated bool   `json:"truncated"`
}

// Event is the input projection from the eBPF SSL uprobe pipeline.
type Event struct {
	Time      time.Time
	Binary    string
	PID       uint32
	Direction string
	PeerSNI   string
	PeerIP    string
	PeerPort  uint16
	Payload   []byte
}

// ListFilter narrows the records returned by List.
type ListFilter struct {
	Binary        string
	PeerSNI       string
	DirectionSpec string
	Since         time.Time
}

// Stats reports the ledger's runtime counters.
type Stats struct {
	AllowedBinaries   int    `json:"allowed_binaries"`
	Stored            int    `json:"stored"`
	DroppedNotAllowed uint64 `json:"dropped_not_allowed"`
	DroppedNotHTTP    uint64 `json:"dropped_not_http"`
	Observed          uint64 `json:"observed_total"`
}

// AuditLogger receives a record for every operator view. Implementations
// MUST be cheap and non-blocking; the ledger holds its read lock while
// calling LogAccess.
type AuditLogger interface {
	LogAccess(remoteIP, action, recordID, binary string)
}

// DiscardAuditLogger is a no-op AuditLogger used when the audit-log
// file fails to open. Operator gets a daemon warning at startup.
type DiscardAuditLogger struct{}

// LogAccess implements AuditLogger.
func (DiscardAuditLogger) LogAccess(remoteIP, action, recordID, binary string) {}

// Options configures a Ledger. An empty AllowedBinaries list makes
// the ledger dormant — Observe drops every record.
type Options struct {
	AllowedBinaries []string
	MaxBodyKB       int
	RingSize        int
	AuditLogger     AuditLogger
}

// Ledger is the in-memory ring buffer of decoded TLS plaintext records.
type Ledger struct {
	mu        sync.RWMutex
	ring      []Record
	pos       int
	full      bool
	allowed   map[string]bool
	maxBodyKB int

	auditLogger AuditLogger

	// counters
	cntObserved     uint64
	cntNotAllowed   uint64
	cntNotHTTP      uint64
}

// sensitiveHeaders is the FIXED, non-operator-overridable redaction
// set. Adding to it is fine; removing requires a code change.
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-auth-token":        true,
	"x-api-key":           true,
	"x-csrf-token":        true,
	"x-session-id":        true,
}

// jsonSecretKeyRegex matches `"key":"value"` for any sensitive JSON
// key (case-insensitive). Top-level OR nested — the regex is shallow,
// not a parser. Side benefit: works on YAML/JSON-ish payloads that
// aren't strictly valid JSON.
var jsonSecretKeyRegex = regexp.MustCompile(
	`(?i)"(password|passwd|token|api[_-]?key|secret|credentials?|client[_-]?secret|access[_-]?token|refresh[_-]?token|session[_-]?id)"\s*:\s*"([^"]*)"`)

// New returns a Ledger configured by opts. If opts.AllowedBinaries is
// empty, Observe will drop every event — the ledger is dormant.
func New(opts Options) *Ledger {
	if opts.MaxBodyKB <= 0 {
		opts.MaxBodyKB = 4
	}
	if opts.RingSize <= 0 {
		opts.RingSize = 500
	}
	if opts.AuditLogger == nil {
		opts.AuditLogger = DiscardAuditLogger{}
	}
	l := &Ledger{
		ring:        make([]Record, opts.RingSize),
		allowed:     make(map[string]bool, len(opts.AllowedBinaries)),
		maxBodyKB:   opts.MaxBodyKB,
		auditLogger: opts.AuditLogger,
	}
	for _, b := range opts.AllowedBinaries {
		if b = strings.TrimSpace(b); b != "" {
			l.allowed[b] = true
		}
	}
	return l
}

// Observe records one SSL_read or SSL_write plaintext event. Dropped
// silently when the binary is not in the allow list.
func (l *Ledger) Observe(ev Event) {
	atomic.AddUint64(&l.cntObserved, 1)
	if len(ev.Payload) == 0 {
		return
	}
	l.mu.RLock()
	allowed := l.allowed[ev.Binary]
	l.mu.RUnlock()
	if !allowed {
		atomic.AddUint64(&l.cntNotAllowed, 1)
		return
	}

	rec := Record{
		ID:        newID(),
		Time:      ev.Time,
		Binary:    ev.Binary,
		PID:       ev.PID,
		Direction: ev.Direction,
		PeerSNI:   ev.PeerSNI,
		PeerIP:    ev.PeerIP,
		PeerPort:  ev.PeerPort,
	}
	if !l.parseHTTP(ev.Payload, &rec) {
		atomic.AddUint64(&l.cntNotHTTP, 1)
		// Still store the record — operator opted in for this binary;
		// non-HTTP TLS streams (gRPC, custom protocols, raw TLS) are
		// legitimate targets for forensic review. Apply secret-field
		// redaction on the raw bytes treated as text.
		body := redactJSONFields(string(ev.Payload))
		cap := l.maxBodyKB * 1024
		rec.BodyBytes = len(ev.Payload)
		rec.Truncated = len(ev.Payload) > cap
		rec.BodyText = truncateBody(body, cap, len(ev.Payload))
	}

	l.mu.Lock()
	l.ring[l.pos] = rec
	l.pos++
	if l.pos >= len(l.ring) {
		l.pos = 0
		l.full = true
	}
	l.mu.Unlock()
}

// parseHTTP attempts to parse ev as HTTP/1.x request OR response and
// fills the HTTP fields on rec. Returns true on a successful parse;
// false leaves rec.HTTP* zeroed (caller stores raw bytes instead).
func (l *Ledger) parseHTTP(payload []byte, rec *Record) bool {
	br := bufio.NewReader(bytes.NewReader(payload))

	// Probe first line: REQ "METHOD path HTTP/x.y" or RESP "HTTP/x.y CODE".
	first, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return false
	}
	firstTrim := strings.TrimRight(first, "\r\n")

	headers := make(map[string]string)
	isReq := false
	isResp := false

	if strings.HasPrefix(firstTrim, "HTTP/") {
		// response: HTTP/1.1 200 OK
		parts := strings.SplitN(firstTrim, " ", 3)
		if len(parts) < 2 {
			return false
		}
		isResp = true
		var code int
		_, _ = fmt.Sscanf(parts[1], "%d", &code)
		rec.HTTPStatus = code
	} else {
		// request: GET /path HTTP/1.1
		parts := strings.SplitN(firstTrim, " ", 3)
		if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
			return false
		}
		switch parts[0] {
		case "GET", "POST", "PUT", "DELETE", "HEAD",
			"OPTIONS", "PATCH", "CONNECT", "TRACE":
			isReq = true
			rec.HTTPMethod = parts[0]
			rec.HTTPPath = parts[1]
		default:
			return false
		}
	}
	if !isReq && !isResp {
		return false
	}

	// Headers via textproto.
	tp := textproto.NewReader(br)
	mimeHdr, err := tp.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		// truncated headers (uprobe buffer is 256 B); store what we have
		// without failing the parse — the request line was valid.
	}
	for k, vs := range mimeHdr {
		if len(vs) == 0 {
			continue
		}
		canon := http.CanonicalHeaderKey(k)
		val := vs[0]
		if sensitiveHeaders[strings.ToLower(canon)] {
			val = "[REDACTED]"
		}
		headers[canon] = val
	}
	if len(headers) > 0 {
		rec.Headers = headers
	}

	// Remaining bytes after headers are the body.
	bodyBuf := new(bytes.Buffer)
	_, _ = io.Copy(bodyBuf, br)
	rec.BodyBytes = bodyBuf.Len()
	bodyStr := bodyBuf.String()
	bodyStr = redactJSONFields(bodyStr)
	cap := l.maxBodyKB * 1024
	rec.Truncated = rec.BodyBytes > cap
	rec.BodyText = truncateBody(bodyStr, cap, rec.BodyBytes)
	return true
}

// truncateBody clips body to limit bytes and appends a marker when the
// original was longer.
func truncateBody(body string, limit, originalBytes int) string {
	if originalBytes <= limit || len(body) <= limit {
		return body
	}
	return body[:limit] + fmt.Sprintf("\n[...truncated, %d more bytes]", originalBytes-limit)
}

// redactJSONFields walks body and replaces "<sensitive>":"..." values
// with [REDACTED]. Shallow regex — no JSON parser, no recursion.
func redactJSONFields(body string) string {
	return jsonSecretKeyRegex.ReplaceAllString(body, `"$1":"[REDACTED]"`)
}

// List returns up to n most recent records, newest first.
func (l *Ledger) List(n int, filter ListFilter, remoteIP string) []Record {
	l.mu.RLock()
	defer l.mu.RUnlock()
	all := l.snapshotLocked()
	out := make([]Record, 0, n)
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		r := all[i]
		if filter.Binary != "" && !strings.Contains(r.Binary, filter.Binary) {
			continue
		}
		if filter.PeerSNI != "" && !strings.Contains(r.PeerSNI, filter.PeerSNI) {
			continue
		}
		if filter.DirectionSpec != "" && r.Direction != filter.DirectionSpec {
			continue
		}
		if !filter.Since.IsZero() && r.Time.Before(filter.Since) {
			continue
		}
		out = append(out, r)
	}
	l.auditLogger.LogAccess(remoteIP, "list", "", "")
	return out
}

// Get returns one record by ID.
func (l *Ledger) Get(id, remoteIP string) (Record, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, r := range l.snapshotLocked() {
		if r.ID == id {
			l.auditLogger.LogAccess(remoteIP, "get", id, r.Binary)
			return r, true
		}
	}
	l.auditLogger.LogAccess(remoteIP, "get_miss", id, "")
	return Record{}, false
}

// snapshotLocked returns the ring as a flat slice in chronological order.
// Caller must hold l.mu (read or write).
func (l *Ledger) snapshotLocked() []Record {
	if !l.full {
		out := make([]Record, l.pos)
		copy(out, l.ring[:l.pos])
		return out
	}
	out := make([]Record, len(l.ring))
	copy(out, l.ring[l.pos:])
	copy(out[len(l.ring)-l.pos:], l.ring[:l.pos])
	return out
}

// Stats reports current counters.
func (l *Ledger) Stats() Stats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	stored := l.pos
	if l.full {
		stored = len(l.ring)
	}
	return Stats{
		AllowedBinaries:   len(l.allowed),
		Stored:            stored,
		DroppedNotAllowed: atomic.LoadUint64(&l.cntNotAllowed),
		DroppedNotHTTP:    atomic.LoadUint64(&l.cntNotHTTP),
		Observed:          atomic.LoadUint64(&l.cntObserved),
	}
}

// AddAllow adds binary to the per-binary opt-in list at runtime.
func (l *Ledger) AddAllow(binary string) {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return
	}
	l.mu.Lock()
	l.allowed[binary] = true
	l.mu.Unlock()
}

// RemoveAllow removes binary from the per-binary opt-in list.
func (l *Ledger) RemoveAllow(binary string) {
	l.mu.Lock()
	delete(l.allowed, binary)
	l.mu.Unlock()
}

// AllowList returns the current per-binary opt-in list.
func (l *Ledger) AllowList() []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]string, 0, len(l.allowed))
	for b := range l.allowed {
		out = append(out, b)
	}
	return out
}

// newID returns an opaque 8-byte hex ID for a record. Cryptographic
// randomness isn't required — uniqueness across the 500-entry ring is.
func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
