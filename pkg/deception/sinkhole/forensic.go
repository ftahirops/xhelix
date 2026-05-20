// Package sinkhole is the Ring 2 outbound trap. When a protected
// service's forbidden connect() is routed here (via eBPF socket
// redirect, P-PS.7b — next commit), this package speaks plausible
// HTTP / TLS / raw-TCP back to the attacker's C2 client framing
// while harvesting every byte into the evidence chain.
//
// Goals (PROTECTED_SERVICES_TRAP.md §4.2):
//   - Attacker's C2 framing parses successfully (their malware
//     reports "phone home OK") so they keep talking
//   - Their actual C2 server sees zero callbacks
//   - We get the full beacon protocol: tasking format, encryption
//     handshake, JA3/JA4 fingerprint, every payload
//   - Cost-asymmetry: 50-500ms per response, attacker burns minutes
//
// Pure Go, CGO_ENABLED=0. Standard library only (crypto/tls,
// net/http, encoding/json).
package sinkhole

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"sync"
	"time"
)

// Logger receives sinkhole events. Implementations push them into
// the evidence chain (P-PS.11) or stdout JSON during local testing.
// All methods MUST be safe for concurrent calls.
type Logger interface {
	OnBeaconStart(meta BeaconMeta)
	OnBeaconData(d BeaconData)
	OnBeaconResponse(r BeaconResponse)
	OnBeaconEnd(e BeaconEnd)
}

// BeaconMeta is emitted once when a connection arrives.
type BeaconMeta struct {
	BeaconID   string    `json:"beacon_id"`
	StartedAt  time.Time `json:"started_at"`
	LocalAddr  string    `json:"local_addr"`
	PeerAddr   string    `json:"peer_addr"`
	Protocol   string    `json:"protocol"` // "http", "tls", "raw"

	// TLS-specific (populated post-handshake).
	SNI      string   `json:"sni,omitempty"`
	ALPN     string   `json:"alpn,omitempty"`
	JA3      string   `json:"ja3,omitempty"`
	JA3Hash  string   `json:"ja3_hash,omitempty"`

	// Attribution. Populated when the redirect knows the source.
	OriginalDestIP   string `json:"original_dest_ip,omitempty"`
	OriginalDestPort uint16 `json:"original_dest_port,omitempty"`
	ServiceName      string `json:"service_name,omitempty"`
	LineageID        uint64 `json:"lineage_id,omitempty"`
}

// BeaconData is emitted for each chunk of attacker-sent bytes. The
// raw payload is included verbatim (capped to MaxPayloadBytes per
// emission); the full byte stream is also written to the connection
// buffer for forensic replay.
type BeaconData struct {
	BeaconID string    `json:"beacon_id"`
	At       time.Time `json:"at"`
	Sequence int       `json:"sequence"`
	Length   int       `json:"length"`
	Payload  string    `json:"payload"` // hex if non-text, else as-is up to cap
	IsText   bool      `json:"is_text"`
	Sha256   string    `json:"sha256"`

	// Parsed indicators if we recognized the framing. Populated
	// by the protocol handler.
	HTTPMethod string `json:"http_method,omitempty"`
	HTTPHost   string `json:"http_host,omitempty"`
	HTTPPath   string `json:"http_path,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// BeaconResponse is emitted when we send bytes back.
type BeaconResponse struct {
	BeaconID string        `json:"beacon_id"`
	At       time.Time     `json:"at"`
	Sequence int           `json:"sequence"`
	Length   int           `json:"length"`
	Latency  time.Duration `json:"latency"`
	Status   string        `json:"status,omitempty"` // HTTP-only ("200 OK")
}

// BeaconEnd is emitted once when the connection closes.
type BeaconEnd struct {
	BeaconID    string        `json:"beacon_id"`
	EndedAt     time.Time     `json:"ended_at"`
	Duration    time.Duration `json:"duration"`
	BytesRecv   int64         `json:"bytes_recv"`
	BytesSent   int64         `json:"bytes_sent"`
	Exchanges   int           `json:"exchanges"`
	CloseReason string        `json:"close_reason"`
}

// MaxPayloadBytes caps the inline payload in a single BeaconData.
// Larger payloads are SHA-256'd and truncated; the full content
// goes to the connection's separate forensic buffer.
const MaxPayloadBytes = 4096

// --- helpers ---

// classifyAndEncode returns (encoded, isText, sha256-hex). Text-y
// payloads stay as plain string; binary gets hex-encoded.
func classifyAndEncode(b []byte) (string, bool, string) {
	sum := sha256.Sum256(b)
	hexSum := hex.EncodeToString(sum[:])
	truncated := b
	if len(truncated) > MaxPayloadBytes {
		truncated = truncated[:MaxPayloadBytes]
	}
	if isMostlyText(truncated) {
		return string(truncated), true, hexSum
	}
	return hex.EncodeToString(truncated), false, hexSum
}

func isMostlyText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*4 >= len(b)*3 // ≥75% printable
}

// JSONLLogger writes one JSON object per event to w. Test+
// production-friendly.
type JSONLLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewJSONLLogger wraps an io.Writer. Caller owns the writer's lifecycle.
func NewJSONLLogger(w io.Writer) *JSONLLogger { return &JSONLLogger{w: w} }

type wireRecord struct {
	Type string      `json:"type"`
	Body interface{} `json:"body"`
}

func (l *JSONLLogger) emit(typ string, body interface{}) {
	rec := wireRecord{Type: typ, Body: body}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(append(b, '\n'))
}

func (l *JSONLLogger) OnBeaconStart(m BeaconMeta)        { l.emit("beacon_start", m) }
func (l *JSONLLogger) OnBeaconData(d BeaconData)          { l.emit("beacon_data", d) }
func (l *JSONLLogger) OnBeaconResponse(r BeaconResponse)  { l.emit("beacon_response", r) }
func (l *JSONLLogger) OnBeaconEnd(e BeaconEnd)            { l.emit("beacon_end", e) }

// noopLogger is the silent default.
type noopLogger struct{}

func (noopLogger) OnBeaconStart(BeaconMeta)       {}
func (noopLogger) OnBeaconData(BeaconData)         {}
func (noopLogger) OnBeaconResponse(BeaconResponse) {}
func (noopLogger) OnBeaconEnd(BeaconEnd)           {}

// remoteAddrToStr robustly serializes a net.Addr, including
// "<nil>" if nil — used in BeaconMeta and tests.
func remoteAddrToStr(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
