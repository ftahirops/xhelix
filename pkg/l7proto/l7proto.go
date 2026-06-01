// Package l7proto classifies an egress flow's application-layer protocol
// from cheap, already-captured signals (dst port, TLS SNI presence, the
// HTTP request-line / HTTP-2 preface from the SSL uprobe, ALPN, L4). It is
// a pure heuristic: where signals are absent it falls back to port
// inference and finally ProtoRaw. Encrypted/partial-byte classification is
// best-effort — callers should treat low-confidence labels accordingly.
package l7proto

import (
	"bytes"
	"strings"
)

type Proto string

const (
	ProtoHTTPS    Proto = "https"
	ProtoHTTP     Proto = "http"
	ProtoHTTP2    Proto = "http2"
	ProtoGRPC     Proto = "grpc"
	ProtoSSH      Proto = "ssh"
	ProtoDNS      Proto = "dns"
	ProtoQUIC     Proto = "quic"
	ProtoUDPOther Proto = "udp-other"
	ProtoTLSOther Proto = "tls-other"
	ProtoRaw      Proto = "raw"
)

// Signals are the inputs to Classify. All optional; zero values are "unknown".
type Signals struct {
	L4              string // "tcp" | "udp"
	DstPort         uint16
	SNI             string
	ALPN            string // "h2","grpc","http/1.1",... (EO.5b)
	HTTPRequestLine string // from SSL uprobe (decrypted)
	PayloadPrefix   []byte // first decrypted bytes (HTTP/2 preface etc.)
	// QUICConfirmed is set by the EO.5c eBPF peek when the UDP/443
	// payload carries a QUIC long-header + known version. Without it,
	// UDP/443 is labeled udp-other (not a false "quic" port guess).
	QUICConfirmed bool
}

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// Classify returns the best-effort L7 protocol for a flow.
func Classify(s Signals) Proto {
	switch strings.ToLower(s.ALPN) {
	case "grpc":
		return ProtoGRPC
	case "h2", "h2c":
		return ProtoHTTP2
	case "http/1.1", "http/1.0":
		// fall through to HTTP/HTTPS resolution below
	}
	if len(s.PayloadPrefix) >= len(http2Preface) && bytes.Equal(s.PayloadPrefix[:len(http2Preface)], http2Preface) {
		return ProtoHTTP2
	}
	if s.HTTPRequestLine != "" {
		if s.DstPort == 443 || s.SNI != "" {
			return ProtoHTTPS
		}
		return ProtoHTTP
	}
	if s.L4 == "udp" {
		switch s.DstPort {
		case 53:
			return ProtoDNS
		case 443:
			// quic ONLY when the eBPF peek confirmed a QUIC long-header
			// (EO.5c); otherwise it's unconfirmed UDP/443, not a guess.
			if s.QUICConfirmed {
				return ProtoQUIC
			}
			return ProtoUDPOther
		}
		return ProtoUDPOther
	}
	switch s.DstPort {
	case 22:
		return ProtoSSH
	case 53:
		return ProtoDNS
	case 80, 8080:
		return ProtoHTTP
	}
	if s.SNI != "" {
		return ProtoHTTPS
	}
	if s.DstPort == 443 || s.DstPort == 8443 {
		return ProtoTLSOther
	}
	return ProtoRaw
}
