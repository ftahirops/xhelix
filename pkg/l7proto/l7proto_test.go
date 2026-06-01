package l7proto

import "testing"

func TestClassify(t *testing.T) {
	h2preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	cases := []struct {
		name        string
		l4          string
		dstPort     uint16
		sni         string
		httpReqLine string
		payload     []byte
		alpn        string
		quic        bool
		want        Proto
	}{
		{"https-sni", "tcp", 443, "api.example.com", "", nil, "", false, ProtoHTTPS},
		{"http-reqline", "tcp", 80, "", "GET / HTTP/1.1", nil, "", false, ProtoHTTP},
		{"http2-preface", "tcp", 443, "x.example.com", "", h2preface, "", false, ProtoHTTP2},
		{"http2-alpn", "tcp", 443, "x.example.com", "", nil, "h2", false, ProtoHTTP2},
		{"grpc-alpn", "tcp", 443, "svc.internal", "", nil, "grpc", false, ProtoGRPC},
		{"ssh", "tcp", 22, "", "", nil, "", false, ProtoSSH},
		{"dns-udp", "udp", 53, "", "", nil, "", false, ProtoDNS},
		{"quic-udp443-confirmed", "udp", 443, "", "", nil, "", true, ProtoQUIC},
		{"udp443-unconfirmed", "udp", 443, "", "", nil, "", false, ProtoUDPOther},
		{"quic-confirmed-no-l4", "", 0, "", "", nil, "", true, ProtoQUIC},
		{"udp-other-port", "udp", 1234, "", "", nil, "", false, ProtoUDPOther},
		{"tls-other", "tcp", 443, "", "", nil, "", false, ProtoTLSOther},
		{"raw", "tcp", 9999, "", "", nil, "", false, ProtoRaw},
	}
	for _, c := range cases {
		got := Classify(Signals{L4: c.l4, DstPort: c.dstPort, SNI: c.sni, HTTPRequestLine: c.httpReqLine, PayloadPrefix: c.payload, ALPN: c.alpn, QUICConfirmed: c.quic})
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
