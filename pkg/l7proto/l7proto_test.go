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
		want        Proto
	}{
		{"https-sni", "tcp", 443, "api.example.com", "", nil, "", ProtoHTTPS},
		{"http-reqline", "tcp", 80, "", "GET / HTTP/1.1", nil, "", ProtoHTTP},
		{"http2-preface", "tcp", 443, "x.example.com", "", h2preface, "", ProtoHTTP2},
		{"http2-alpn", "tcp", 443, "x.example.com", "", nil, "h2", ProtoHTTP2},
		{"grpc-alpn", "tcp", 443, "svc.internal", "", nil, "grpc", ProtoGRPC},
		{"ssh", "tcp", 22, "", "", nil, "", ProtoSSH},
		{"dns-udp", "udp", 53, "", "", nil, "", ProtoDNS},
		{"quic-udp443", "udp", 443, "", "", nil, "", ProtoQUIC},
		{"tls-other", "tcp", 443, "", "", nil, "", ProtoTLSOther},
		{"raw", "tcp", 9999, "", "", nil, "", ProtoRaw},
	}
	for _, c := range cases {
		got := Classify(Signals{L4: c.l4, DstPort: c.dstPort, SNI: c.sni, HTTPRequestLine: c.httpReqLine, PayloadPrefix: c.payload, ALPN: c.alpn})
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
