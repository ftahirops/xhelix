package sinkhole

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"

	"crypto/tls"
)

// ja3Fingerprint builds an approximation of the JA3 string from a
// ClientHelloInfo. The full JA3 spec
// (https://github.com/salesforce/ja3) requires fields the standard
// library's tls.ClientHelloInfo doesn't expose (cipher suites in
// order, full extension list, elliptic curves, EC point formats), so
// we synthesize a stable fingerprint from what's available:
//
//   <version>,<cipher_suites>,<ALPNs>
//
// Good enough to cluster identical clients (same library, same
// version) without claiming compatibility with the canonical JA3
// tooling. Real JA3 capture lands in P-PS.11 (forensic pipeline)
// where we read the raw ClientHello via a custom listener.
func ja3Fingerprint(hi *tls.ClientHelloInfo) string {
	if hi == nil {
		return ""
	}
	var b strings.Builder
	// TLS version offered (highest from SupportedVersions, or
	// negotiated fallback).
	if len(hi.SupportedVersions) > 0 {
		fmt.Fprintf(&b, "%d", hi.SupportedVersions[0])
	}
	b.WriteByte(',')
	for i, cs := range hi.CipherSuites {
		if i > 0 {
			b.WriteByte('-')
		}
		fmt.Fprintf(&b, "%d", cs)
	}
	b.WriteByte(',')
	for i, proto := range hi.SupportedProtos {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(proto)
	}
	return b.String()
}

// ja3Hash returns the MD5 of the JA3 string (per JA3 convention).
func ja3Hash(ja3 string) string {
	if ja3 == "" {
		return ""
	}
	h := md5.Sum([]byte(ja3))
	return hex.EncodeToString(h[:])
}
