package synth

import (
	"sort"
	"strings"
)

// ExecEnvelope is the candidate ExecAllowed set: the distinct exec exemplar
// raws (already sorted+deduped by Gather).
func ExecEnvelope(o Observed) []string {
	out := append([]string(nil), o.ExecRaws...)
	return out
}

// hostFromEgressKey extracts the host portion from a recorder egress key.
// Keys are stored as bare "host" or "host:port" (port appended only when
// present). IPv6 addresses may appear unbracketed ("2001:db8::1") or in
// bracketed form ("[2001:db8::1]:443").
//
// Strip rule: strip the port suffix ONLY when the suffix after the last ":"
// is non-empty, all-ASCII-digits, AND either the key contains exactly one
// colon (IPv4/hostname with port) OR the key starts with "[" (bracketed IPv6
// with port). Any other multi-colon unbracketed key is treated as a bare IPv6
// address and returned whole.
func hostFromEgressKey(key string) string {
	i := strings.LastIndex(key, ":")
	if i < 0 {
		// No colon at all — key is a plain hostname or IPv4 without port.
		return key
	}

	suffix := key[i+1:]
	isDigits := len(suffix) > 0
	for _, c := range suffix {
		if c < '0' || c > '9' {
			isDigits = false
			break
		}
	}

	bracketed := strings.HasPrefix(key, "[")
	singleColon := strings.Count(key, ":") == 1

	if isDigits && (singleColon || bracketed) {
		host := key[:i]
		// Bracketed IPv6: "[2001:db8::1]:443" → strip surrounding brackets.
		if bracketed {
			host = strings.TrimPrefix(host, "[")
			host = strings.TrimSuffix(host, "]")
		}
		return host
	}

	// Multi-colon unbracketed key: bare IPv6 address — return whole.
	return key
}

// EgressHosts is the candidate UpstreamHosts set: the host portion of each
// observed "host:port" egress key, port stripped (IPv6-safe), deduped+sorted.
func EgressHosts(o Observed) []string {
	set := map[string]struct{}{}
	for _, key := range o.EgressKeys {
		host := hostFromEgressKey(key)
		if host != "" {
			set[host] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}
