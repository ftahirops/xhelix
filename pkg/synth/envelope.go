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

// EgressHosts is the candidate UpstreamHosts set: the host portion of each
// observed "host:port" egress key, port stripped (last colon), deduped+sorted.
func EgressHosts(o Observed) []string {
	set := map[string]struct{}{}
	for _, key := range o.EgressKeys {
		host := key
		if i := strings.LastIndex(key, ":"); i >= 0 {
			host = key[:i]
		}
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
