package egressguard

import (
	"github.com/xhelix/xhelix/pkg/brp"
)

// brpProfileLookup adapts brp.Matcher → ProfileLookup. The matcher
// resolves by full key (App+Version+OSFamily+Role+FeatureFingerprint);
// egressguard only knows the role, so the adapter scans the matcher's
// profile library and returns the first match's UpstreamHosts.
//
// This is a v0 implementation. A more efficient lookup (per-role
// index) is a follow-on; in practice the profile library is small
// (single-digit profiles per host) so a scan is fine.
type brpProfileLookup struct {
	matcher *brp.Matcher
}

// NewBRPProfileLookup adapts a brp.Matcher into the ProfileLookup
// interface egressguard consumes. Nil-safe — pass nil matcher to get
// an adapter that always returns empty (no declared peers known).
func NewBRPProfileLookup(matcher *brp.Matcher) ProfileLookup {
	return &brpProfileLookup{matcher: matcher}
}

func (b *brpProfileLookup) UpstreamHostsForRole(role string) []string {
	if b.matcher == nil || role == "" {
		return nil
	}
	for _, p := range b.matcher.Profiles() {
		if p.Key.Role == role {
			return p.Behavior.UpstreamHosts
		}
	}
	return nil
}
