package egressledger

import (
	"sort"
	"strings"
	"time"
)

// matchFilter returns true if the record passes the supplied filter.
func matchFilter(r FlowRecord, f FlowFilter) bool {
	if f.Binary != "" && !strings.Contains(r.Key.Binary, f.Binary) {
		return false
	}
	if f.UID >= 0 && uint32(f.UID) != r.Key.UID {
		return false
	}
	if f.CGroupID >= 0 && uint64(f.CGroupID) != r.Key.CGroupID {
		return false
	}
	if f.DestCIDR != "" && f.DestCIDR != r.Key.DestCIDR {
		return false
	}
	if f.DestPort >= 0 && uint16(f.DestPort) != r.Key.DestPort {
		return false
	}
	if f.SNI != "" && !strings.Contains(r.Key.SNI, f.SNI) {
		return false
	}
	if f.DestClass != "" && f.DestClass != r.Key.DestClass {
		return false
	}
	if f.DenyOnly && r.Metrics.DenyEvents == 0 {
		return false
	}
	if f.ServiceRole != "" && r.Metrics.ServiceRole != f.ServiceRole {
		return false
	}
	if f.L7Protocol != "" && r.Metrics.L7Protocol != f.L7Protocol {
		return false
	}
	if f.Visibility == "public" || f.Visibility == "internal" {
		isPublic := IsPublicDestClass(r.Key.DestClass)
		if r.Key.DestClass == "" {
			// Fallback to CIDR inspection when class wasn't stamped.
			isPublic = IsPublicCIDR(r.Key.DestCIDR)
		}
		if f.Visibility == "public" && !isPublic {
			return false
		}
		if f.Visibility == "internal" && isPublic {
			return false
		}
	}
	return true
}

// QueryLive returns the hot-tier snapshot filtered, sorted by bucket desc.
func (l *Ledger) QueryLive(filter FlowFilter) []FlowRecord {
	if l == nil {
		return nil
	}
	rows := l.hot.snapshot()
	out := make([]FlowRecord, 0, len(rows))
	for _, r := range rows {
		if matchFilter(r, filter) {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Bucket.After(out[j].Bucket) })
	return out
}

// QueryTimeline auto-picks the right tier based on range width.
func (l *Ledger) QueryTimeline(start, end time.Time, filter FlowFilter) []FlowRecord {
	if l == nil || !start.Before(end) {
		return nil
	}
	now := time.Now()
	var out []FlowRecord
	add := func(r FlowRecord) {
		if matchFilter(r, filter) {
			out = append(out, r)
		}
	}

	// A query window can span multiple tiers (e.g. "last 7d" reaches hot +
	// warm + cold). Scan EVERY tier whose stored range overlaps [start,end]
	// and union the results. After Tick() each bucket lives in exactly one
	// tier (hot→warm→cold migration deletes from the prior tier), so the
	// union does not double-count.
	//
	// The OLD code picked a single tier by the window's end-age, so any query
	// ending at "now" only ever hit hot/warm and the cold parquet history was
	// never returned — every long window looked identical (same warm slice).
	hotStart := now.Add(-l.opts.HotWindow)

	// Tiers are disjoint in time: hot.slide() evicts to warm (deletes from
	// hot), and the hourly cold-roll drains warm→cold (deletes from warm), so
	// a bucket lives in exactly one tier. Warm only retains ~the last hour
	// before draining to cold, so cold holds everything older than ~1h — NOT
	// just older than WarmRetention. Scan hot for the recent edge, and BOTH
	// warm and cold whenever the window reaches older than the hot window;
	// their disjointness means the union doesn't double-count.
	if end.After(hotStart) {
		for _, r := range l.hot.snapshotRange(start, end) {
			add(r)
		}
	}
	if start.Before(hotStart) {
		_ = l.warm.scan(start, end, func(r FlowRecord) bool { add(r); return true })
		_ = l.cold.scan(start, end, func(r FlowRecord) bool { add(r); return true })
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Bucket.Before(out[j].Bucket) })
	return out
}

// QueryBinary is a convenience wrapper for one binary across a range.
func (l *Ledger) QueryBinary(binary string, start, end time.Time) []FlowRecord {
	return l.QueryTimeline(start, end, FlowFilter{
		Binary:   binary,
		UID:      -1,
		CGroupID: -1,
		DestPort: -1,
	})
}

// QueryDestination is a convenience wrapper for one (cidr, port) target.
func (l *Ledger) QueryDestination(cidr string, port uint16, start, end time.Time) []FlowRecord {
	return l.QueryTimeline(start, end, FlowFilter{
		UID:      -1,
		CGroupID: -1,
		DestCIDR: cidr,
		DestPort: int32(port),
	})
}
