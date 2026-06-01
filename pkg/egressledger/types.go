package egressledger

import (
	"log/slog"
	"net"
	"time"
)

// FlowKey is the dedup/aggregation key for a flow bucket.
type FlowKey struct {
	Binary    string
	ExeSHA    string
	UID       uint32
	CGroupID  uint64
	DestCIDR  string
	DestPort  uint16
	Protocol  string
	SNI       string
	DNSName   string
	DestClass string
	// Role: "client" (this process initiated the connect), "server"
	// (this process is on the accept side — the bytes are replies),
	// or "" (unknown). Stamped at the pipeline observe site from the
	// kprobe kind + local src_port. Aggregation by Role prevents
	// inbound replies and outbound initiations from merging into one
	// row.
	Role string
}

// FlowMetrics is the counter set associated with a FlowKey within a bucket.
type FlowMetrics struct {
	FirstSeen    time.Time
	LastSeen     time.Time
	Connects     uint64
	BytesOut     uint64
	BytesIn      uint64
	DistinctDsts uint32
	DenyEvents   uint64
	VerifyEvents uint64
	// ServiceRole / ParentComm: last observed for this key (descriptive;
	// the key already pins binary/uid/cgroup so role is stable). Enables
	// grouping aggregates by role without inflating the FlowKey.
	ServiceRole string
	ParentComm  string
}

// FlowRecord is a (bucket, key, metrics) triple returned by queries.
type FlowRecord struct {
	Key     FlowKey
	Metrics FlowMetrics
	Bucket  time.Time
}

// Event is the raw input to Observe.
type Event struct {
	Time     time.Time
	Binary   string
	ExeSHA   string
	UID      uint32
	CGroupID uint64
	DestIP   net.IP
	DestPort uint16
	Protocol string
	SNI      string
	DNSName  string
	BytesOut uint64
	BytesIn  uint64
	Connect  bool
	Deny     bool
	Verify   bool
	// DestClass, if set by the caller (e.g. the pipeline running
	// pkg/destclass at the write site), drives smart per-class
	// bucketing in flowKeyForIP. Empty falls back to the legacy /16
	// behavior or the Options.DestClassifier callback.
	DestClass string
	// Role: "client"|"server"|"". Server == accept-side reply path.
	Role string
	// PID/PPID/Comm of the originating process. Not aggregated in the
	// FlowKey (would explode cardinality) but recorded in the recent-
	// events ring so the country drilldown can answer "which PIDs
	// touched this country in the last hour".
	PID  uint32
	PPID uint32
	Comm string
	// ContainerID / ContainerClass / Unit describe the cgroup origin of
	// the process. ContainerClass is "container"|"user"|"system"|
	// "kernel"|"unknown" (cgroupclass.Class.String()); ContainerID is the
	// docker/containerd/cri-o id when ContainerClass=="container"; Unit is
	// the systemd unit. Recorded in the recent-events ring (NOT the FlowKey
	// — would explode cardinality and force a store-schema change).
	ContainerID    string
	ContainerClass string
	Unit           string
	// ServiceRole / ParentComm are descriptive enrichment (role from
	// pkg/servicerole; parent process comm). NOT part of FlowKey.
	ServiceRole string
	ParentComm  string
	// SrcPort — local port. Used at observe time to decide Role when
	// the caller didn't set it. Not stored.
	SrcPort uint16
}

// FlowFilter scopes a Query*. Zero/empty fields are "any"; -1 means any
// for the signed numeric fields.
type FlowFilter struct {
	Binary    string
	UID       int32
	CGroupID  int64
	DestCIDR  string
	DestPort  int32
	SNI       string
	DestClass string
	DenyOnly  bool

	// Visibility filters by public/internal classification. Empty (zero
	// value) and "any" both mean no filter. "public" excludes private/
	// loopback/link-local destinations. "internal" includes ONLY
	// private/loopback/link-local. The dashboard defaults to "public"
	// for the main pages and "internal" for the dedicated Internal
	// Network page.
	Visibility string
}

// Stats describes the current ledger health.
type Stats struct {
	HotRows        int
	WarmKeys       int
	ColdDays       int
	ColdBytes      int64
	LastTickAt     time.Time
	LastCompactAt  time.Time
	RetentionDays  int
	ObserveCount   uint64
	DropEmptyCount uint64
}

// Options configures the ledger.
type Options struct {
	Dir            string
	RetentionDays  int
	HotWindow      time.Duration
	HotBucket      time.Duration
	WarmRetention  time.Duration
	WarmBucket     time.Duration
	ColdBucket     time.Duration
	Logger         *slog.Logger
	DestClassifier func(ip net.IP, sni string) string
	// ExcludePrivate, if true, drops private/loopback/link-local
	// destinations at write time. Saves ~30-50% on storage for
	// operators who only care about external egress.
	ExcludePrivate bool
	// OwnIPs is the set of IP addresses the host owns (any interface).
	// When non-empty, Observe drops events whose DestIP matches — this
	// suppresses kernel-loopback noise where the host talks to itself
	// over its own public IP and the eBPF accept-side socket records
	// the peer as the "destination". String form is the canonical
	// netip.Addr.String() of each address.
	OwnIPs map[string]bool
	// RecentRingCap bounds the side ring of (PID, dest) events used
	// by the country drilldown for historical PID recall. Zero =
	// default 65536.
	RecentRingCap int
}

// defaults fills in the zero-value fields with sane defaults.
func (o *Options) defaults() {
	if o.RetentionDays <= 0 {
		o.RetentionDays = 14
	}
	if o.HotWindow <= 0 {
		o.HotWindow = 60 * time.Minute
	}
	if o.HotBucket <= 0 {
		o.HotBucket = time.Minute
	}
	if o.WarmRetention <= 0 {
		o.WarmRetention = 48 * time.Hour
	}
	if o.WarmBucket <= 0 {
		o.WarmBucket = 5 * time.Minute
	}
	if o.ColdBucket <= 0 {
		o.ColdBucket = time.Hour
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}
