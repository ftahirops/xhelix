// Package dnsresolver collects DNS observations and links them to
// pids so that subsequent connects can be labelled with the
// qname the destination IP was resolved from.
//
// The package is decoupled from the DNS source. Today, observations
// arrive from sensors/netids via the daemon dispatch loop (Suricata
// EVE log). Later, a built-in DNS server (planned T0.7b, needs
// miekg/dns) can feed Observations directly. Either way, the
// downstream model is the same: pkg/connstate.AttachDNS gets called
// on the matching pid + destination IPs.
//
// Pid attribution uses the well-known /proc/net/udp source-port
// lookup (same trick Portmaster uses). It's racy on its own — the
// socket may already be closed when we look — so the Collector
// also keeps a small per-port recency window: a query observed at
// time T is allowed to attribute to a process that owned the port
// at T ± window.
//
// The Collector is goroutine-safe and intentionally allocation-
// lean for the connect hot path.
package dnsresolver

import "time"

// Query is a DNS question — what was asked and when.
type Query struct {
	At        time.Time
	QName     string
	QType     string // "A", "AAAA", "TXT", etc.
	SrcPort   uint16 // client UDP source port; 0 if unknown
	Upstream  string // resolver that answered (informational)
	Encrypted bool   // true if query was DoH/DoT (qname may be unknown)
}

// Answer is the resolution result.
type Answer struct {
	IPs []string // resolved A / AAAA addresses; never nil
	TTL time.Duration
}

// Observation is one Query + Answer pair. Either field may be
// empty (e.g. NXDOMAIN answers have no IPs but a known qname).
type Observation struct {
	Query
	Answer

	// PID is the resolved process id (filled by the Collector),
	// or 0 if attribution failed.
	PID uint32

	// Exe is the resolved process exe path, when known.
	Exe string
}

// Sink is the callback the Collector invokes for every fully-
// processed Observation. The daemon's dispatch loop installs the
// sink so the observation can flow into pkg/connstate.AttachDNS,
// the history store, and the event chain.
//
// The sink must be safe to call concurrently and must not block
// the caller for long; do real work in a goroutine.
type Sink func(obs Observation)
