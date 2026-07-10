// Package webroot tracks a per-vhost lineage root so processes serving an
// inbound HTTP request get a non-admin (RootWeb) causal root and their
// workflows can become learnable. It is the "C" slice of the Root Emitters
// work (docs/ROOT_EMITTERS_SCOPE.md), driven by the eBPF ssl_read signal
// (sensor ebpf.ssl) which carries the serving PID + http_host atomically.
//
// Minting + proctree attribution is done by the pipeline (it needs the
// SourceMinter + ProcTree); this package owns only the per-vhost id cache,
// so it stays pure + testable. The cache is bounded (vhost count is normally
// config-bounded, but a hostile/misconfigured Host header space could be
// unbounded — so we cap it).
package webroot

import (
	"context"
	"sync"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
)

// Minter is the subset of source.Minter this package needs to mint a
// per-request web anchor. Declared here (rather than importing source) to
// keep the package a pure, dependency-light id cache.
type Minter interface {
	MintFromEvent(ctx context.Context, ev model.Event) (lineage.LineageID, error)
}

// DefaultCap bounds the number of distinct vhost roots cached/minted. Past it,
// new vhosts are not minted (existing ones still resolve) — prevents anchor
// blow-up from a churning/spoofed Host header space.
const DefaultCap = 4096

// Tracker caches one lineage root id per vhost (Host header value). It also
// backs the per-request app-tier root path: a per-host monotonic sequence
// (NextSeq, used to synthesize app-tier request ids) and a mint-once-per-
// request-id cache (MintRequest). Both are cap-bounded like the vhost map.
type Tracker struct {
	mu       sync.Mutex
	cap      int
	hosts    map[string]lineage.LineageID
	seqs     map[string]uint64            // per-host monotonic counter (NextSeq)
	requests map[string]lineage.LineageID // per-request-id minted anchor (MintRequest)
	ridOrder []string                     // FIFO insertion order of requests keys, for eviction
}

// New returns a Tracker with the default cap.
func New() *Tracker { return NewWithCap(DefaultCap) }

// NewWithCap is New with an explicit cap (cap <= 0 uses the default).
func NewWithCap(cap int) *Tracker {
	if cap <= 0 {
		cap = DefaultCap
	}
	return &Tracker{
		cap:      cap,
		hosts:    map[string]lineage.LineageID{},
		seqs:     map[string]uint64{},
		requests: map[string]lineage.LineageID{},
	}
}

// NextSeq returns the next per-host monotonic sequence number, used to
// synthesize a unique app-tier request id when the FastCGI event carries
// none. Cap-bounded: once seqs holds cap distinct hosts, an unseen host is
// not added and NextSeq returns 0 (the pid + fcgi_request_id still keep the
// synthesized id reasonably distinct). Never returns a decreasing value for
// a given host within the cap.
func (t *Tracker) NextSeq(host string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.seqs[host]; !ok && len(t.seqs) >= t.cap {
		return 0
	}
	t.seqs[host]++
	return t.seqs[host]
}

// MintRequest mints a per-request web (KindWeb) anchor for rid, once. It
// builds an identity event tagged service=web + http_host + request_id (and
// carries path/method when present) and calls minter.MintFromEvent, mirroring
// the per-vhost mint path. Returns (anchorID, true) when it minted, or
// (existingID|0, false) when rid was already minted or the mint was declined.
//
// The requests map is a mint-once-per-recent-rid dedup guard, not a durable
// store — request_id is high-cardinality (one per HTTP request), so unlike
// hosts/seqs it is bounded with FIFO eviction rather than a hard stop: once
// cap distinct rids are cached, the oldest is evicted to make room for the
// new one. A stale evicted rid reappearing just mints a fresh anchor, which
// is rare and harmless — the alternative (a hard cap) would silently stop
// minting forever once the process had seen cap distinct requests.
func (t *Tracker) MintRequest(ctx context.Context, minter Minter, ev model.Event, rid string) (lineage.LineageID, bool) {
	if minter == nil || rid == "" {
		return 0, false
	}
	host := ev.Tags["http_host"]
	if host == "" {
		return 0, false
	}

	t.mu.Lock()
	if id, ok := t.requests[rid]; ok {
		t.mu.Unlock()
		return id, false // mint-once: already have an anchor for this request
	}
	t.mu.Unlock()

	// Mint outside the lock (minter may touch SQLite). Dispatch is single-
	// goroutine so this cannot race, but the recheck below is cheap insurance.
	sev := model.NewEvent("identity.web", model.SeverityInfo)
	sev.PID = ev.PID
	sev.Tags["service"] = "web"
	sev.Tags["http_host"] = host
	sev.Tags["request_id"] = rid
	if uri := ev.Tags["http_uri"]; uri != "" {
		sev.Tags["path"] = uri
	}
	if m := ev.Tags["method"]; m != "" {
		sev.Tags["method"] = m
	}
	id, err := minter.MintFromEvent(ctx, sev)
	if err != nil || id == 0 {
		return 0, false
	}

	t.mu.Lock()
	if existing, ok := t.requests[rid]; ok {
		t.mu.Unlock()
		return existing, false
	}
	if len(t.requests) >= t.cap {
		// Evict the oldest rid to make room (FIFO ring): the requests map is
		// only a recent-mint dedup guard, so it must never hard-stop minting.
		oldest := t.ridOrder[0]
		t.ridOrder = t.ridOrder[1:]
		delete(t.requests, oldest)
	}
	t.requests[rid] = id
	t.ridOrder = append(t.ridOrder, rid)
	t.mu.Unlock()
	return id, true
}

// Get returns the cached root id for a vhost and whether one exists.
func (t *Tracker) Get(host string) (lineage.LineageID, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.hosts[host]
	return id, ok
}

// Put caches the root id for a vhost. No-op once the cap is reached (so a
// runaway Host-header space can't blow up the anchor store).
func (t *Tracker) Put(host string, id lineage.LineageID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.hosts[host]; !ok && len(t.hosts) >= t.cap {
		return false
	}
	t.hosts[host] = id
	return true
}

// Len reports the number of cached vhosts (test helper / observability).
func (t *Tracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.hosts)
}
