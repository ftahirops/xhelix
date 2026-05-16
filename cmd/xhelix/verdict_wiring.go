package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/knowngood"
	"github.com/xhelix/xhelix/pkg/policy"
	"github.com/xhelix/xhelix/pkg/telemetrycorpus"
	"github.com/xhelix/xhelix/pkg/verdict"
)

// verdictCtx bundles the verdict engine + supporting state. Built
// once at daemon start, shared read-only across the dispatch loop
// and the LocalAPI handlers.
type verdictCtx struct {
	engine *verdict.Engine
	policy *policy.Policy
	kg     *knowngood.Corpus
	tlm    *telemetrycorpus.Corpus

	// On-disk policy source (hot-reloadable). May be nil if the
	// operator hasn't placed a file at the watched path.
	source *policy.FileSource

	// blockTelemetry flips the telemetry layer between observe-tag
	// and active-deny. Read atomically from the engine's hot path.
	blockTelemetry atomic.Bool

	// cache memoises verdicts by (exe-sha or exe-path, dst-ip,
	// dst-port, dns-name, sni). Bounded; LRU eviction on size cap.
	mu       sync.Mutex
	cache    map[string]cachedVerdict
	cacheCap int
	cacheTTL time.Duration
}

type cachedVerdict struct {
	v       verdict.Verdict
	expires time.Time
}

func newVerdictCtx() *verdictCtx {
	pol := policy.New()
	kg := knowngood.NewDefault()
	tlm := telemetrycorpus.NewDefault()
	vc := &verdictCtx{
		policy:   pol,
		kg:       kg,
		tlm:      tlm,
		cache:    make(map[string]cachedVerdict, 4096),
		cacheCap: 4096,
		cacheTTL: 5 * time.Minute,
	}
	vc.engine = verdict.New(
		policy.Layer{P: pol},                                           // 0
		telemetrycorpus.Layer{C: tlm, BlockFn: vc.blockTelemetry.Load}, // 1
		knowngood.Layer{C: kg},                                         // 2
	)
	return vc
}

// loadPolicyFile attaches a hot-reloadable on-disk policy source.
// Errors during the initial load are returned; subsequent reload
// errors are silent (previous policy stays active).
func (vc *verdictCtx) loadPolicyFile(path string, onChange func()) error {
	src := &policy.FileSource{Path: path}
	if _, err := src.Load(); err != nil {
		return err
	}
	vc.source = src
	vc.applySource()
	src.OnChange = func(_ *policy.FullDocument) {
		vc.applySource()
		// Invalidate the cache so the new policy takes effect on the
		// next decideForConn for every flow.
		vc.mu.Lock()
		vc.cache = make(map[string]cachedVerdict, vc.cacheCap)
		vc.mu.Unlock()
		if onChange != nil {
			onChange()
		}
	}
	go src.Watch(make(chan struct{}))
	return nil
}

// applySource pulls the latest FullDocument from the source and
// applies it to the engine's policy + telemetry-block flag.
func (vc *verdictCtx) applySource() {
	if vc.source == nil {
		return
	}
	fd := vc.source.Current()
	if fd == nil {
		return
	}
	doc := fd.Doc
	vc.policy.Load(&doc)
	vc.blockTelemetry.Store(fd.Settings.BlockTelemetry)
}

// decideForConn runs verdict.Decide for one connstate.Conn (or just
// the fields we have at connect time). Result is cached per tuple +
// process for cacheTTL.
func (vc *verdictCtx) decideForConn(c connstate.Conn) verdict.Verdict {
	key := vc.cacheKey(c)
	vc.mu.Lock()
	if cv, ok := vc.cache[key]; ok && time.Now().Before(cv.expires) {
		vc.mu.Unlock()
		return cv.v
	}
	vc.mu.Unlock()

	conn := verdict.Conn{
		PID:     c.PID,
		Comm:    c.Comm,
		Exe:     c.Exe,
		ExeSHA:  c.ExeSHA,
		UID:     c.UserID,
		DstIP:   c.Tuple.DstAddr.String(),
		DstPort: c.Tuple.DstPort,
		DNSName: c.DNSName,
		SNI:     c.SNI,
		Proto:   c.Tuple.Proto.String(),
		// Country / ASN are filled by the GeoIP layer when it lands
		// (F5.5). They start empty.
	}
	v := vc.engine.Decide(conn)
	vc.mu.Lock()
	if len(vc.cache) >= vc.cacheCap {
		// Cheap eviction: drop ~25% of the map. Not pretty, but the
		// hot path never blocks.
		drop := vc.cacheCap / 4
		for k := range vc.cache {
			delete(vc.cache, k)
			drop--
			if drop <= 0 {
				break
			}
		}
	}
	vc.cache[key] = cachedVerdict{v: v, expires: time.Now().Add(vc.cacheTTL)}
	vc.mu.Unlock()
	return v
}

func (vc *verdictCtx) cacheKey(c connstate.Conn) string {
	id := c.ExeSHA
	if id == "" {
		id = c.Exe
	}
	if id == "" {
		id = c.Comm
	}
	return id + "|" + c.Tuple.DstAddr.String() + "|" +
		shortuint16(c.Tuple.DstPort) + "|" + c.DNSName + "|" + c.SNI
}

func shortuint16(v uint16) string {
	// avoid strconv import; small custom is fine for a cache key
	if v == 0 {
		return "0"
	}
	b := [6]byte{}
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
