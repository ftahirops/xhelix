package main

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/enforce/nfqueue"
	"github.com/xhelix/xhelix/pkg/verdict"
)

// enforceCtx wraps the NFQUEUE manager + nft rule lifecycle.
// Daemon owns one of these; LocalAPI handlers flip arm/disarm.
type enforceCtx struct {
	cfg   enforceConfig
	mgr   *nfqueue.Manager
	armed atomic.Bool
	since atomic.Int64 // unix-nanos when armed
	soak  atomic.Int64 // unix-nanos when soak ends (DROP becomes real)
	mu    sync.Mutex
	log   *slog.Logger

	// Mode: 0=off, 1=soft (alert-only, never drops),
	// 2=hard (deny verdicts drop packets after soak).
	mode atomic.Int32

	// Counters
	wouldDrop atomic.Uint64

	// Wired at construction:
	vctx    *verdictCtx
	connTab *connstate.Table
}

const (
	modeOff  int32 = 0
	modeSoft int32 = 1
	modeHard int32 = 2
)

type enforceConfig struct {
	QueueNum uint16
	NftTable string
	NftChain string
}

func defaultEnforceConfig() enforceConfig {
	return enforceConfig{
		QueueNum: 0,
		NftTable: "xhelix_enforce",
		NftChain: "output",
	}
}

func newEnforceCtx(log *slog.Logger, vctx *verdictCtx, tab *connstate.Table) *enforceCtx {
	return &enforceCtx{
		cfg:     defaultEnforceConfig(),
		log:     log,
		vctx:    vctx,
		connTab: tab,
	}
}

// Arm installs the nft rules and starts the queue consumer.
//
// modeStr selects behaviour:
//   "soft" — verdicts are computed and would_drop is incremented +
//            alerts logged, but every packet is ACCEPTed. Safe to
//            leave on indefinitely; great for tuning policy.
//   "hard" — after the soak window, deny verdicts actually drop the
//            packet. During the soak window behaves like "soft".
func (e *enforceCtx) Arm(ctx context.Context, soak time.Duration, modeStr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.armed.Load() {
		return nil
	}
	if soak < 0 {
		soak = 0
	}
	mode := modeHard
	switch modeStr {
	case "soft":
		mode = modeSoft
	case "hard", "":
		mode = modeHard
	default:
		return fmt.Errorf("enforce arm: unknown mode %q (want soft|hard)", modeStr)
	}
	e.mode.Store(mode)
	if err := e.installNft(); err != nil {
		return fmt.Errorf("enforce arm: nft install: %w", err)
	}
	mgr := nfqueue.New(nfqueue.Config{
		QueueNum: e.cfg.QueueNum,
		Logger:   e.log,
		Deadline: 25 * time.Millisecond, // tight; fail-open ACCEPT on miss
	}, e.makeVerdictFn())
	if err := mgr.Start(ctx); err != nil {
		_ = e.removeNft()
		return fmt.Errorf("enforce arm: queue start: %w", err)
	}
	e.mgr = mgr
	e.armed.Store(true)
	now := time.Now()
	e.since.Store(now.UnixNano())
	e.soak.Store(now.Add(soak).UnixNano())
	e.wouldDrop.Store(0)
	e.log.Warn("enforcement ARMED",
		"queue", e.cfg.QueueNum, "soak_seconds", int(soak.Seconds()))
	return nil
}

// InSoak returns true while we're still in the post-arm soak window.
func (e *enforceCtx) InSoak() bool {
	if !e.armed.Load() {
		return false
	}
	return time.Now().UnixNano() < e.soak.Load()
}

// Status returns a single map suitable for a JSON response.
func (e *enforceCtx) Status() map[string]any {
	armed := e.armed.Load()
	out := map[string]any{
		"armed":       armed,
		"mode":        modeName(e.mode.Load()),
		"in_soak":     false,
		"soak_left_s": 0,
		"would_drop":  e.wouldDrop.Load(),
	}
	if armed {
		now := time.Now().UnixNano()
		soak := e.soak.Load()
		if now < soak {
			out["in_soak"] = true
			out["soak_left_s"] = int((soak - now) / int64(time.Second))
		}
		out["since"] = time.Unix(0, e.since.Load()).Format(time.RFC3339)
	}
	for k, v := range e.Stats() {
		out["pkt_"+k] = v
	}
	return out
}

// Disarm tears down nft + stops the queue. Idempotent. Guaranteed
// to complete fast — never blocks the user's network behind a
// busy daemon.
func (e *enforceCtx) Disarm() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.armed.Load() {
		return
	}
	_ = e.removeNft()
	if e.mgr != nil {
		e.mgr.Stop()
		e.mgr = nil
	}
	e.armed.Store(false)
	e.mode.Store(modeOff)
	e.log.Warn("enforcement DISARMED — observe-only verdicts")
}

// IsArmed returns the current state.
func (e *enforceCtx) IsArmed() bool { return e.armed.Load() }

// Stats returns the latest counters from the queue manager, or empty
// if disarmed.
func (e *enforceCtx) Stats() map[string]uint64 {
	if !e.armed.Load() || e.mgr == nil {
		return map[string]uint64{}
	}
	return e.mgr.StatsSnapshot()
}

// makeVerdictFn returns the closure NFQUEUE calls per packet.
// It mirrors the dispatch-time decideForConn path but built from
// what's visible in the L3 packet alone — at SYN time we only have
// (dst-ip, dst-port). The verdict engine matches against any DNS
// hint / SNI already attached to a matching connstate.Conn.
func (e *enforceCtx) makeVerdictFn() nfqueue.VerdictFn {
	return func(_ context.Context, p nfqueue.Packet) nfqueue.Verdict {
		// Only act on outbound new connections — TCP SYN without ACK.
		if p.Proto == nfqueue.ProtoTCP && (p.TCPFlags&0x12) != 0x02 {
			return nfqueue.VerdictAccept
		}

		// Look up any pre-existing connstate row for this 3-tuple. The
		// TLS DPI sniffer or DNS observer may already have attached
		// SNI / DNSName from an earlier observation.
		var conn verdict.Conn
		conn.DstIP = p.DstIP.String()
		conn.DstPort = p.DstPort
		conn.Proto = p.Proto.String()
		if e.connTab != nil {
			tup := connstate.Tuple{
				Proto:   connstate.ProtoTCP,
				SrcPort: p.SrcPort,
				DstAddr: p.DstIP,
				DstPort: p.DstPort,
			}
			if c, ok := e.connTab.Lookup(tup); ok {
				conn.PID = c.PID
				conn.Comm = c.Comm
				conn.Exe = c.Exe
				conn.ExeSHA = c.ExeSHA
				conn.UID = c.UserID
				conn.DNSName = c.DNSName
				conn.SNI = c.SNI
			}
		}

		v := e.vctx.engine.Decide(conn)
		if v.Action != verdict.ActionDeny {
			return nfqueue.VerdictAccept
		}
		// Always count + log; whether to drop depends on mode + soak.
		e.wouldDrop.Add(1)
		mode := e.mode.Load()
		if mode == modeSoft || e.InSoak() {
			if e.log != nil {
				e.log.Info("enforce WOULD-DROP",
					"mode", modeName(mode), "in_soak", e.InSoak(),
					"dst", p.DstIP, "port", p.DstPort,
					"pid", conn.PID, "comm", conn.Comm, "layer", v.Layer)
			}
			return nfqueue.VerdictAccept
		}
		if e.log != nil {
			e.log.Warn("enforce DROP",
				"dst", p.DstIP, "port", p.DstPort,
				"pid", conn.PID, "comm", conn.Comm, "layer", v.Layer)
		}
		return nfqueue.VerdictDrop
	}
}

func modeName(m int32) string {
	switch m {
	case modeSoft:
		return "soft"
	case modeHard:
		return "hard"
	}
	return "off"
}

// installNft runs `nft` to set up the table/chain/rule. Uses the
// `bypass` flag on the queue rule — the critical safety feature.
// Without bypass, a kernel timeout on userspace would DROP packets,
// taking the network down. With bypass, the kernel forwards them on
// when the queue is full or absent.
func (e *enforceCtx) installNft() error {
	rule := fmt.Sprintf(`
		table inet %[1]s {
			chain %[2]s {
				type filter hook output priority 0; policy accept;
				meta nfproto ipv4 ip protocol tcp tcp flags syn / fin,syn,rst,ack queue num %[3]d bypass
				meta nfproto ipv6 meta l4proto tcp tcp flags syn / fin,syn,rst,ack queue num %[3]d bypass
			}
		}`, e.cfg.NftTable, e.cfg.NftChain, e.cfg.QueueNum)
	return runNft(rule)
}

func (e *enforceCtx) removeNft() error {
	return runNft(fmt.Sprintf("delete table inet %s", e.cfg.NftTable))
}

func runNft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %w: %s", err, out)
	}
	return nil
}
