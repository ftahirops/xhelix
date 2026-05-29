// Adapters that bridge daemon-side providers (geoip, destclass,
// connstate) to the web package's small interfaces. The web layer
// declares only what it needs; this file does the impedance match so
// pkg/ui/web doesn't import sensor packages.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/destclass"
	"github.com/xhelix/xhelix/pkg/egressledger"
	"github.com/xhelix/xhelix/pkg/egresspolicy"
	"github.com/xhelix/xhelix/pkg/geoip"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/threatintel"
	"github.com/xhelix/xhelix/ui/web"
)

// systemReverseDNS satisfies web.ReverseDNSResolver using the
// goroutine-safe net.DefaultResolver. The handler enforces a 2s
// timeout via the supplied context.
type systemReverseDNS struct{}

func (systemReverseDNS) Lookup(ctx context.Context, ip string) (string, error) {
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return "", err
	}
	if len(names) == 0 {
		return "", nil
	}
	return names[0], nil
}

// threatIntelAdapter satisfies web.ThreatIntelHits. Returns the feed
// source name (e.g. "spamhaus_drop") for hits, or "" otherwise.
type threatIntelAdapter struct{ s *threatintel.Set }

func (a threatIntelAdapter) Match(ip string) string {
	if a.s == nil {
		return ""
	}
	p := net.ParseIP(ip)
	if p == nil {
		return ""
	}
	t := a.s.Lookup(p)
	return t.Source
}

// ledgerWorkflowAdapter is the egresspolicy.LedgerSource backed by
// *egressledger.Ledger. Kept here (not in pkg/egresspolicy) to avoid
// pulling pkg/egressledger into the workflow library's import graph.
type ledgerWorkflowAdapter struct{ l *egressledger.Ledger }

func (a ledgerWorkflowAdapter) QueryBinary(binary string, start, end time.Time) []egresspolicy.LedgerFlow {
	if a.l == nil {
		return nil
	}
	rows := a.l.QueryBinary(binary, start, end)
	out := make([]egresspolicy.LedgerFlow, 0, len(rows))
	for _, r := range rows {
		out = append(out, egresspolicy.LedgerFlow{
			Binary:    r.Key.Binary,
			DestCIDR:  r.Key.DestCIDR,
			DestPort:  r.Key.DestPort,
			Protocol:  r.Key.Protocol,
			SNI:       r.Key.SNI,
			DNSName:   r.Key.DNSName,
			DestClass: r.Key.DestClass,
			BytesOut:  r.Metrics.BytesOut,
			BytesIn:   r.Metrics.BytesIn,
			Connects:  r.Metrics.Connects,
			FirstSeen: r.Metrics.FirstSeen,
			LastSeen:  r.Metrics.LastSeen,
		})
	}
	return out
}

// egressPolicyWebAdapter exposes a loaded *egresspolicy.Engine as
// web.EgressPolicyProvider — the smaller surface the dashboard needs
// for its policy panel. Week 4 widened this adapter with Propose /
// Install / Delete by also wiring the egress ledger so the workflow
// library can draft policies from observed flows.
type egressPolicyWebAdapter struct {
	e *egresspolicy.Engine
	l *egressledger.Ledger
}

func (a egressPolicyWebAdapter) List() []egresspolicy.SignedPolicy {
	if a.e == nil || a.e.Store() == nil {
		return nil
	}
	return a.e.Store().All()
}

func (a egressPolicyWebAdapter) Get(binary string) *egresspolicy.SignedPolicy {
	if a.e == nil || a.e.Store() == nil {
		return nil
	}
	return a.e.Store().Get(binary)
}

func (a egressPolicyWebAdapter) Reload() (int, error) {
	if a.e == nil || a.e.Store() == nil {
		return 0, nil
	}
	return a.e.Store().Reload()
}

func (a egressPolicyWebAdapter) Propose(ctx context.Context, binary string, days int) (egresspolicy.Proposal, error) {
	if a.l == nil {
		return egresspolicy.Proposal{}, fmt.Errorf("egress ledger not enabled")
	}
	if days <= 0 {
		days = 14
	}
	end := time.Now()
	start := end.Add(-time.Duration(days) * 24 * time.Hour)
	src := ledgerWorkflowAdapter{l: a.l}
	props := egresspolicy.ProposeFromLedger(ctx, src, []string{binary}, start, end)
	if len(props) == 0 {
		return egresspolicy.Proposal{}, fmt.Errorf("no proposal generated for %q", binary)
	}
	return props[0], nil
}

func (a egressPolicyWebAdapter) Install(sp egresspolicy.SignedPolicy) (string, int, error) {
	if a.e == nil || a.e.Store() == nil {
		return "", 0, fmt.Errorf("egress policy engine not enabled")
	}
	if err := a.e.Store().VerifyAndSave(sp); err != nil {
		return "", 0, err
	}
	n, _ := a.e.Store().Reload()
	return sp.Policy.Binary, n, nil
}

func (a egressPolicyWebAdapter) Delete(binary string) (int, error) {
	if a.e == nil || a.e.Store() == nil {
		return 0, fmt.Errorf("egress policy engine not enabled")
	}
	if err := a.e.Store().Delete(binary); err != nil {
		return 0, err
	}
	n, _ := a.e.Store().Reload()
	return n, nil
}

// procTreeWebAdapter satisfies web.ProcTreeLookup. Resolves the comm
// of a PID's direct parent via proctree.Graph. Returns "" if not known.
type procTreeWebAdapter struct{ g *proctree.Graph }

func (a procTreeWebAdapter) ParentComm(pid uint32) string {
	if a.g == nil {
		return ""
	}
	anc := a.g.Ancestors(pid, 1)
	if len(anc) == 0 {
		return ""
	}
	return anc[0].Comm
}

// Ancestors satisfies web.ProcAncestry — full chain up to depth.
func (a procTreeWebAdapter) Ancestors(pid uint32, depth int) []web.AncestorNode {
	if a.g == nil {
		return nil
	}
	anc := a.g.Ancestors(pid, depth)
	out := make([]web.AncestorNode, 0, len(anc))
	for _, n := range anc {
		out = append(out, web.AncestorNode{PID: n.PID, Comm: n.Comm, Exe: n.Image})
	}
	return out
}

// geoipWebAdapter satisfies web.GeoIPLookup.
type geoipWebAdapter struct{ p geoip.Provider }

func (a geoipWebAdapter) Lookup(ip string) (country, asn, org string, ok bool) {
	if a.p == nil {
		return "", "", "", false
	}
	r, found := a.p.Lookup(ip)
	if !found {
		return "", "", "", false
	}
	return r.Country, r.ASN, r.ASNOrg, true
}

// destclassWebAdapter satisfies web.DestClassify.
type destclassWebAdapter struct{ c *destclass.Classifier }

func (a destclassWebAdapter) Classify(ip net.IP, sni string, port uint16) string {
	if a.c == nil {
		return "unknown"
	}
	d := a.c.Classify(ip, sni, port)
	return string(d.Class)
}

// connstateToConnView projects connstate.Conn into the smaller view
// the web layer wants. Field names mirror web.ConnView json tags.
func connstateToConnView(in []connstate.Conn) []web.ConnView {
	out := make([]web.ConnView, 0, len(in))
	for _, c := range in {
		out = append(out, web.ConnView{
			PID:       c.PID,
			PPID:      c.PPID,
			Comm:      c.Comm,
			Exe:       c.Exe,
			ExeSHA:    c.ExeSHA,
			Proto:     c.Tuple.Proto.String(),
			State:     c.State.String(),
			Direction: c.Direction.String(),
			SrcAddr:   c.Tuple.SrcAddr.String(),
			SrcPort:   c.Tuple.SrcPort,
			DstAddr:   c.Tuple.DstAddr.String(),
			DstPort:   c.Tuple.DstPort,
			DNSName:   c.DNSName,
			SNI:       c.SNI,
			BytesOut:  c.BytesOut,
			BytesIn:   c.BytesIn,
		})
	}
	return out
}

// discoverOwnIPs enumerates IP addresses bound to any local interface
// and returns them as a set keyed by netip.Addr.String(). Used by the
// egress ledger to drop self-loopback rows where the kernel routes
// host-to-own-public-IP traffic through the loopback path and the
// eBPF accept-side socket records the peer (us) as the destination.
func discoverOwnIPs(log *slog.Logger) map[string]bool {
	out := map[string]bool{}
	ifs, err := net.Interfaces()
	if err != nil {
		if log != nil {
			log.Warn("egress: failed to enumerate interfaces for OwnIPs", "err", err)
		}
		return out
	}
	for _, iface := range ifs {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			out[ip.String()] = true
		}
	}
	if log != nil {
		log.Info("egress: own-IP filter populated", "count", len(out))
	}
	return out
}
