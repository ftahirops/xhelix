package pipeline

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/xhelix/xhelix/pkg/cgroupclass"
	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/model"
)

// Helpers extracted from cmd/xhelix/runhelpers.go in P-RF.7b.
// All previously package-local to main; moved here because Handle
// is the only caller.

// lookupSNIFromConnstate returns the SNI recorded for any active flow
// on (pid, dst_ip, dst_port). Empty string if not yet known (TLS
// Hello hasn't been parsed) or if connstate / dpi isn't active.
func lookupSNIFromConnstate(tab *connstate.Table, pid uint32, dstIP string, dstPort uint16) string {
	if tab == nil || pid == 0 {
		return ""
	}
	for _, c := range tab.SnapshotByPID(pid) {
		if c.SNI == "" {
			continue
		}
		if c.Tuple.DstAddr.String() == dstIP && c.Tuple.DstPort == dstPort {
			return c.SNI
		}
	}
	return ""
}

// splitCSV is a forgiving comma-and-space splitter used for the
// dns_answers tag emitted by sensors/netids. Empty input returns nil.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// feedConnstateBytes folds a net_bytes ebpf event into connstate's
// per-flow BytesIn/BytesOut counters. Cheap; non-fatal on missing tags.
func feedConnstateBytes(tab *connstate.Table, ev model.Event) {
	dst := ev.Tags["dst_ip"]
	if dst == "" {
		return
	}
	addr, err := netip.ParseAddr(dst)
	if err != nil {
		return
	}
	var dport, sport uint16
	if p := ev.Tags["dst_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		dport = uint16(pp)
	}
	if p := ev.Tags["src_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		sport = uint16(pp)
	}
	var nbytes uint64
	if b := ev.Tags["bytes"]; b != "" {
		_, _ = fmt.Sscanf(b, "%d", &nbytes)
	}
	if nbytes == 0 {
		return
	}
	var dir uint8
	if ev.Tags["dir"] == "in" {
		dir = 1
	}
	tab.UpdateBytes(connstate.Tuple{
		Proto: connstate.ProtoTCP, SrcPort: sport,
		DstAddr: addr, DstPort: dport,
	}, dir, nbytes)
}

// feedConnstate converts an ebpf.net net_connect event into a
// connstate.ConnectEvent and inserts it.
func feedConnstate(tab *connstate.Table, classifier *cgroupclass.Classifier, ev model.Event) {
	dstStr := ev.Tags["dst_ip"]
	if dstStr == "" {
		return
	}
	dstAddr, err := netip.ParseAddr(dstStr)
	if err != nil {
		return
	}
	port := uint16(0)
	if p := ev.Tags["dst_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		port = uint16(pp)
	}
	srcPort := uint16(0)
	if p := ev.Tags["src_port"]; p != "" {
		var pp int
		_, _ = fmt.Sscanf(p, "%d", &pp)
		srcPort = uint16(pp)
	}
	tuple := connstate.Tuple{
		Proto:   connstate.ProtoTCP,
		SrcPort: srcPort,
		DstAddr: dstAddr,
		DstPort: port,
	}
	ce := connstate.ConnectEvent{
		Time:  ev.Time,
		PID:   ev.PID,
		PPID:  ev.ParentPID,
		Comm:  ev.Comm,
		Exe:   ev.Image,
		Tuple: tuple,
	}
	if classifier != nil && ev.PID != 0 {
		info := classifier.Classify(ev.PID)
		ce.CGroupClass = info.Class
		ce.Unit = info.Unit
		ce.UserID = info.UserID
	}
	if sha := ev.Tags["image_sha256"]; sha != "" {
		ce.ExeSHA = sha
	}
	tab.OnConnect(ce)
}

// splitArgv parses a space-separated argv string.
func splitArgv(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// parseHexUint64 parses "0x..." or decimal; 0 on error.
func parseHexUint64(s string) uint64 {
	if s == "" {
		return 0
	}
	s = strings.TrimPrefix(s, "0x")
	var v uint64
	_, _ = fmt.Sscanf(s, "%x", &v)
	return v
}

// parseUint32 parses decimal; 0 on error.
func parseUint32(s string) uint32 {
	if s == "" {
		return 0
	}
	var v uint32
	_, _ = fmt.Sscanf(s, "%d", &v)
	return v
}
