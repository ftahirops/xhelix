package snicheck

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/connstate"
	"github.com/xhelix/xhelix/pkg/model"
)

func netipParse(s string) (netip.Addr, error) { return netip.ParseAddr(s) }

func TestNote_AllowedComm_Skipped(t *testing.T) {
	out := make(chan model.Event, 8)
	d := New(connstate.New(0), out, Config{Host: "h", EvalDelay: 10 * time.Millisecond})
	d.Start(context.Background())
	d.Note(1, "apt", "/usr/bin/apt", 0, net.ParseIP("1.2.3.4"), 443)
	if s := d.Stats(); s.Seen != 0 || s.Skipped != 1 {
		t.Fatalf("expected seen=0 skipped=1, got %+v", s)
	}
}

func TestNote_AllowedCIDR_Skipped(t *testing.T) {
	out := make(chan model.Event, 8)
	d := New(connstate.New(0), out, Config{
		Host:       "h",
		EvalDelay:  10 * time.Millisecond,
		AllowCIDRs: []string{"169.254.169.254/32"},
	})
	d.Start(context.Background())
	d.Note(1, "curl", "/usr/bin/curl", 0, net.ParseIP("169.254.169.254"), 443)
	if s := d.Stats(); s.Seen != 0 || s.Skipped != 1 {
		t.Fatalf("expected skipped=1 got %+v", s)
	}
}

func TestNote_NonTLSPort_Ignored(t *testing.T) {
	out := make(chan model.Event, 8)
	d := New(connstate.New(0), out, Config{Host: "h", EvalDelay: 10 * time.Millisecond})
	d.Start(context.Background())
	d.Note(1, "curl", "/usr/bin/curl", 0, net.ParseIP("1.2.3.4"), 80)
	if s := d.Stats(); s.Seen != 0 {
		t.Fatalf("expected seen=0, got %+v", s)
	}
}

func TestEvaluate_FlagsNoSNI(t *testing.T) {
	tab := connstate.New(0)
	// Synthesise a Conn row with bytes out but no SNI — i.e. an
	// outbound TLS that completed handshake without SNI.
	tab.OnConnect(connstate.ConnectEvent{
		PID:   42,
		Tuple: connstateTuple("1.2.3.4", 443),
		Time:  time.Now(),
	})
	tab.UpdateBytes(connstateTuple("1.2.3.4", 443), 0, 600)

	out := make(chan model.Event, 8)
	d := New(tab, out, Config{Host: "h", EvalDelay: 5 * time.Millisecond})
	d.Start(context.Background())
	d.Note(42, "evil", "/tmp/x", 0, net.ParseIP("1.2.3.4"), 443)

	select {
	case ev := <-out:
		if ev.Tags["kind"] != "tls_no_sni" {
			t.Fatalf("got kind=%s", ev.Tags["kind"])
		}
		if ev.Tags["dst_ip"] != "1.2.3.4" {
			t.Fatalf("dst_ip=%q", ev.Tags["dst_ip"])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("no event emitted; stats=%+v", d.Stats())
	}
}

func TestEvaluate_SNIAttached_NoAlert(t *testing.T) {
	tab := connstate.New(0)
	tab.OnConnect(connstate.ConnectEvent{
		PID:   42,
		Tuple: connstateTuple("1.2.3.4", 443),
		Time:  time.Now(),
	})
	tab.UpdateBytes(connstateTuple("1.2.3.4", 443), 0, 600)
	tab.AttachSNI(connstateTuple("1.2.3.4", 443), "example.com")

	out := make(chan model.Event, 8)
	d := New(tab, out, Config{Host: "h", EvalDelay: 5 * time.Millisecond})
	d.Start(context.Background())
	d.Note(42, "curl", "/usr/bin/curl", 0, net.ParseIP("1.2.3.4"), 443)

	select {
	case ev := <-out:
		t.Fatalf("unexpected event with SNI present: %+v", ev.Tags)
	case <-time.After(150 * time.Millisecond):
		// expected: no alert
	}
}

func connstateTuple(dst string, port uint16) connstate.Tuple {
	// SrcAddr/SrcPort intentionally zero — connstate uses these as
	// part of the map key; matching by DstAddr/DstPort is what the
	// snicheck evaluator does via SnapshotByPID, so this synthetic
	// is fine.
	a, _ := netipParse(dst)
	return connstate.Tuple{
		Proto:   connstate.ProtoTCP,
		DstAddr: a,
		DstPort: port,
	}
}
