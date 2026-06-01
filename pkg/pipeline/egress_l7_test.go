package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/egressledger"
	"github.com/xhelix/xhelix/pkg/model"
)

// TestEgressStampsL7Protocol is the EO5a-T3 contract: at the egress observe
// site the flow's application-layer protocol is classified from already-
// captured signals (dst port, SNI, HTTP request-line, payload prefix) and
// stamped onto the egressledger.Event before Observe is called.
func TestEgressStampsL7Protocol(t *testing.T) {
	led, err := egressledger.New(egressledger.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	p := &Pipeline{EgressLedger: led}

	// Port 22 → ssh by port inference.
	ssh := model.NewEvent("ebpf.net", model.SeverityInfo)
	ssh.PID = 1234
	ssh.Image = "/usr/bin/ssh"
	ssh.Comm = "ssh"
	ssh.Tags["kind"] = "net_connect"
	ssh.Tags["protocol"] = "tcp"
	ssh.Tags["dst_ip"] = "1.2.3.4"
	ssh.Tags["dst_port"] = "22"
	p.Handle(context.Background(), ssh)

	// SNI set + port 443 → https.
	https := model.NewEvent("ebpf.net", model.SeverityInfo)
	https.PID = 5678
	https.Image = "/usr/bin/curl"
	https.Comm = "curl"
	https.Tags["kind"] = "net_connect"
	https.Tags["protocol"] = "tcp"
	https.Tags["dst_ip"] = "5.6.7.8"
	https.Tags["dst_port"] = "443"
	https.Tags["sni"] = "example.com"
	p.Handle(context.Background(), https)

	rows := led.QueryRecent(time.Now().Add(-time.Hour), nil, "", 10)
	if len(rows) < 2 {
		t.Fatalf("want >=2 recent egress rows, got %d", len(rows))
	}

	var gotSSH, gotHTTPS string
	for _, r := range rows {
		switch r.DestPort {
		case 22:
			gotSSH = r.L7Protocol
		case 443:
			gotHTTPS = r.L7Protocol
		}
	}
	if gotSSH != "ssh" {
		t.Fatalf("port 22 L7Protocol = %q, want ssh", gotSSH)
	}
	if gotHTTPS != "https" {
		t.Fatalf("port 443 (SNI) L7Protocol = %q, want https", gotHTTPS)
	}
}
