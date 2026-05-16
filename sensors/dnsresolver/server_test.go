package dnsresolver

import (
	"context"
	"net"
	"testing"
	"time"
)

// runFakeUpstream binds a UDP socket that returns buildResponse()
// for every incoming query. Returns its addr ("ip:port") and a
// cancel function.
func runFakeUpstream(t *testing.T) (string, func()) {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, peer, err := c.ReadFrom(buf)
			if err != nil {
				continue
			}
			resp := buildResponse()
			// Mirror the query ID into the response (real upstream does this).
			if n >= 2 && len(resp) >= 2 {
				resp[0] = buf[0]
				resp[1] = buf[1]
			}
			_, _ = c.WriteTo(resp, peer)
		}
	}()
	return c.LocalAddr().String(), func() {
		close(stop)
		_ = c.Close()
		<-done
	}
}

func TestServerForwardsAndObserves(t *testing.T) {
	upstreamAddr, stopUpstream := runFakeUpstream(t)
	defer stopUpstream()

	cap := &capturingSink{}
	col := NewCollector(&fakeResolver{}, cap.Sink())

	srv := &Server{
		Addr:     "127.0.0.1:0",
		Upstream: upstreamAddr,
		Collector: col,
		UpstreamTimeout: 500 * time.Millisecond,
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	// Build a client that sends a query and reads the response.
	client, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Write(buildQuery())
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64*1024)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if n < dnsHdrLen {
		t.Fatalf("short response: %d bytes", n)
	}

	// Wait for the observation to land in the sink.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(cap.snapshot()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	obs := cap.snapshot()
	if len(obs) == 0 {
		t.Fatal("no observation emitted")
	}
	o := obs[0]
	if o.QName != "example.com" {
		t.Errorf("qname = %q", o.QName)
	}
	if o.QType != "A" {
		t.Errorf("qtype = %q", o.QType)
	}
	if len(o.IPs) != 2 {
		t.Errorf("IPs = %v", o.IPs)
	}
	if o.Upstream != upstreamAddr {
		t.Errorf("upstream = %q", o.Upstream)
	}

	q, a, dropped := srv.Stats()
	if q == 0 || a == 0 {
		t.Errorf("stats: q=%d a=%d", q, a)
	}
	if dropped != 0 {
		t.Errorf("dropped = %d, want 0", dropped)
	}
}

func TestServerUpstreamTimeoutStillObserves(t *testing.T) {
	cap := &capturingSink{}
	col := NewCollector(&fakeResolver{}, cap.Sink())

	srv := &Server{
		Addr:            "127.0.0.1:0",
		Upstream:        "127.0.0.1:1", // black-hole port
		Collector:       col,
		UpstreamTimeout: 100 * time.Millisecond,
		ReadTimeout:     500 * time.Millisecond,
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	client, _ := net.Dial("udp", srv.LocalAddr().String())
	defer client.Close()
	_, _ = client.Write(buildQuery())

	// Even though upstream is dead, the query observation should land.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(cap.snapshot()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(cap.snapshot()) == 0 {
		t.Fatal("no observation on upstream timeout")
	}
	_, _, dropped := srv.Stats()
	if dropped == 0 {
		t.Error("dropped counter not incremented")
	}
}

func TestServerRequiresFields(t *testing.T) {
	if err := (&Server{}).Start(context.Background()); err == nil {
		t.Fatal("expected error without Addr/Upstream/Collector")
	}
}

func TestServerStopIdempotent(t *testing.T) {
	srv := &Server{
		Addr: "127.0.0.1:0", Upstream: "127.0.0.1:1",
		Collector: NewCollector(&fakeResolver{}, (&capturingSink{}).Sink()),
	}
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := srv.Stop(); err != nil { // idempotent
		t.Fatal(err)
	}
}
