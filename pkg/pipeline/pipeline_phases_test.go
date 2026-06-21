package pipeline

import (
	"encoding/base64"
	"testing"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/tlsledger"
)

// These tests cover observeTLSPlaintext, the first phase extracted from
// the 2000-line Handle() in the P-RF.8 incremental decomposition. They
// pin the behaviour the inline block had so the extraction is provably
// non-regressing and future phase extractions have a template to follow.

func newTLSLedger(t *testing.T, allowed ...string) *tlsledger.Ledger {
	t.Helper()
	return tlsledger.New(tlsledger.Options{AllowedBinaries: allowed})
}

func sslEvent(binary, payloadB64 string) model.Event {
	ev := model.NewEvent("ebpf.ssl", model.SeverityHigh)
	ev.Image = binary
	ev.PID = 4242
	ev.Tags["payload_b64"] = payloadB64
	ev.Tags["dst_ip"] = "203.0.113.7"
	ev.Tags["dst_port"] = "443"
	ev.Tags["direction"] = "out"
	return ev
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestObserveTLSPlaintext_AllowedBinaryStored(t *testing.T) {
	led := newTLSLedger(t, "/usr/sbin/nginx")
	p := &Pipeline{TLSPlaintext: led}

	p.observeTLSPlaintext(sslEvent("/usr/sbin/nginx", b64("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))

	st := led.Stats()
	if st.Observed != 1 {
		t.Errorf("Observed=%d want 1", st.Observed)
	}
	if st.Stored != 1 {
		t.Errorf("Stored=%d want 1 (allow-listed binary should be captured)", st.Stored)
	}
}

func TestObserveTLSPlaintext_NotAllowedDropped(t *testing.T) {
	led := newTLSLedger(t, "/usr/sbin/nginx")
	p := &Pipeline{TLSPlaintext: led}

	p.observeTLSPlaintext(sslEvent("/tmp/evil", b64("GET / HTTP/1.1\r\n\r\n")))

	st := led.Stats()
	if st.Observed != 1 {
		t.Errorf("Observed=%d want 1", st.Observed)
	}
	if st.Stored != 0 || st.DroppedNotAllowed != 1 {
		t.Errorf("non-allowed binary should drop: stored=%d droppedNotAllowed=%d", st.Stored, st.DroppedNotAllowed)
	}
}

func TestObserveTLSPlaintext_WrongSensorShortCircuits(t *testing.T) {
	led := newTLSLedger(t, "/usr/sbin/nginx")
	p := &Pipeline{TLSPlaintext: led}

	ev := sslEvent("/usr/sbin/nginx", b64("GET / HTTP/1.1\r\n\r\n"))
	ev.Sensor = "ebpf.net" // not an SSL payload event

	p.observeTLSPlaintext(ev)

	if st := led.Stats(); st.Observed != 0 {
		t.Errorf("non-ssl sensor must not reach the ledger; Observed=%d want 0", st.Observed)
	}
}

func TestObserveTLSPlaintext_RawPayloadTagAlsoCaptured(t *testing.T) {
	led := newTLSLedger(t, "/usr/sbin/nginx")
	p := &Pipeline{TLSPlaintext: led}

	// No base64 — the raw "payload" tag path must still feed the ledger.
	ev := model.NewEvent("ebpf.ssl", model.SeverityHigh)
	ev.Image = "/usr/sbin/nginx"
	ev.Tags["payload"] = "RAW-BYTES-NOT-HTTP"

	p.observeTLSPlaintext(ev)

	if st := led.Stats(); st.Stored != 1 {
		t.Errorf("raw payload tag should be captured; stored=%d want 1", st.Stored)
	}
}

func TestObserveTLSPlaintext_NilLedgerNoPanic(t *testing.T) {
	p := &Pipeline{} // TLSPlaintext nil
	// Must be a no-op, not a panic.
	p.observeTLSPlaintext(sslEvent("/usr/sbin/nginx", b64("GET / HTTP/1.1\r\n\r\n")))
}

func TestObserveTLSPlaintext_EmptyPayloadNoStore(t *testing.T) {
	led := newTLSLedger(t, "/usr/sbin/nginx")
	p := &Pipeline{TLSPlaintext: led}

	ev := model.NewEvent("ebpf.ssl", model.SeverityHigh)
	ev.Image = "/usr/sbin/nginx" // no payload tags at all

	p.observeTLSPlaintext(ev)

	if st := led.Stats(); st.Observed != 0 || st.Stored != 0 {
		t.Errorf("empty payload should never reach Observe; stats=%+v", st)
	}
}
