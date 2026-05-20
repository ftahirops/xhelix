package forensicapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/forensic"
)

func seededStore(t *testing.T) *forensic.Store {
	t.Helper()
	s := forensic.NewStore()
	t0 := time.Unix(1700000000, 0).UTC()
	s.Add(forensic.Observation{Kind: forensic.KindDomain, Value: "c2.evil.com", At: t0, Origin: "sinkhole", Confidence: forensic.ConfidenceDeterministic})
	s.Add(forensic.Observation{Kind: forensic.KindDomain, Value: "dga-thing.com", At: t0.Add(time.Hour), Origin: "dnspoison", Confidence: forensic.ConfidenceMedium})
	s.Add(forensic.Observation{Kind: forensic.KindJA3, Value: "abc123", At: t0, Origin: "sinkhole", Confidence: forensic.ConfidenceDeterministic})
	return s
}

func TestHandleQuery_Defaults(t *testing.T) {
	a := &API{Store: seededStore(t)}
	out, err := a.handleQuery(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	iocs := out.([]*forensic.IOC)
	if len(iocs) != 3 {
		t.Fatalf("got %d IOCs, want 3", len(iocs))
	}
}

func TestHandleQuery_Filters(t *testing.T) {
	a := &API{Store: seededStore(t)}
	raw := json.RawMessage(`{"kinds":["domain"],"confidence":"high","origin":"sinkhole","limit":10}`)
	out, err := a.handleQuery(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	iocs := out.([]*forensic.IOC)
	if len(iocs) != 1 || iocs[0].Value != "c2.evil.com" {
		t.Fatalf("filter wrong: %+v", iocs)
	}
}

func TestHandleQuery_BadSince(t *testing.T) {
	a := &API{Store: seededStore(t)}
	raw := json.RawMessage(`{"since":"not a time"}`)
	if _, err := a.handleQuery(context.Background(), raw); err == nil {
		t.Fatal("bad since should error")
	}
}

func TestHandleQuery_LimitDefaultApplied(t *testing.T) {
	s := forensic.NewStore()
	for i := 0; i < 500; i++ {
		s.Add(forensic.Observation{Kind: forensic.KindDomain, Value: "d" + itoa(i) + ".com"})
	}
	a := &API{Store: s}
	out, _ := a.handleQuery(context.Background(), nil)
	iocs := out.([]*forensic.IOC)
	if len(iocs) != 200 {
		t.Fatalf("default limit not honored: got %d, want 200", len(iocs))
	}
}

func TestHandleGet(t *testing.T) {
	a := &API{Store: seededStore(t)}
	raw := json.RawMessage(`{"kind":"domain","value":"c2.evil.com"}`)
	out, err := a.handleGet(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	ioc := out.(*forensic.IOC)
	if ioc.Value != "c2.evil.com" {
		t.Fatalf("got %+v", ioc)
	}
}

func TestHandleGet_NotFound(t *testing.T) {
	a := &API{Store: seededStore(t)}
	raw := json.RawMessage(`{"kind":"domain","value":"unknown.com"}`)
	if _, err := a.handleGet(context.Background(), raw); err == nil {
		t.Fatal("unknown should error")
	}
}

func TestHandleTag(t *testing.T) {
	s := seededStore(t)
	a := &API{Store: s}
	raw := json.RawMessage(`{"kind":"domain","value":"c2.evil.com","tag":"cobalt-strike"}`)
	out, err := a.handleTag(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if ok := out.(map[string]bool)["ok"]; !ok {
		t.Fatal("ok should be true")
	}
	ioc := s.Get(forensic.KindDomain, "c2.evil.com")
	if len(ioc.Tags) != 1 || ioc.Tags[0] != "cobalt-strike" {
		t.Fatalf("tag not applied: %v", ioc.Tags)
	}
}

func TestHandleCount(t *testing.T) {
	a := &API{Store: seededStore(t)}
	out, _ := a.handleCount(context.Background(), nil)
	res := out.(CountResult)
	if res.Total != 3 {
		t.Fatalf("Total=%d want 3", res.Total)
	}
}

func TestNilStore_AllHandlersError(t *testing.T) {
	a := &API{}
	if _, err := a.handleQuery(context.Background(), nil); err == nil {
		t.Fatal("nil store → handleQuery should error")
	}
	if _, err := a.handleGet(context.Background(), json.RawMessage(`{"kind":"d","value":"v"}`)); err == nil {
		t.Fatal("nil store → handleGet should error")
	}
	if _, err := a.handleTag(context.Background(), json.RawMessage(`{"kind":"d","value":"v","tag":"x"}`)); err == nil {
		t.Fatal("nil store → handleTag should error")
	}
	if _, err := a.handleCount(context.Background(), nil); err == nil {
		t.Fatal("nil store → handleCount should error")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
