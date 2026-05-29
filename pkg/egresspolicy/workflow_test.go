package egresspolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// fakeLedger satisfies LedgerSource for the workflow tests.
type fakeLedger struct {
	byBinary map[string][]LedgerFlow
}

func (f *fakeLedger) QueryBinary(b string, _, _ time.Time) []LedgerFlow {
	return f.byBinary[b]
}

func TestPropose_ZeroFlows_SuggestObserve(t *testing.T) {
	ll := &fakeLedger{byBinary: map[string][]LedgerFlow{"/usr/bin/cron": nil}}
	props := ProposeFromLedger(context.Background(), ll, []string{"/usr/bin/cron"},
		time.Now().Add(-14*24*time.Hour), time.Now())
	if len(props) != 1 {
		t.Fatalf("want 1 proposal got %d", len(props))
	}
	p := props[0]
	if p.SuggestedMode != ModeObserve {
		t.Errorf("zero flows: SuggestedMode=%q want observe", p.SuggestedMode)
	}
	if p.TotalConnects != 0 {
		t.Errorf("zero flows: TotalConnects=%d want 0", p.TotalConnects)
	}
}

func TestPropose_DenseTraffic_SuggestDenyDefault(t *testing.T) {
	now := time.Now()
	// FirstSeen 4 days back so spanDays >= 3 (the days-set picks up two
	// distinct YYYY-MM-DD stamps spanning multiple calendar days).
	flows := []LedgerFlow{
		{Binary: "/usr/bin/foo", DestCIDR: "203.0.113.0/16", DestPort: 443, Protocol: "tcp",
			SNI: "api.example.com", DestClass: "cloudflare",
			Connects: 500, BytesOut: 1024,
			FirstSeen: now.Add(-96 * time.Hour), LastSeen: now},
		// add an intermediate flow stamp so the day set has 3 entries
		{Binary: "/usr/bin/foo", DestCIDR: "203.0.113.0/16", DestPort: 443, Protocol: "tcp",
			SNI: "api.example.com", DestClass: "cloudflare",
			Connects: 0,
			FirstSeen: now.Add(-48 * time.Hour), LastSeen: now.Add(-48 * time.Hour)},
	}
	ll := &fakeLedger{byBinary: map[string][]LedgerFlow{"/usr/bin/foo": flows}}
	props := ProposeFromLedger(context.Background(), ll, []string{"/usr/bin/foo"},
		now.Add(-14*24*time.Hour), now)
	if len(props) != 1 {
		t.Fatal("want 1 proposal")
	}
	p := props[0]
	if p.SuggestedMode != ModeDenyDefault {
		t.Errorf("dense traffic: SuggestedMode=%q want deny_default", p.SuggestedMode)
	}
	if len(p.Allow) != 1 {
		t.Errorf("want 1 allow rule, got %d", len(p.Allow))
	}
	if p.Allow[0].Confidence < 80 {
		t.Errorf("dense + cloudflare class: confidence=%d want >=80", p.Allow[0].Confidence)
	}
}

func TestPropose_SparseFanout_SuggestObserve(t *testing.T) {
	now := time.Now()
	flows := make([]LedgerFlow, 0, 50)
	for i := 0; i < 50; i++ {
		flows = append(flows, LedgerFlow{
			Binary:    "/usr/bin/spread",
			DestCIDR:  "10." + itoa(i) + ".0.0/16",
			DestPort:  uint16(1000 + i),
			Protocol:  "tcp",
			Connects:  1,
			FirstSeen: now.Add(-time.Hour),
			LastSeen:  now,
		})
	}
	ll := &fakeLedger{byBinary: map[string][]LedgerFlow{"/usr/bin/spread": flows}}
	props := ProposeFromLedger(context.Background(), ll, []string{"/usr/bin/spread"},
		now.Add(-14*24*time.Hour), now)
	p := props[0]
	if p.SuggestedMode != ModeObserve {
		t.Errorf("sparse fanout: SuggestedMode=%q want observe", p.SuggestedMode)
	}
	if p.UniqueDests != 50 {
		t.Errorf("UniqueDests=%d want 50", p.UniqueDests)
	}
}

func TestAttachConfidence_Boundaries(t *testing.T) {
	cases := []struct {
		obs       uint64
		span      int
		destClass string
		want      int
	}{
		{500, 5, "cloudflare", 90}, // 80 + 10 (well-known)
		{500, 5, "", 80},           // baseline high
		{20, 1, "", 60},            // mid tier
		{5, 1, "", 30},             // sparse
		{500, 5, "raw", 30},        // raw caps even at high volume
		{0, 0, "", 0},              // no data
	}
	for _, c := range cases {
		r := ProposalRule{Observations: c.obs, DestClass: c.destClass}
		attachConfidence(&r, c.span)
		if r.Confidence != c.want {
			t.Errorf("attachConfidence(obs=%d,span=%d,class=%q)=%d want %d",
				c.obs, c.span, c.destClass, r.Confidence, c.want)
		}
	}
}

func TestToPolicy_PreservesAllowRules(t *testing.T) {
	now := time.Now()
	p := Proposal{
		Binary:        "/usr/bin/foo",
		SuggestedMode: ModeDenyDefault,
		Allow: []ProposalRule{
			{DestCIDR: "10.0.0.0/16", DestPort: 443, Protocol: "tcp",
				SNI: "api.example.com", DestClass: "cloudflare",
				Observations: 200, LastSeen: now, Reason: "test"},
		},
	}
	pol := p.ToPolicy()
	if pol.Binary != "/usr/bin/foo" {
		t.Errorf("binary lost: %q", pol.Binary)
	}
	if pol.Mode != ModeDenyDefault {
		t.Errorf("mode lost: %q", pol.Mode)
	}
	if len(pol.Allow) != 1 {
		t.Fatalf("allow lost: %d", len(pol.Allow))
	}
	r := pol.Allow[0]
	if r.DestCIDR != "10.0.0.0/16" || r.SNI != "api.example.com" || r.DestClass != "cloudflare" {
		t.Errorf("rule fields lost: %+v", r)
	}
	if len(r.Ports) != 1 || r.Ports[0] != 443 {
		t.Errorf("port lost: %v", r.Ports)
	}
	if len(r.Protocols) != 1 || r.Protocols[0] != "tcp" {
		t.Errorf("protocol lost: %v", r.Protocols)
	}
}

func TestProposalToSignedPolicy_VerifyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := Proposal{
		Binary:        "/usr/bin/foo",
		SuggestedMode: ModeDenyDefault,
		Allow: []ProposalRule{
			{DestCIDR: "10.0.0.0/16", DestPort: 443, Protocol: "tcp",
				SNI: "api.example.com", Observations: 200,
				LastSeen: time.Now().UTC()},
		},
	}
	sp, err := ProposalToSignedPolicy(p, "test-operator", priv)
	if err != nil {
		t.Fatalf("ProposalToSignedPolicy: %v", err)
	}
	if err := Verify(sp, pub); err != nil {
		t.Errorf("Verify roundtrip failed: %v", err)
	}
}

// itoa avoids importing strconv just for one path.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [4]byte
	n := 0
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	for i > 0 && n < len(buf) {
		buf[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	out := make([]byte, 0, n+1)
	if neg {
		out = append(out, '-')
	}
	for j := n - 1; j >= 0; j-- {
		out = append(out, buf[j])
	}
	return string(out)
}
