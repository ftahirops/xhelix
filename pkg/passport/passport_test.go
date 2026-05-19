package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func goodParams() IssueParams {
	return IssueParams{
		Actor:       "admin_user_91",
		Route:       "/admin/export/orders",
		DataClasses: []string{"pii", "customer_order"},
		MaxRows:     5000,
		DestCIDRs:   []string{"10.0.30.0/24"},
		Reason:      "monthly finance export",
		ApprovedBy:  "operator_id_12",
		TTL:         5 * time.Minute,
	}
}

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestIssue_Verify_RoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	s, err := Issue(priv, goodParams())
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(pub, s)
	if err != nil {
		t.Errorf("Verify: %v", err)
	}
	if got.Actor != "admin_user_91" || got.MaxRows != 5000 {
		t.Errorf("verified payload mismatch: %+v", got)
	}
	if s.KeyID == "" {
		t.Error("KeyID should be populated")
	}
}

func TestIssue_ClampsTTL(t *testing.T) {
	_, priv := newKey(t)
	p := goodParams()
	p.TTL = 2 * time.Hour
	s, err := Issue(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	ttl := s.Passport.ExpiresAt.Sub(s.Passport.IssuedAt)
	if ttl != HardTTLMax {
		t.Errorf("TTL = %v, want %v (clamped)", ttl, HardTTLMax)
	}

	p.TTL = 1 * time.Second
	s, err = Issue(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	ttl = s.Passport.ExpiresAt.Sub(s.Passport.IssuedAt)
	if ttl != MinTTL {
		t.Errorf("TTL = %v, want %v (raised to MinTTL)", ttl, MinTTL)
	}
}

func TestIssue_RejectsMissingFields(t *testing.T) {
	_, priv := newKey(t)
	cases := map[string]func(p *IssueParams){
		"empty actor":         func(p *IssueParams) { p.Actor = "" },
		"empty reason":        func(p *IssueParams) { p.Reason = "" },
		"empty approver":      func(p *IssueParams) { p.ApprovedBy = "" },
		"empty data_classes":  func(p *IssueParams) { p.DataClasses = nil },
		"no destinations":     func(p *IssueParams) { p.DestCIDRs = nil; p.DestIPs = nil; p.DestHostSuffixes = nil },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			p := goodParams()
			mut(&p)
			if _, err := Issue(priv, p); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestIssue_RejectsBadCIDR(t *testing.T) {
	_, priv := newKey(t)
	p := goodParams()
	p.DestCIDRs = []string{"not-a-cidr"}
	if _, err := Issue(priv, p); err == nil {
		t.Error("expected error for bad CIDR")
	}
}

func TestVerify_RejectsTampered(t *testing.T) {
	pub, priv := newKey(t)
	s, _ := Issue(priv, goodParams())

	tampered := s
	tampered.Passport.MaxRows = 999999 // raise the cap
	if _, err := Verify(pub, tampered); err == nil {
		t.Error("Verify should reject tampered MaxRows")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	pub, priv := newKey(t)
	s, _ := Issue(priv, goodParams())
	// Hack the expiry into the past and re-sign so the only failure
	// mode is the TTL check.
	s.Passport.ExpiresAt = time.Now().Add(-1 * time.Minute)
	s.Passport.IssuedAt = s.Passport.ExpiresAt.Add(-5 * time.Minute)
	body, _ := json.Marshal(s.Passport)
	sig := ed25519.Sign(priv, body)
	s.Signature = base64.StdEncoding.EncodeToString(sig)

	if _, err := Verify(pub, s); err == nil {
		t.Error("expected expired error")
	}
}

func TestVerify_RejectsForeignKey(t *testing.T) {
	_, priv := newKey(t)
	otherPub, _ := newKey(t)
	s, _ := Issue(priv, goodParams())
	if _, err := Verify(otherPub, s); err == nil {
		t.Error("Verify with wrong pubkey should fail")
	}
}

func TestStore_Issue_VerifyActive(t *testing.T) {
	_, priv := newKey(t)
	st := NewStore(priv)
	s, err := st.Issue(goodParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.VerifyActive(s); err != nil {
		t.Errorf("VerifyActive: %v", err)
	}
}

func TestStore_Revoke(t *testing.T) {
	_, priv := newKey(t)
	st := NewStore(priv)
	s, _ := st.Issue(goodParams())
	st.Revoke(s.Passport.ID)
	if _, err := st.VerifyActive(s); err == nil {
		t.Error("VerifyActive on revoked passport should fail")
	}
}

func TestStore_ActiveDestinations_FiltersByClass(t *testing.T) {
	_, priv := newKey(t)
	st := NewStore(priv)

	p1 := goodParams()
	p1.DataClasses = []string{"pii"}
	p1.DestCIDRs = []string{"10.1.0.0/16"}
	if _, err := st.Issue(p1); err != nil {
		t.Fatal(err)
	}

	p2 := goodParams()
	p2.DataClasses = []string{"backup"}
	p2.DestCIDRs = []string{"10.2.0.0/16"}
	if _, err := st.Issue(p2); err != nil {
		t.Fatal(err)
	}

	cidrs, _, _ := st.ActiveDestinations("pii")
	if len(cidrs) != 1 || cidrs[0].String() != "10.1.0.0/16" {
		t.Errorf("pii destinations = %v, want [10.1.0.0/16]", cidrs)
	}
	cidrs, _, _ = st.ActiveDestinations("backup")
	if len(cidrs) != 1 || cidrs[0].String() != "10.2.0.0/16" {
		t.Errorf("backup destinations = %v, want [10.2.0.0/16]", cidrs)
	}
	cidrs, _, _ = st.ActiveDestinations("never-issued")
	if len(cidrs) != 0 {
		t.Errorf("unknown class should return no destinations, got %v", cidrs)
	}
}

func TestStore_ActiveDestinations_DropsExpired(t *testing.T) {
	_, priv := newKey(t)
	st := NewStore(priv)
	// Issue, then force-expire by directly manipulating the byID map.
	s, _ := st.Issue(goodParams())
	st.mu.Lock()
	stored := st.byID[s.Passport.ID]
	stored.Passport.ExpiresAt = time.Now().Add(-1 * time.Minute)
	st.byID[s.Passport.ID] = stored
	st.mu.Unlock()

	cidrs, _, _ := st.ActiveDestinations("pii")
	if len(cidrs) != 0 {
		t.Errorf("expired passport should not contribute destinations, got %v", cidrs)
	}
	// Hot-path also swept it.
	if st.Stats().Active != 0 {
		t.Errorf("expired passport should be swept, Active = %d", st.Stats().Active)
	}
}

func TestStore_List_HidesExpired(t *testing.T) {
	_, priv := newKey(t)
	st := NewStore(priv)
	s, _ := st.Issue(goodParams())
	st.mu.Lock()
	stored := st.byID[s.Passport.ID]
	stored.Passport.ExpiresAt = time.Now().Add(-1 * time.Minute)
	st.byID[s.Passport.ID] = stored
	st.mu.Unlock()
	if len(st.List()) != 0 {
		t.Error("List should hide expired passports")
	}
}

func TestStore_ExactIPBecomesSlash32(t *testing.T) {
	_, priv := newKey(t)
	st := NewStore(priv)
	p := goodParams()
	p.DestCIDRs = nil
	p.DestIPs = []string{"203.0.113.7"}
	if _, err := st.Issue(p); err != nil {
		t.Fatal(err)
	}
	cidrs, _, _ := st.ActiveDestinations("pii")
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 cidr, got %v", cidrs)
	}
	ones, _ := cidrs[0].Mask.Size()
	if ones != 32 {
		t.Errorf("ip-as-cidr should be /32, got /%d", ones)
	}
	if !cidrs[0].Contains(net.ParseIP("203.0.113.7")) {
		t.Errorf("exact-ip cidr should contain the original IP")
	}
}
