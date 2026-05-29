package egresspolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func samplePolicy() Policy {
	return Policy{
		SchemaVersion: SchemaVersion,
		Binary:        "/usr/bin/curl",
		Mode:          ModeDenyDefault,
		Signer:        "operator-test",
		SignedAt:      time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		Allow: []Rule{
			{DestClass: "cloudflare", Ports: []uint16{443}, Protocols: []string{"tcp"}},
			{SNI: "*.example.com", Ports: []uint16{443}},
		},
		Deny: []Rule{
			{Country: "RU"},
		},
		OnlyUIDs: []uint32{0, 1000},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	p := samplePolicy()
	sp, err := Sign(p, "operator-test", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(sp, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedPolicy(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, err := Sign(samplePolicy(), "operator-test", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Flip the mode after signing.
	sp.Policy.Mode = ModeAllowAny
	if err := Verify(sp, pub); err == nil {
		t.Fatalf("Verify should fail on tampered policy")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := Sign(samplePolicy(), "operator-test", priv)
	sp.Signature = "AAAA" + sp.Signature[4:]
	if err := Verify(sp, pub); err == nil {
		t.Fatalf("Verify should fail on tampered signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := Sign(samplePolicy(), "operator-test", priv)
	if err := Verify(sp, other); err == nil {
		t.Fatalf("Verify should fail with wrong pub key")
	}
}

func TestCanonicalBytesDeterministic(t *testing.T) {
	p := samplePolicy()
	// Add scope list in non-sorted order — canonical bytes must sort it.
	p.OnlyUIDs = []uint32{1000, 0, 33}
	p.OnlyCgroups = []string{"system", "user"}
	a, err := canonicalBytes(p)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	// Re-arrange scope lists — must still produce identical bytes.
	p2 := p
	p2.OnlyUIDs = []uint32{33, 1000, 0}
	p2.OnlyCgroups = []string{"user", "system"}
	b, err := canonicalBytes(p2)
	if err != nil {
		t.Fatalf("canonical2: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("canonical bytes not deterministic:\n--A--\n%s\n--B--\n%s", a, b)
	}
}

func TestValidateRejectsUnknownMode(t *testing.T) {
	p := samplePolicy()
	p.Mode = "wat"
	if err := p.Validate(); err == nil {
		t.Fatalf("Validate should reject unknown mode")
	}
}

func TestValidateRejectsBadCIDR(t *testing.T) {
	p := samplePolicy()
	p.Allow = []Rule{{DestCIDR: "not-a-cidr"}}
	if err := p.Validate(); err == nil {
		t.Fatalf("Validate should reject bad CIDR")
	}
}

func TestActionString(t *testing.T) {
	cases := map[Action]string{
		ActionAllow:   "allow",
		ActionObserve: "observe",
		ActionVerify:  "verify",
		ActionDeny:    "deny",
	}
	for a, want := range cases {
		if got := a.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", a, got, want)
		}
	}
}
