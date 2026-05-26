package brp

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

func newKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

func minimalProfile() Profile {
	return Profile{
		SchemaVersion: SchemaVersion,
		ProfileID:     "brp-nginx-1.24.0-debian12-reverse-proxy-v1",
		Confidence:    ConfidenceStrict,
		SampleCount:   42,
		FleetCount:    50,
		SigningEpoch:  time.Now().UnixNano(),
		VersionRange:  "1.24.0",
		Key: parser.ProfileKey{
			App:                "nginx",
			VersionFamily:      "1.24.x",
			OSFamily:           "debian12",
			PackageOrigin:      "deb",
			Role:               "nginx-reverse-proxy",
			FeatureFingerprint: "abc123",
		},
		Behavior: parser.ConfigDerivedBehavior{
			Role:        "nginx-reverse-proxy",
			Features:    []string{"proxy_pass", "tls"},
			ListenPorts: []int{443},
			ReadRoots:   []string{"/etc/nginx/", "/etc/ssl/"},
			WriteRoots:  []string{"/var/log/nginx/"},
		},
	}
}

func TestSign_Verify_RoundTrip(t *testing.T) {
	pub, priv := newKeys(t)
	sp, err := Sign(minimalProfile(), "xhelix-test", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sp.Algorithm != "ed25519" {
		t.Errorf("Algorithm = %q, want ed25519", sp.Algorithm)
	}
	if sp.Signer != "xhelix-test" {
		t.Errorf("Signer = %q, want xhelix-test", sp.Signer)
	}
	if err := Verify(sp, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv := newKeys(t)
	otherPub, _ := newKeys(t)
	sp, _ := Sign(minimalProfile(), "xhelix-test", priv)
	if err := Verify(sp, otherPub); err == nil {
		t.Fatal("Verify with wrong key should fail")
	} else if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("expected sig-mismatch error, got: %v", err)
	}
}

func TestVerify_TamperedProfile(t *testing.T) {
	pub, priv := newKeys(t)
	sp, _ := Sign(minimalProfile(), "xhelix-test", priv)

	// Tamper with the profile body after signing.
	sp.Profile.Behavior.ListenPorts = []int{80, 443} // added port 80
	if err := Verify(sp, pub); err == nil {
		t.Fatal("Verify of tampered profile should fail")
	}
}

func TestVerify_WrongAlgorithm(t *testing.T) {
	pub, priv := newKeys(t)
	sp, _ := Sign(minimalProfile(), "xhelix-test", priv)
	sp.Algorithm = "rsa-pss" // not supported
	if err := Verify(sp, pub); err == nil {
		t.Fatal("Verify of unsupported algorithm should fail")
	}
}

func TestSign_RejectsProtectedWriteRoot(t *testing.T) {
	_, priv := newKeys(t)
	p := minimalProfile()
	// Try to sign a profile granting write to /etc/shadow.
	p.Behavior.WriteRoots = []string{"/var/log/nginx/", "/etc/shadow"}
	_, err := Sign(p, "evil-signer", priv)
	if err == nil {
		t.Fatal("Sign should refuse a profile granting write to /etc/shadow")
	}
	if !strings.Contains(err.Error(), "protected path") {
		t.Errorf("expected protected-path error, got: %v", err)
	}
}

func TestSign_RejectsProtectedExecAllowed(t *testing.T) {
	_, priv := newKeys(t)
	p := minimalProfile()
	p.Behavior.ExecAllowed = []string{"/usr/local/psa/admin/bin/admin"}
	_, err := Sign(p, "evil-signer", priv)
	if err == nil {
		t.Fatal("Sign should refuse a profile listing protected ExecAllowed")
	}
}

func TestVerify_RejectsProtectedAfterSwap(t *testing.T) {
	// An attacker sign a benign profile with a legit key, then swaps
	// in WriteRoots that hit a protected path. The signature won't
	// match — Verify must catch BOTH (a) the cryptographic mismatch
	// AND (b) the protected-path violation. We assert the protected-
	// path check runs before signature verify (cheaper, fails fast).
	pub, priv := newKeys(t)
	sp, _ := Sign(minimalProfile(), "xhelix-test", priv)

	// Swap in a forbidden path. Both checks should fail this; we
	// want a clear error from the protected check first.
	sp.Profile.Behavior.WriteRoots = append(sp.Profile.Behavior.WriteRoots, "/etc/shadow")
	err := Verify(sp, pub)
	if err == nil {
		t.Fatal("expected Verify failure")
	}
	if !strings.Contains(err.Error(), "protected") {
		t.Errorf("expected protected-path error to fire first, got: %v", err)
	}
}

func TestProfile_Validate_Required(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Profile)
	}{
		{"empty profile_id", func(p *Profile) { p.ProfileID = "" }},
		{"zero schema_version", func(p *Profile) { p.SchemaVersion = 0 }},
		{"unknown confidence", func(p *Profile) { p.Confidence = ConfidenceUnknown }},
		{"empty key.App", func(p *Profile) { p.Key.App = "" }},
		{"zero signing_epoch", func(p *Profile) { p.SigningEpoch = 0 }},
		{"negative signing_epoch", func(p *Profile) { p.SigningEpoch = -1 }},
		{"future signing_epoch", func(p *Profile) { p.SigningEpoch = time.Now().Add(48 * time.Hour).UnixNano() }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := minimalProfile()
			c.mut(&p)
			if err := p.Validate(); err == nil {
				t.Errorf("Validate should fail for %s", c.name)
			}
		})
	}
}

func TestProfile_Validate_NewerSchemaRejected(t *testing.T) {
	p := minimalProfile()
	p.SchemaVersion = SchemaVersion + 1
	if err := p.Validate(); err == nil {
		t.Fatal("newer schema version must be rejected")
	} else if !strings.Contains(err.Error(), "newer than supported") {
		t.Errorf("expected schema-newer error, got: %v", err)
	}
}

func TestSign_FillsDefaults(t *testing.T) {
	_, priv := newKeys(t)
	p := minimalProfile()
	p.SchemaVersion = 0 // defaulted
	p.SigningEpoch = 0  // defaulted
	sp, err := Sign(p, "xhelix-test", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sp.Profile.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion not defaulted: %d", sp.Profile.SchemaVersion)
	}
	if sp.Profile.SigningEpoch == 0 {
		t.Error("SigningEpoch not defaulted")
	}
}

func TestSignedProfile_FileRoundTrip(t *testing.T) {
	pub, priv := newKeys(t)
	sp, err := Sign(minimalProfile(), "xhelix-test", priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	path := filepath.Join(t.TempDir(), "profile.signed.json")
	if err := WriteSigned(path, sp); err != nil {
		t.Fatalf("WriteSigned: %v", err)
	}
	loaded, err := LoadSigned(path)
	if err != nil {
		t.Fatalf("LoadSigned: %v", err)
	}
	if err := Verify(loaded, pub); err != nil {
		t.Fatalf("Verify after file round-trip: %v", err)
	}
	if loaded.Profile.ProfileID != sp.Profile.ProfileID {
		t.Errorf("ProfileID round-trip mismatch")
	}
}

func TestConfidenceClass_JSON_RoundTrip(t *testing.T) {
	cases := []ConfidenceClass{
		ConfidenceStrict, ConfidenceStableFallback,
		ConfidenceConstrainedAdaptation, ConfidenceUnprofiled,
	}
	for _, c := range cases {
		t.Run(c.String(), func(t *testing.T) {
			b, err := c.MarshalJSON()
			if err != nil {
				t.Fatalf("MarshalJSON: %v", err)
			}
			var out ConfidenceClass
			if err := out.UnmarshalJSON(b); err != nil {
				t.Fatalf("UnmarshalJSON: %v", err)
			}
			if out != c {
				t.Errorf("round-trip mismatch: %v vs %v", c, out)
			}
		})
	}
}

func TestCanonicalBytes_Deterministic(t *testing.T) {
	p := minimalProfile()
	b1, err1 := p.CanonicalBytes()
	b2, err2 := p.CanonicalBytes()
	if err1 != nil || err2 != nil {
		t.Fatalf("CanonicalBytes errors: %v %v", err1, err2)
	}
	if string(b1) != string(b2) {
		t.Error("CanonicalBytes is not deterministic across calls")
	}
}
