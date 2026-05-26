package brp

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"

	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

// helper: build, sign, return a signed profile with given key bucketing.
func signedNginx(t *testing.T, priv ed25519.PrivateKey, signer, version, os, fp string) SignedProfile {
	t.Helper()
	p := minimalProfile()
	p.ProfileID = "brp-nginx-" + version + "-" + os + "-rp"
	p.VersionRange = version
	p.Key.VersionFamily = "1.24.x"
	p.Key.OSFamily = os
	p.Key.PackageOrigin = "deb"
	p.Key.Role = "nginx-reverse-proxy"
	p.Key.FeatureFingerprint = fp
	sp, err := Sign(p, signer, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sp
}

// makeMatcher creates a Matcher with one trusted signer + key.
func makeMatcher(t *testing.T) (*Matcher, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := NewMatcher(map[string]ed25519.PublicKey{"trusted": pub})
	return m, priv
}

func TestMatcher_NewEmpty(t *testing.T) {
	m := NewMatcher(nil)
	if m.Size() != 0 {
		t.Errorf("new matcher Size = %d, want 0", m.Size())
	}
	r := m.Match(MatchInput{App: "nginx"})
	if r.Confidence != ConfidenceUnprofiled {
		t.Errorf("empty library should return Unprofiled, got %v", r.Confidence)
	}
}

func TestMatcher_AddProfile_TrustRequired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := NewMatcher(map[string]ed25519.PublicKey{"only-trusted": pub})

	// Sign with a different signer name → not in trust root.
	sp := signedNginx(t, priv, "untrusted-signer", "1.24.0", "debian12", "fpA")
	if err := m.AddProfile(sp); err == nil {
		t.Fatal("AddProfile must reject untrusted signer")
	}
	if m.Size() != 0 {
		t.Errorf("size after rejection = %d, want 0", m.Size())
	}
}

func TestMatcher_StrictMatch(t *testing.T) {
	m, priv := makeMatcher(t)
	sp := signedNginx(t, priv, "trusted", "1.24.0", "debian12", "fpA")
	if err := m.AddProfile(sp); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	r := m.Match(MatchInput{
		App: "nginx", Version: "1.24.0", OSFamily: "debian12",
		PackageOrigin: "deb", Role: "nginx-reverse-proxy", FeatureFingerprint: "fpA",
	})
	if r.Confidence != ConfidenceStrict {
		t.Errorf("Confidence = %v, want strict", r.Confidence)
	}
	if r.Profile == nil || r.Profile.ProfileID != sp.Profile.ProfileID {
		t.Errorf("Profile mismatch: %+v", r.Profile)
	}
}

func TestMatcher_StableFallback_FeatureFingerprintDiffers(t *testing.T) {
	m, priv := makeMatcher(t)
	_ = m.AddProfile(signedNginx(t, priv, "trusted", "1.24.x", "debian12", "fpA"))

	// Same version family + OS + Role but different fingerprint.
	r := m.Match(MatchInput{
		App: "nginx", Version: "1.24.5", OSFamily: "debian12",
		PackageOrigin: "deb", Role: "nginx-reverse-proxy", FeatureFingerprint: "fpB",
	})
	if r.Confidence != ConfidenceStableFallback {
		t.Errorf("Confidence = %v, want stable_fallback", r.Confidence)
	}
	if r.Profile == nil {
		t.Fatal("expected a profile")
	}
}

func TestMatcher_ConstrainedAdaptation_AnyVersionAnyOS(t *testing.T) {
	m, priv := makeMatcher(t)
	_ = m.AddProfile(signedNginx(t, priv, "trusted", "1.24.x", "debian12", "fpA"))

	// Different OS, version doesn't match family.
	r := m.Match(MatchInput{
		App: "nginx", Version: "1.26.0", OSFamily: "rhel9",
		PackageOrigin: "rpm", Role: "nginx-reverse-proxy", FeatureFingerprint: "fpZ",
	})
	if r.Confidence != ConfidenceConstrainedAdaptation {
		t.Errorf("Confidence = %v, want constrained_adaptation", r.Confidence)
	}
	if r.Profile == nil {
		t.Fatal("expected a profile (any role match)")
	}
}

func TestMatcher_Unprofiled_NoRoleMatch(t *testing.T) {
	m, priv := makeMatcher(t)
	_ = m.AddProfile(signedNginx(t, priv, "trusted", "1.24.0", "debian12", "fpA"))

	// nginx is there but role is different.
	r := m.Match(MatchInput{
		App: "nginx", Version: "1.24.0", OSFamily: "debian12",
		PackageOrigin: "deb", Role: "nginx-static", FeatureFingerprint: "fpA",
	})
	if r.Confidence != ConfidenceUnprofiled {
		t.Errorf("Confidence = %v, want unprofiled", r.Confidence)
	}
	if r.Profile != nil {
		t.Errorf("expected nil profile, got %+v", r.Profile)
	}
}

func TestMatcher_Unprofiled_NoAppMatch(t *testing.T) {
	m, _ := makeMatcher(t)
	r := m.Match(MatchInput{App: "apache"}) // empty library + empty input
	if r.Confidence != ConfidenceUnprofiled {
		t.Errorf("Confidence = %v, want unprofiled", r.Confidence)
	}
}

func TestMatcher_LoadDir(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	m := NewMatcher(map[string]ed25519.PublicKey{"trusted": pub})

	dir := t.TempDir()
	// One valid profile.
	good := signedNginx(t, priv, "trusted", "1.24.0", "debian12", "fpA")
	if err := WriteSigned(filepath.Join(dir, "good.signed.json"), good); err != nil {
		t.Fatalf("WriteSigned: %v", err)
	}
	// One profile signed by an untrusted signer.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	bad := signedNginx(t, otherPriv, "different-signer", "1.26.0", "rhel9", "fpC")
	if err := WriteSigned(filepath.Join(dir, "bad.signed.json"), bad); err != nil {
		t.Fatalf("WriteSigned bad: %v", err)
	}
	// One non-profile file (should be skipped silently).
	_ = WriteSigned(filepath.Join(dir, "ignored.txt"), good)

	loaded, rejected, err := m.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if loaded != 1 {
		t.Errorf("loaded = %d, want 1", loaded)
	}
	if rejected != 1 {
		t.Errorf("rejected = %d, want 1", rejected)
	}
}

func TestMatcher_LoadDir_MissingDir(t *testing.T) {
	m, _ := makeMatcher(t)
	loaded, rejected, err := m.LoadDir("/nonexistent/brp")
	if err != nil {
		t.Errorf("missing dir should NOT be an error, got: %v", err)
	}
	if loaded != 0 || rejected != 0 {
		t.Errorf("missing dir: loaded=%d rejected=%d", loaded, rejected)
	}
}

func TestMatcher_TamperedProfileRejected(t *testing.T) {
	m, priv := makeMatcher(t)
	sp := signedNginx(t, priv, "trusted", "1.24.0", "debian12", "fpA")
	// Mutate the profile post-sign → signature should not verify.
	sp.Profile.Behavior.ListenPorts = []int{8080}
	if err := m.AddProfile(sp); err == nil {
		t.Fatal("tampered profile must be rejected")
	}
}

func TestVersionMatchFamily(t *testing.T) {
	cases := []struct {
		profile, binary string
		want            bool
	}{
		{"1.24.0", "1.24.0", true},
		{"1.24.x", "1.24.0", true},
		{"1.24.x", "1.24.5", true},
		{"1.24.x", "1.25.0", false},
		{"1.24.*", "1.24.7", true},
		{"1.x", "1.5.3", true},
		{"1.x", "2.5.3", false},
		{"", "1.24.0", false},
		{"1.24.0", "", false},
	}
	for _, c := range cases {
		got := versionMatchFamily(c.profile, c.binary)
		if got != c.want {
			t.Errorf("versionMatchFamily(%q, %q) = %v, want %v",
				c.profile, c.binary, got, c.want)
		}
	}
}

func TestVersionMatchExact(t *testing.T) {
	cases := []struct {
		profile, binary string
		want            bool
	}{
		{"1.24.0", "1.24.0", true},
		{"1.24.0", "1.24", true}, // tolerate .0 suffix
		{"1.24", "1.24.0", true},
		{"1.24.0", "1.24.5", false},
		{"1.24.x", "1.24.0", false}, // family is not exact
	}
	for _, c := range cases {
		got := versionMatchExact(c.profile, c.binary)
		if got != c.want {
			t.Errorf("versionMatchExact(%q, %q) = %v, want %v",
				c.profile, c.binary, got, c.want)
		}
	}
}

func TestMinConfidence(t *testing.T) {
	// Larger numeric value = more conservative class. min() returns the larger.
	cases := []struct {
		a, b, want ConfidenceClass
	}{
		{ConfidenceStrict, ConfidenceStableFallback, ConfidenceStableFallback},
		{ConfidenceStrict, ConfidenceStrict, ConfidenceStrict},
		{ConfidenceUnprofiled, ConfidenceStrict, ConfidenceUnprofiled},
		{ConfidenceUnknown, ConfidenceStrict, ConfidenceStrict},
		{ConfidenceStrict, ConfidenceUnknown, ConfidenceStrict},
	}
	for _, c := range cases {
		got := minConfidence(c.a, c.b)
		if got != c.want {
			t.Errorf("minConfidence(%v, %v) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// Suppress unused-import warning when the helper isn't exercised in
// every test. parser is used via the helper above.
var _ = parser.ProfileKey{}
