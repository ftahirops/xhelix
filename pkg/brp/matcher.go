package brp

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// MatchInput is the bundle of identity facts the runtime knows about a
// process it wants to resolve to a profile. The fields mirror
// parser.ProfileKey (App, Role, FeatureFingerprint) plus the
// inventory-supplied (Version, OSFamily, PackageOrigin) and the
// process's actual binary hash for cross-checking.
type MatchInput struct {
	BinaryHash         string // sha256 hex of the executing binary
	App                string // "nginx", "apache", etc.
	Version            string // "1.24.0"
	OSFamily           string // "debian12"
	PackageOrigin      string // "deb", "rpm", "source"
	Role               string // parser-derived ("nginx-reverse-proxy")
	FeatureFingerprint string // parser-derived
}

// MatchResult is the outcome of Matcher.Match. Profile may be nil if
// ConfidenceUnprofiled — callers MUST check Confidence before
// dereferencing Profile.
type MatchResult struct {
	Profile    *Profile
	Confidence ConfidenceClass
	Reason     string // operator-readable explanation, e.g. "strict match" / "nearest version 1.24.x (was 1.24.0)" / "no matching profile"
}

// Matcher holds a library of signature-verified profiles and resolves
// runtime MatchInput values to (profile, confidence) pairs.
//
// Loading a profile verifies its signature against the configured
// trust root before it joins the library. Unverified profiles are
// REJECTED — there is no "load anyway and warn" mode.
//
// Safe for concurrent use; the library is replaceable atomically via
// LoadDir, and Match takes only a read lock.
type Matcher struct {
	mu             sync.RWMutex
	library        []*SignedProfile
	trustedPubKeys map[string]ed25519.PublicKey
}

// NewMatcher returns an empty matcher whose trusted signers are given
// by trustedKeys (signer name → public key). Profile load operations
// reject any signed profile whose Signer is not in this map.
//
// The map may be nil — in that case the matcher loads no profiles at
// all (every Match returns Unprofiled). This is the safe default for
// air-gapped operators who haven't configured a trust root yet.
func NewMatcher(trustedKeys map[string]ed25519.PublicKey) *Matcher {
	if trustedKeys == nil {
		trustedKeys = map[string]ed25519.PublicKey{}
	}
	return &Matcher{trustedPubKeys: trustedKeys}
}

// AddProfile validates and adds a single signed profile to the library.
// The signer MUST be in the trust root and the signature MUST verify.
// On any failure the library is unchanged.
func (m *Matcher) AddProfile(sp SignedProfile) error {
	pub, ok := m.trustedPubKeys[sp.Signer]
	if !ok {
		return fmt.Errorf("signer %q not in trust root", sp.Signer)
	}
	if err := Verify(sp, pub); err != nil {
		return fmt.Errorf("verify %s: %w", sp.Profile.ProfileID, err)
	}
	m.mu.Lock()
	m.library = append(m.library, &sp)
	m.mu.Unlock()
	return nil
}

// LoadDir loads every *.signed.json file under dir into the library.
// Returns counts (loaded, rejected) and the first I/O error (per-file
// signature failures are reported as rejections, not errors).
//
// A typical operator deployment ships profiles under
// /usr/share/xhelix/brp/ and operator-local overlays under
// /etc/xhelix/brp/ — call LoadDir twice with both roots to compose them.
func (m *Matcher) LoadDir(dir string) (loaded, rejected int, err error) {
	if _, statErr := os.Stat(dir); statErr != nil {
		// Missing dir is not an error — defer to caller to decide.
		if os.IsNotExist(statErr) {
			return 0, 0, nil
		}
		return 0, 0, statErr
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("read %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".signed.json") {
			continue
		}
		path := filepath.Join(dir, name)
		sp, lerr := LoadSigned(path)
		if lerr != nil {
			rejected++
			continue
		}
		if aerr := m.AddProfile(sp); aerr != nil {
			rejected++
			continue
		}
		loaded++
	}
	return loaded, rejected, nil
}

// Size returns the number of profiles currently loaded.
func (m *Matcher) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.library)
}

// Profiles returns a snapshot copy of the loaded Profile records. Safe
// to publish to callers; modifications to the returned slice do not
// affect the matcher's library. Order is library-insertion order.
func (m *Matcher) Profiles() []Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Profile, 0, len(m.library))
	for _, sp := range m.library {
		out = append(out, sp.Profile)
	}
	return out
}

// Match returns the best profile + applied confidence for in.
//
// Resolution order (most-specific first):
//
//  1. STRICT — exact match on (App, Version, OSFamily, PackageOrigin,
//     Role, FeatureFingerprint). Confidence = the profile's declared
//     Confidence (must itself be ConfidenceStrict to qualify).
//
//  2. STABLE FALLBACK — same App + matching VersionFamily prefix +
//     OSFamily + Role; FeatureFingerprint differs. Confidence is
//     downgraded to ConfidenceStableFallback regardless of profile's
//     declared value.
//
//  3. CONSTRAINED ADAPTATION — same App + Role only (any version, any
//     OS). Confidence is ConfidenceConstrainedAdaptation.
//
//  4. UNPROFILED — no match. Profile = nil, Confidence =
//     ConfidenceUnprofiled.
//
// The applied confidence is min(profile's declared, match-level cap).
// A profile declared as ConfidenceStableFallback never returns as
// Strict even on a strict match — the operator gets the conservative
// view by default.
func (m *Matcher) Match(in MatchInput) MatchResult {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if in.App == "" {
		return MatchResult{Confidence: ConfidenceUnprofiled, Reason: "no app fingerprint"}
	}

	// Collect candidates by App match. Library is small (dozens of
	// profiles); linear scan is fine.
	var byApp []*SignedProfile
	for _, sp := range m.library {
		if sp.Profile.Key.App == in.App {
			byApp = append(byApp, sp)
		}
	}
	if len(byApp) == 0 {
		return MatchResult{Confidence: ConfidenceUnprofiled, Reason: "no profile for app " + in.App}
	}

	// Pass 1 — STRICT.
	for _, sp := range byApp {
		k := sp.Profile.Key
		if k.OSFamily == in.OSFamily &&
			k.PackageOrigin == in.PackageOrigin &&
			k.Role == in.Role &&
			k.FeatureFingerprint == in.FeatureFingerprint &&
			versionMatchExact(sp.Profile.VersionRange, in.Version) {
			return MatchResult{
				Profile:    &sp.Profile,
				Confidence: minConfidence(sp.Profile.Confidence, ConfidenceStrict),
				Reason:     "strict match",
			}
		}
	}

	// Pass 2 — STABLE FALLBACK: relax FeatureFingerprint but require
	// OSFamily + Role + VersionFamily match.
	for _, sp := range byApp {
		k := sp.Profile.Key
		if k.OSFamily == in.OSFamily &&
			k.Role == in.Role &&
			versionMatchFamily(sp.Profile.VersionRange, in.Version) {
			return MatchResult{
				Profile:    &sp.Profile,
				Confidence: minConfidence(sp.Profile.Confidence, ConfidenceStableFallback),
				Reason:     fmt.Sprintf("stable_fallback: feature_fingerprint differs (profile=%s)", sp.Profile.VersionRange),
			}
		}
	}

	// Pass 3 — CONSTRAINED ADAPTATION: same App + Role only.
	for _, sp := range byApp {
		if sp.Profile.Key.Role == in.Role {
			return MatchResult{
				Profile:    &sp.Profile,
				Confidence: ConfidenceConstrainedAdaptation,
				Reason: fmt.Sprintf("constrained_adaptation: nearest %s role (profile %s)",
					in.Role, sp.Profile.VersionRange),
			}
		}
	}

	return MatchResult{
		Confidence: ConfidenceUnprofiled,
		Reason:     fmt.Sprintf("no profile matches app=%s role=%s version=%s", in.App, in.Role, in.Version),
	}
}

// versionMatchExact returns true if profileRange covers binaryVersion
// exactly. For now we treat exact-version as exact string equality
// AND the trivial case where profileRange ends in ".0" (so an installed
// "1.24" matches a profile range of "1.24.0").
func versionMatchExact(profileRange, binaryVersion string) bool {
	if profileRange == "" && binaryVersion == "" {
		return true
	}
	if profileRange == binaryVersion {
		return true
	}
	// Tolerate "1.24" == "1.24.0".
	if strings.HasSuffix(profileRange, ".0") &&
		strings.TrimSuffix(profileRange, ".0") == binaryVersion {
		return true
	}
	if strings.HasSuffix(binaryVersion, ".0") &&
		strings.TrimSuffix(binaryVersion, ".0") == profileRange {
		return true
	}
	return false
}

// versionMatchFamily returns true if binaryVersion lies inside the
// VersionFamily window represented by profileRange.
//
// Supported forms:
//
//   - "1.24.0"   — exact, matches itself only
//   - "1.24.x"   — minor-family, matches 1.24.anything
//   - "1.x"      — major-family, matches 1.anything
//   - "1.24.*"   — wildcard variant of 1.24.x
//
// Designed to be conservative: ambiguous input is treated as "no match"
// rather than over-broad.
func versionMatchFamily(profileRange, binaryVersion string) bool {
	if profileRange == "" || binaryVersion == "" {
		return false
	}
	// Exact match counts as family match too.
	if profileRange == binaryVersion {
		return true
	}
	// Replace ".x" or ".*" suffix with "." prefix for the binary.
	for _, suffix := range []string{".x", ".*"} {
		if strings.HasSuffix(profileRange, suffix) {
			prefix := strings.TrimSuffix(profileRange, suffix) + "."
			if strings.HasPrefix(binaryVersion, prefix) {
				return true
			}
		}
	}
	return false
}

// minConfidence returns the more-conservative (numerically larger in
// the const block, since smaller-number = more-trusted) of two classes.
//
// ConfidenceStrict(1) < ConfidenceStableFallback(2) <
// ConfidenceConstrainedAdaptation(3) < ConfidenceUnprofiled(4)
func minConfidence(a, b ConfidenceClass) ConfidenceClass {
	if a == ConfidenceUnknown {
		return b
	}
	if b == ConfidenceUnknown {
		return a
	}
	if a > b {
		return a
	}
	return b
}
