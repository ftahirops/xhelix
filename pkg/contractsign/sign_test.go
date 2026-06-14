package contractsign

import (
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv := genKey(t)
	trust := map[string]ed25519.PublicKey{"ci": pub}
	sig := Sign("wordpress", "deadbeef", priv)
	if err := Verify("wordpress", "deadbeef", "ci", sig, trust); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Wrong app / hash / signer must all fail.
	if Verify("other", "deadbeef", "ci", sig, trust) == nil {
		t.Error("signature must not verify for a different app")
	}
	if Verify("wordpress", "feedface", "ci", sig, trust) == nil {
		t.Error("signature must not verify for a different hash (drift)")
	}
	if Verify("wordpress", "deadbeef", "unknown", sig, trust) == nil {
		t.Error("signature from an untrusted signer must fail")
	}
}

func TestStore_AddRejectsUntrusted(t *testing.T) {
	pub, priv := genKey(t)
	_, roguePriv := genKey(t)
	s, err := Open(filepath.Join(t.TempDir(), "sig.db"), map[string]ed25519.PublicKey{"ci": pub})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Trusted signature → accepted.
	good := base64.StdEncoding.EncodeToString(Sign("app", "hash1", priv))
	if _, err := s.Add("app", "hash1", "ci", good); err != nil {
		t.Fatalf("trusted signature rejected: %v", err)
	}
	if ok, who := s.HasValid("app", "hash1"); !ok || who != "ci" {
		t.Errorf("HasValid should report ci, got ok=%v who=%q", ok, who)
	}

	// Signature from a rogue key claiming to be "ci" → rejected.
	rogue := base64.StdEncoding.EncodeToString(Sign("app", "hash2", roguePriv))
	if _, err := s.Add("app", "hash2", "ci", rogue); err == nil {
		t.Error("rogue signature must be rejected at Add")
	}
	if ok, _ := s.HasValid("app", "hash2"); ok {
		t.Error("rogue signature must not be stored")
	}
}

func TestStore_HasValidRejectsAfterKeyRevoked(t *testing.T) {
	pub, priv := genKey(t)
	path := filepath.Join(t.TempDir(), "sig.db")
	s, _ := Open(path, map[string]ed25519.PublicKey{"ci": pub})
	good := base64.StdEncoding.EncodeToString(Sign("app", "h", priv))
	if _, err := s.Add("app", "h", "ci", good); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.HasValid("app", "h"); !ok {
		t.Fatal("setup: should be valid")
	}
	s.Close()

	// Reopen with an EMPTY trust root (key revoked). The stored signature
	// must no longer count — HasValid re-verifies against current trust.
	s2, _ := Open(path, map[string]ed25519.PublicKey{})
	defer s2.Close()
	if ok, _ := s2.HasValid("app", "h"); ok {
		t.Error("revoked signer's signature must not count as valid")
	}
}

func TestStore_DriftBlocksOldSignature(t *testing.T) {
	pub, priv := genKey(t)
	s, _ := Open(filepath.Join(t.TempDir(), "sig.db"), map[string]ed25519.PublicKey{"ci": pub})
	defer s.Close()
	good := base64.StdEncoding.EncodeToString(Sign("app", "v1hash", priv))
	_, _ = s.Add("app", "v1hash", "ci", good)
	// The contract drifted → new hash. No signature exists for it.
	if ok, _ := s.HasValid("app", "v2hash"); ok {
		t.Error("unsigned drift (new hash) must NOT be considered signed")
	}
}
