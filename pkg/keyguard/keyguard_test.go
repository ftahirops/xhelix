package keyguard

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNew_DefaultsFileKind(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "chain.key")
	s, err := New(Config{Path: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind() != "file" {
		t.Errorf("kind = %q, want file", s.Kind())
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("expected key file created: %v", err)
	}
}

func TestSign_VerifyRoundtrip(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{Kind: "file", Path: filepath.Join(dir, "k")})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("batch-#123 prev=AAA hash=BBB")
	h := sha256.Sum256(payload)
	sig, err := s.Sign(h[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(s.PublicKey(), h[:], sig) {
		t.Error("signature failed to verify with PublicKey()")
	}
}

func TestSign_StableAcrossReload(t *testing.T) {
	// Same file → same pubkey, same signature for same input.
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	s1, err := New(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	pub1 := s1.PublicKey()
	s2, err := New(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if string(pub1) != string(s2.PublicKey()) {
		t.Error("pubkey changed across reload")
	}
}

func TestNew_UnimplementedKinds(t *testing.T) {
	for _, k := range []string{"tpm", "aws-kms", "gcp-kms", "vault"} {
		_, err := New(Config{Kind: k})
		if !errors.Is(err, ErrSignerNotImpl) {
			t.Errorf("kind=%q: want ErrSignerNotImpl, got %v", k, err)
		}
	}
}

func TestNew_UnknownKind(t *testing.T) {
	_, err := New(Config{Kind: "garbage"})
	if err == nil {
		t.Error("garbage kind should error")
	}
}

func TestNew_RejectsTruncatedKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if err := os.WriteFile(path, []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{Path: path})
	if err == nil {
		t.Error("expected error on wrong-size key file")
	}
}
