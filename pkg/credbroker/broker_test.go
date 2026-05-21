package credbroker

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// helper: build a broker with a deterministic key for tests.
func newTestBroker(t *testing.T) *Broker {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := NewAESGCMSealer(key, "test-key")
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return NewBroker(s, 0)
}

func TestSealUnsealRoundTrip(t *testing.T) {
	b := newTestBroker(t)
	plaintext := []byte("[default]\naws_access_key_id = AKIA...\naws_secret_access_key = wJal...\n")
	sf, err := b.Seal(plaintext, Meta{
		Class:    ClassAPIKey,
		Purpose:  "prod AWS creds",
		Issuer:   "operator:farhan",
		OrigPath: "/root/.aws/credentials",
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sf.Meta.Version != 1 {
		t.Errorf("Meta.Version = %d, want 1", sf.Meta.Version)
	}
	if sf.Meta.Created.IsZero() {
		t.Error("Created not stamped")
	}
	if sf.Meta.KeyID != "test-key" {
		t.Errorf("KeyID = %q, want test-key", sf.Meta.KeyID)
	}
	got, err := b.Unseal(sf)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("unseal: got %q, want %q", got, plaintext)
	}
}

func TestSealedFileWriteRead(t *testing.T) {
	b := newTestBroker(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ".aws", "credentials.sealed")

	pt := []byte("super secret content")
	sf, err := b.Seal(pt, Meta{Class: ClassCredentials, Purpose: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sf.Write(path); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Verify mode and dir mode.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 0600", info.Mode().Perm())
	}

	got, err := ReadSealed(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Meta.Purpose != "test" {
		t.Errorf("Meta.Purpose = %q, want test", got.Meta.Purpose)
	}
	plaintext, err := b.Unseal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, pt) {
		t.Errorf("round-trip mismatch")
	}
}

func TestTamperDetected(t *testing.T) {
	b := newTestBroker(t)
	sf, _ := b.Seal([]byte("secret"), Meta{Class: ClassAPIKey})
	// Flip one byte of ciphertext.
	sf.Ciphertext[len(sf.Ciphertext)/2] ^= 0xff
	if _, err := b.Unseal(sf); err == nil {
		t.Error("expected tamper-detection error, got nil")
	}
}

func TestKeyIDMismatchRefuses(t *testing.T) {
	b1 := newTestBroker(t)
	sf, _ := b1.Seal([]byte("secret"), Meta{Class: ClassAPIKey})

	// Different sealer (same key bytes but different KeyID).
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	other, _ := NewAESGCMSealer(key, "other-key")
	b2 := NewBroker(other, 0)
	if _, err := b2.Unseal(sf); err == nil {
		t.Error("expected keyID mismatch refusal, got nil")
	}
}

func TestDecideStubAllowAll(t *testing.T) {
	b := newTestBroker(t)
	pt := []byte("hello")
	sf, _ := b.Seal(pt, Meta{Class: ClassAPIKey})
	req := Request{
		SealedPath: "/test.sealed",
		PID:        1234,
		Lineage: []LineageNode{
			{PID: 1234, Comm: "bash", Image: "/bin/bash", UID: 0},
		},
		Now:    time.Unix(1000, 0),
		Reason: "test",
	}
	res := b.Decide(sf, req)
	if res.Outcome != OutcomeAllow {
		t.Errorf("Outcome = %s, want allow (stub policy)", res.Outcome)
	}
	if !bytes.Equal(res.Plaintext, pt) {
		t.Error("plaintext mismatch")
	}
	if res.Audit.PID != 1234 {
		t.Errorf("Audit.PID = %d, want 1234", res.Audit.PID)
	}
	hist := b.History()
	if len(hist) != 1 {
		t.Errorf("history len = %d, want 1", len(hist))
	}
}

func TestLoadOrCreateMasterKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	k1, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 {
		t.Errorf("len = %d, want 32", len(k1))
	}
	// Load again — must be the same key.
	k2, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("re-load returned a different key")
	}
}

func TestSealedFileFormatRobustToWhitespace(t *testing.T) {
	b := newTestBroker(t)
	sf, _ := b.Seal([]byte("data"), Meta{Class: ClassCredentials})
	dir := t.TempDir()
	path := filepath.Join(dir, "x.sealed")
	if err := sf.Write(path); err != nil {
		t.Fatal(err)
	}
	// Append trailing whitespace to simulate editor behaviour.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("\n\n   \n")
	_ = f.Close()
	got, err := ReadSealed(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	pt, err := b.Unseal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "data" {
		t.Errorf("got %q, want data", pt)
	}
}
