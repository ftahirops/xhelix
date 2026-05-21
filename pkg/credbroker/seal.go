package credbroker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Sealer wraps the cryptographic primitive. The default
// implementation is AES-256-GCM with a per-secret random nonce.
//
// Future Sealer implementations will plug in TPM-sealed or KMS-
// wrapped keys (the LOW_FALSE_POSITIVE doc §7.1 honesty about
// "off-host or hardware-backed custody improves resistance").
// USG.1a ships the file-backed key only.
type Sealer interface {
	// Seal encrypts plaintext under the sealer's master key.
	// Returns ciphertext suitable for embedding in a sealed file.
	Seal(plaintext []byte) ([]byte, error)
	// Unseal reverses Seal. Returns an error if the ciphertext
	// has been tampered with (GCM authentication failure).
	Unseal(ciphertext []byte) ([]byte, error)
	// KeyID identifies this sealer's master key for rotation.
	KeyID() string
}

// AESGCMSealer uses AES-256-GCM. The master key is 32 bytes.
// Ciphertext layout: [12-byte nonce][gcm-ciphertext-with-tag].
type AESGCMSealer struct {
	key   []byte // 32 bytes
	keyID string
}

// NewAESGCMSealer wraps a 32-byte master key. Returns error if
// len(key) != 32.
func NewAESGCMSealer(key []byte, keyID string) (*AESGCMSealer, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("credbroker: master key must be 32 bytes, got %d", len(key))
	}
	if keyID == "" {
		keyID = "default"
	}
	// Make a defensive copy so the caller can zero their slice.
	k := make([]byte, 32)
	copy(k, key)
	return &AESGCMSealer{key: k, keyID: keyID}, nil
}

// Seal implements Sealer.
func (s *AESGCMSealer) Seal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	// gcm.Seal returns nonce || ciphertext || tag when first arg
	// is nil-with-cap; we explicitly prepend the nonce so the
	// layout is unambiguous on disk.
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Unseal implements Sealer.
func (s *AESGCMSealer) Unseal(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ct := ciphertext[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// GCM Open returns a generic "message authentication failed"
		// on any tamper. We don't expose details — leaking which
		// bit was flipped helps an attacker.
		return nil, errors.New("credbroker: sealed object authentication failed")
	}
	return pt, nil
}

// KeyID implements Sealer.
func (s *AESGCMSealer) KeyID() string { return s.keyID }

// GenerateMasterKey returns a cryptographically-random 32-byte key.
// Used by the initial-setup flow when no key file exists yet.
func GenerateMasterKey() ([]byte, error) {
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	return k, nil
}
