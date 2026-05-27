package memhardening

import (
	"bytes"
	"testing"
)

func TestSecretBytes_WipeZeroes(t *testing.T) {
	s := NewSecret(8)
	copy(s.Bytes(), []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if s.Len() != 8 {
		t.Fatalf("len=%d want 8", s.Len())
	}
	s.Wipe()
	if s.Len() != 0 {
		t.Errorf("Wipe should reset Len to 0, got %d", s.Len())
	}
	if s.Bytes() != nil {
		t.Errorf("Wipe should release buffer, got %v", s.Bytes())
	}
}

func TestSecretBytes_FromBytesZeroesSource(t *testing.T) {
	src := []byte("hunter2!")
	s := FromBytes(src)
	defer s.Wipe()
	if !bytes.Equal(src, []byte{0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("FromBytes should zero source, got %v", src)
	}
	if string(s.Bytes()) != "hunter2!" {
		t.Errorf("secret buffer should retain content, got %q", s.Bytes())
	}
}

func TestSecretBytes_WipeIdempotent(t *testing.T) {
	s := NewSecret(4)
	s.Wipe()
	s.Wipe() // should not panic
	var nilSec *SecretBytes
	nilSec.Wipe() // should not panic
}

func TestApply_ZeroConfigIsNoop(t *testing.T) {
	// Just verify Apply doesn't panic on zero-value config.
	Apply(Config{}, nil)
}
