package netban

import (
	"context"
	"testing"
)

func TestQuarantineRefusesEmpty(t *testing.T) {
	b := NewBanner(nil, true)
	if err := b.EngageQuarantine(context.Background(), nil); err == nil {
		t.Fatal("expected error on empty allow-list")
	}
	if b.Quarantined() {
		t.Error("must not be engaged on error")
	}
}

func TestQuarantineRefusesInvalidIP(t *testing.T) {
	b := NewBanner(nil, true)
	err := b.EngageQuarantine(context.Background(), []string{"not-an-ip"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestQuarantineRequiresNFT(t *testing.T) {
	b := NewBanner(nil, false)
	err := b.EngageQuarantine(context.Background(), []string{"10.0.0.1"})
	if err == nil {
		t.Fatal("expected nft-required error")
	}
}
