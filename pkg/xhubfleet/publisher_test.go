package xhubfleet

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/baselinehub"
	"github.com/xhelix/xhelix/pkg/brp"
)

func mkSignableCandidate(t *testing.T) Candidate {
	t.Helper()
	idx := NewRarityIndex()
	tags := baselinehub.CohortTags{
		HostRole: "web", AppRole: "nginx",
		OSFamily: "debian12", PackageOrigin: "apt", VersionFamily: "1.24.x",
	}
	w := mkFullWindow("nginx",
		map[string]uint64{"worker": 5},
		map[string]uint64{"10.0.0.0/24:443": 1},
		map[string]uint64{"/var/log/nginx/access.log": 1},
		map[string]uint64{"tcp:443": 1},
	)
	ingestN(idx, tags, 10, w)
	cands := GenerateCandidates(idx, DefaultCandidateGates())
	if len(cands) != 1 {
		t.Fatalf("setup: want 1 candidate, got %d", len(cands))
	}
	return cands[0]
}

// NewPublisher creates the directory and initializes an empty feed.
func TestPublisher_NewCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feed")
	pub, err := NewPublisher(dir)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dir not created: %v", err)
	}
	if got := pub.Feed(); len(got) != 0 {
		t.Fatalf("expected empty feed, got %d", len(got))
	}
}

// Publish signs and writes the file to disk.
func TestPublisher_PublishWritesToDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feed")
	pub, err := NewPublisher(dir)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	cand := mkSignableCandidate(t)
	sp, err := pub.Publish(cand, "test-signer", priv)
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if sp.Profile.ProfileID == "" {
		t.Fatalf("missing profile_id")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 1 {
		t.Fatalf("expected 1 file on disk, got %d", len(files))
	}
}

// Feed returns published profiles, newest first.
func TestPublisher_FeedNewestFirst(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feed")
	pub, err := NewPublisher(dir)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	pub2 := pub
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Manually craft two SignedProfiles with distinct signing epochs.
	older := brp.SignedProfile{
		Profile: brp.Profile{
			SchemaVersion: brp.SchemaVersion,
			ProfileID:     "test-older",
			Confidence:    brp.ConfidenceStableFallback,
			SigningEpoch:  time.Now().Add(-time.Hour).UnixNano(),
		},
	}
	newer := brp.SignedProfile{
		Profile: brp.Profile{
			SchemaVersion: brp.SchemaVersion,
			ProfileID:     "test-newer",
			Confidence:    brp.ConfidenceStableFallback,
			SigningEpoch:  time.Now().UnixNano(),
		},
	}
	if err := pub2.PutSigned(older); err != nil {
		t.Fatalf("PutSigned older: %v", err)
	}
	if err := pub2.PutSigned(newer); err != nil {
		t.Fatalf("PutSigned newer: %v", err)
	}
	feed := pub2.Feed()
	if len(feed) != 2 {
		t.Fatalf("feed len=%d", len(feed))
	}
	if feed[0].Profile.ProfileID != "test-newer" {
		t.Fatalf("expected newest first, got %s", feed[0].Profile.ProfileID)
	}
	// keep priv referenced (gosec-style lint)
	_ = priv
}

// loadDir reloads after restart: a second NewPublisher on the same dir
// rebuilds the feed from on-disk files.
func TestPublisher_LoadDirRehydratesAfterRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "feed")
	pub, err := NewPublisher(dir)
	if err != nil {
		t.Fatalf("NewPublisher: %v", err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	cand := mkSignableCandidate(t)
	if _, err := pub.Publish(cand, "test-signer", priv); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Second instance: should pick up the file.
	pub2, err := NewPublisher(dir)
	if err != nil {
		t.Fatalf("NewPublisher (reopen): %v", err)
	}
	if got := pub2.Feed(); len(got) != 1 {
		t.Fatalf("after restart feed len=%d want 1", len(got))
	}
}
