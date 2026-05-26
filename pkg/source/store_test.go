package source

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
)

func openMem(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPutGet_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)

	want := Anchor{
		ID:         42,
		Kind:       KindSSH,
		CreatedAt:  time.Unix(1700000000, 0).UTC(),
		Host:       "plesk.example",
		Actor:      "alice",
		UID:        1000,
		LoginUID:   1000,
		SourceIP:   "203.0.113.7",
		SourcePort: 51234,
		SSHKeyHash: "sha256:abc123",
	}
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, 42)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

func TestPut_ZeroID_Rejected(t *testing.T) {
	if err := openMem(t).Put(context.Background(), Anchor{ID: 0, Kind: KindSSH}); err == nil {
		t.Fatal("expected error for ID=0")
	}
}

func TestGet_NotFound(t *testing.T) {
	_, err := openMem(t).Get(context.Background(), 999)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("want sql.ErrNoRows, got %v", err)
	}
}

func TestList_NewestFirst(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	base := time.Unix(1700000000, 0).UTC()
	for i := 1; i <= 5; i++ {
		err := s.Put(ctx, Anchor{
			ID:        lineage.LineageID(i),
			Kind:      KindSSH,
			CreatedAt: base.Add(time.Duration(i) * time.Second),
			Actor:     "u",
		})
		if err != nil {
			t.Fatalf("Put %d: %v", i, err)
		}
	}
	got, err := s.List(ctx, 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 anchors, got %d", len(got))
	}
	// Newest first → ID 5 down to 1.
	for i, a := range got {
		wantID := lineage.LineageID(5 - i)
		if a.ID != wantID {
			t.Errorf("idx %d: want ID %d, got %d", i, wantID, a.ID)
		}
	}
}

func TestChildren_PivotChain(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	base := time.Unix(1700000000, 0).UTC()

	// Root SSH session.
	if err := s.Put(ctx, Anchor{ID: 100, Kind: KindSSH, CreatedAt: base, Actor: "alice"}); err != nil {
		t.Fatalf("put root: %v", err)
	}
	// Two sudos descending from it.
	for i, sudoID := range []lineage.LineageID{200, 201} {
		err := s.Put(ctx, Anchor{
			ID:             sudoID,
			Kind:           KindSudo,
			ParentAnchorID: 100,
			CreatedAt:      base.Add(time.Duration(i+1) * time.Second),
			Actor:          "alice",
		})
		if err != nil {
			t.Fatalf("put sudo %d: %v", sudoID, err)
		}
	}
	// Unrelated cron — should NOT appear in children of 100.
	if err := s.Put(ctx, Anchor{ID: 300, Kind: KindCron, CreatedAt: base, Unit: "backup.timer"}); err != nil {
		t.Fatalf("put cron: %v", err)
	}

	kids, err := s.Children(ctx, 100)
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if len(kids) != 2 {
		t.Fatalf("want 2 children, got %d", len(kids))
	}
	// Oldest first.
	if kids[0].ID != 200 || kids[1].ID != 201 {
		t.Errorf("children order wrong: %d, %d", kids[0].ID, kids[1].ID)
	}
	for _, k := range kids {
		if k.ParentAnchorID != 100 {
			t.Errorf("child %d: parent want 100, got %d", k.ID, k.ParentAnchorID)
		}
		if k.Kind != KindSudo {
			t.Errorf("child %d: kind want sudo, got %s", k.ID, k.Kind)
		}
	}
}

func TestCount_AndSweep(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	old := time.Now().Add(-48 * time.Hour).UTC()
	recent := time.Now().UTC()

	put := func(id lineage.LineageID, ts time.Time) {
		t.Helper()
		err := s.Put(ctx, Anchor{ID: id, Kind: KindSSH, CreatedAt: ts, Actor: "u"})
		if err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	put(1, old)
	put(2, old)
	put(3, recent)

	n, err := s.Count(ctx)
	if err != nil || n != 3 {
		t.Fatalf("Count: n=%d err=%v", n, err)
	}

	cutoff := time.Now().Add(-24 * time.Hour)
	removed, err := s.SweepOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != 2 {
		t.Errorf("sweep removed %d, want 2", removed)
	}
	n, _ = s.Count(ctx)
	if n != 1 {
		t.Errorf("after sweep: count=%d, want 1", n)
	}
}

func TestPut_Replace(t *testing.T) {
	ctx := context.Background()
	s := openMem(t)
	now := time.Unix(1700000000, 0).UTC()

	if err := s.Put(ctx, Anchor{ID: 7, Kind: KindSSH, CreatedAt: now, Actor: "alice"}); err != nil {
		t.Fatalf("first put: %v", err)
	}
	// Replacement: same ID, updated actor + SSH key hash.
	if err := s.Put(ctx, Anchor{ID: 7, Kind: KindSSH, CreatedAt: now, Actor: "alice", SSHKeyHash: "sha256:new"}); err != nil {
		t.Fatalf("second put: %v", err)
	}
	got, err := s.Get(ctx, 7)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.SSHKeyHash != "sha256:new" {
		t.Errorf("expected SSHKeyHash=sha256:new, got %q", got.SSHKeyHash)
	}
}

func TestFromOrigin_Maps(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	o := lineage.Origin{
		ID:         50,
		Type:       lineage.RootSSH,
		CreatedAt:  now,
		UserName:   "bob",
		UID:        2000,
		LoginUID:   2000,
		SourceIP:   "198.51.100.4",
		SourcePort: 22000,
		SSHKeyHash: "sha256:keyXYZ",
	}
	a := FromOrigin(o, 0)
	if a.ID != 50 || a.Kind != KindSSH || a.ParentAnchorID != 0 {
		t.Errorf("FromOrigin core fields wrong: %+v", a)
	}
	if a.Actor != "bob" || a.SourceIP != "198.51.100.4" || a.SourcePort != 22000 || a.SSHKeyHash != "sha256:keyXYZ" {
		t.Errorf("FromOrigin field copy wrong: %+v", a)
	}

	// Cron uses CronEntry as Unit.
	o2 := lineage.Origin{ID: 60, Type: lineage.RootCron, CronEntry: "logrotate", CreatedAt: now}
	a2 := FromOrigin(o2, 0)
	if a2.Unit != "logrotate" {
		t.Errorf("cron Unit mapping wrong: got %q", a2.Unit)
	}
}

func TestKind_String(t *testing.T) {
	cases := map[Kind]string{
		KindSSH:     "ssh",
		KindPAM:     "pam",
		KindSudo:    "sudo",
		KindCron:    "cron",
		KindSystemd: "systemd",
		KindUnknown: "unknown",
		Kind(99):    "unknown",
	}
	for k, want := range cases {
		if got := k.String(); got != want {
			t.Errorf("Kind(%d): want %q got %q", k, want, got)
		}
	}
}

func TestKindFromRootType(t *testing.T) {
	cases := map[lineage.RootType]Kind{
		lineage.RootSSH:       KindSSH,
		lineage.RootPAM:       KindPAM,
		lineage.RootSudo:      KindSudo,
		lineage.RootCron:      KindCron,
		lineage.RootSystemd:   KindSystemd,
		lineage.RootContainer: KindUnknown,
		lineage.RootWeb:       KindUnknown,
		lineage.RootLocal:     KindUnknown,
		lineage.RootKernel:    KindUnknown,
		lineage.RootUnknown:   KindUnknown,
	}
	for rt, want := range cases {
		if got := KindFromRootType(rt); got != want {
			t.Errorf("KindFromRootType(%s): want %d got %d", rt, want, got)
		}
	}
}
