package source

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
)

func newMinter(t *testing.T) (*Minter, *Store) {
	t.Helper()
	s := openMem(t)
	return NewMinter(s, lineage.NewMinter(), lineage.NewStore(), "test-host"), s
}

func tagEvent(tags map[string]string) model.Event {
	ev := model.NewEvent("identity.test", model.SeverityInfo)
	ev.Tags = tags
	return ev
}

func TestMint_NonIdentityEvent_NoOp(t *testing.T) {
	m, _ := newMinter(t)
	id, err := m.MintFromEvent(context.Background(), tagEvent(map[string]string{"foo": "bar"}))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if id != 0 {
		t.Errorf("non-identity event should not mint, got id=%d", id)
	}
}

func TestMint_SSH_Success(t *testing.T) {
	m, s := newMinter(t)
	ctx := context.Background()
	ev := tagEvent(map[string]string{
		"service":  "sshd",
		"outcome":  "success",
		"method":   "publickey",
		"user":     "alice",
		"src_ip":   "203.0.113.7",
		"src_port": "51234",
		"key_fp":   "sha256:keyABC",
	})
	id, err := m.MintFromEvent(ctx, ev)
	if err != nil {
		t.Fatalf("MintFromEvent: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id for sshd success")
	}
	a, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get persisted: %v", err)
	}
	if a.Kind != KindSSH {
		t.Errorf("kind=%s want ssh", a.Kind)
	}
	if a.Actor != "alice" || a.SourceIP != "203.0.113.7" || a.SourcePort != 51234 || a.SSHKeyHash != "sha256:keyABC" {
		t.Errorf("anchor fields wrong: %+v", a)
	}
	if a.ParentAnchorID != 0 {
		t.Errorf("root SSH anchor should have parent=0, got %d", a.ParentAnchorID)
	}
	if a.Host != "test-host" {
		t.Errorf("host not stamped: %q", a.Host)
	}
}

func TestMint_SSH_FailureDoesNotMint(t *testing.T) {
	m, _ := newMinter(t)
	id, err := m.MintFromEvent(context.Background(), tagEvent(map[string]string{
		"service": "sshd",
		"outcome": "failure",
		"user":    "alice",
	}))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id != 0 {
		t.Errorf("failure event should not mint, got id=%d", id)
	}
}

func TestMint_Sudo_LinksToSSHParent(t *testing.T) {
	m, s := newMinter(t)
	ctx := context.Background()

	// Step 1: SSH success for alice.
	sshID, err := m.MintFromEvent(ctx, tagEvent(map[string]string{
		"service": "sshd", "outcome": "success", "user": "alice", "src_ip": "10.0.0.1",
	}))
	if err != nil || sshID == 0 {
		t.Fatalf("ssh mint: id=%d err=%v", sshID, err)
	}

	// Step 2: sudo from alice → root.
	sudoEv := tagEvent(map[string]string{
		"service": "sudo", "user": "alice", "target_user": "root", "tty": "pts/0", "command": "/bin/bash",
	})
	sudoEv.Time = time.Now()
	sudoID, err := m.MintFromEvent(ctx, sudoEv)
	if err != nil || sudoID == 0 {
		t.Fatalf("sudo mint: id=%d err=%v", sudoID, err)
	}

	sudo, err := s.Get(ctx, sudoID)
	if err != nil {
		t.Fatalf("Get sudo: %v", err)
	}
	if sudo.Kind != KindSudo {
		t.Errorf("kind=%s want sudo", sudo.Kind)
	}
	if sudo.ParentAnchorID != sshID {
		t.Errorf("sudo parent=%d want %d (ssh)", sudo.ParentAnchorID, sshID)
	}
	if sudo.Actor != "root" {
		t.Errorf("sudo Actor=%q want root (target_user)", sudo.Actor)
	}

	// Walking children of the SSH anchor should find the sudo.
	kids, err := s.Children(ctx, sshID)
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if len(kids) != 1 || kids[0].ID != sudoID {
		t.Errorf("ssh children unexpected: %+v", kids)
	}
}

func TestMint_Sudo_NoPriorSession_IsRoot(t *testing.T) {
	m, s := newMinter(t)
	ctx := context.Background()
	id, err := m.MintFromEvent(ctx, tagEvent(map[string]string{
		"service": "sudo", "user": "bob", "target_user": "root",
	}))
	if err != nil || id == 0 {
		t.Fatalf("sudo mint: id=%d err=%v", id, err)
	}
	a, _ := s.Get(ctx, id)
	if a.ParentAnchorID != 0 {
		t.Errorf("orphan sudo should be root anchor, got parent=%d", a.ParentAnchorID)
	}
}

func TestMint_PAM_SessionOpen(t *testing.T) {
	m, s := newMinter(t)
	ctx := context.Background()
	id, err := m.MintFromEvent(ctx, tagEvent(map[string]string{
		"service":  "pam",
		"pam_type": "session_open",
		"user":     "alice",
		"src_ip":   "10.0.0.5",
	}))
	if err != nil || id == 0 {
		t.Fatalf("pam mint: id=%d err=%v", id, err)
	}
	a, _ := s.Get(ctx, id)
	if a.Kind != KindPAM {
		t.Errorf("kind=%s want pam", a.Kind)
	}
}

func TestMint_PAM_OtherTypeDoesNotMint(t *testing.T) {
	m, _ := newMinter(t)
	id, _ := m.MintFromEvent(context.Background(), tagEvent(map[string]string{
		"service": "pam", "pam_type": "auth_success", "user": "alice",
	}))
	if id != 0 {
		t.Errorf("non session_open should not mint, got id=%d", id)
	}
}

func TestMint_Cron(t *testing.T) {
	m, s := newMinter(t)
	ctx := context.Background()
	id, err := m.MintFromEvent(ctx, tagEvent(map[string]string{
		"service":    "cron",
		"cron_entry": "logrotate.daily",
		"user":       "root",
	}))
	if err != nil || id == 0 {
		t.Fatalf("cron mint: id=%d err=%v", id, err)
	}
	a, _ := s.Get(ctx, id)
	if a.Kind != KindCron {
		t.Errorf("kind=%s want cron", a.Kind)
	}
	if a.Unit != "logrotate.daily" {
		t.Errorf("cron_entry should land in Unit, got %q", a.Unit)
	}
}

func TestMint_Systemd_Start(t *testing.T) {
	m, s := newMinter(t)
	ctx := context.Background()
	id, err := m.MintFromEvent(ctx, tagEvent(map[string]string{
		"service":     "systemd",
		"unit_action": "start",
		"unit":        "nginx.service",
	}))
	if err != nil || id == 0 {
		t.Fatalf("systemd mint: id=%d err=%v", id, err)
	}
	a, _ := s.Get(ctx, id)
	if a.Kind != KindSystemd {
		t.Errorf("kind=%s want systemd", a.Kind)
	}
	if a.Unit != "nginx.service" {
		t.Errorf("unit=%q want nginx.service", a.Unit)
	}
}

func TestMint_Systemd_NonStartDoesNotMint(t *testing.T) {
	m, _ := newMinter(t)
	id, _ := m.MintFromEvent(context.Background(), tagEvent(map[string]string{
		"service": "systemd", "unit_action": "stop", "unit": "nginx.service",
	}))
	if id != 0 {
		t.Errorf("stop should not mint, got id=%d", id)
	}
}

func TestMint_OriginsAlsoPopulated(t *testing.T) {
	// The in-memory lineage.Store is the hot-path for the rule engine and
	// must receive Origins in lock-step with persistent anchors.
	store := openMem(t)
	origins := lineage.NewStore()
	m := NewMinter(store, lineage.NewMinter(), origins, "test-host")
	ctx := context.Background()

	id, err := m.MintFromEvent(ctx, tagEvent(map[string]string{
		"service": "sshd", "outcome": "success", "user": "alice", "src_ip": "1.2.3.4",
	}))
	if err != nil || id == 0 {
		t.Fatalf("mint: %v id=%d", err, id)
	}
	o, ok := origins.Get(id)
	if !ok {
		t.Fatalf("origin %d not in lineage.Store", id)
	}
	if o.Type != lineage.RootSSH || o.UserName != "alice" || o.SourceIP != "1.2.3.4" {
		t.Errorf("origin populated wrong: %+v", o)
	}
}

func TestMint_NoStoreOptional(t *testing.T) {
	// Minter with nil Store should still mint into the in-memory Origin
	// store and return a non-zero id (useful for tests / dry-run modes).
	m := NewMinter(nil, lineage.NewMinter(), lineage.NewStore(), "no-disk")
	id, err := m.MintFromEvent(context.Background(), tagEvent(map[string]string{
		"service": "sshd", "outcome": "success", "user": "alice",
	}))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero id with nil store")
	}
}
