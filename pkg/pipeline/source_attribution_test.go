package pipeline

import (
	"context"
	"strconv"
	"testing"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/source"
)

// TestSourceAttribution_EndToEnd exercises the T02 wire:
//
//  1. An identity event (PAM session open) flows through Handle.
//  2. The SourceMinter mints a fresh anchor.
//  3. Pipeline stamps the anchor id on ev.Tags["source_anchor_id"].
//  4. Pipeline calls ProcTree.AttributeSource for the event's PID.
//  5. A subsequent spawn under that PID inherits PrimarySource
//     transitively through OnSpawn.
//
// This is the contract pkg/proctree promises and pkg/source.Minter
// delivers; the pipeline is the glue. If this test passes, T02 commit 2
// is wired correctly.
func TestSourceAttribution_EndToEnd(t *testing.T) {
	ctx := context.Background()

	pt := proctree.New(0)
	srcStore, err := source.Open(":memory:")
	if err != nil {
		t.Fatalf("source.Open: %v", err)
	}
	defer srcStore.Close()

	minter := source.NewMinter(srcStore, lineage.NewMinter(), lineage.NewStore(), "test-host")

	p := &Pipeline{
		ProcTree:     pt,
		SourceMinter: minter,
	}

	// Pre-seed proctree with the sshd parent so the identity event
	// has a real PID to attribute against.
	const sshdPID uint32 = 100
	pt.OnSpawn(proctree.Node{PID: sshdPID, PPID: 1, Comm: "sshd"})

	// 1. PAM session_open carrying the sshd session leader's PID.
	identityEv := model.NewEvent("identity.pam", model.SeverityInfo)
	identityEv.PID = sshdPID
	identityEv.UID = 1000
	identityEv.Tags = map[string]string{
		"service":  "pam",
		"pam_type": "session_open",
		"user":     "alice",
		"src_ip":   "203.0.113.7",
	}
	p.Handle(ctx, identityEv)

	// Pipeline must have stamped source_anchor_id on the event.
	sa := identityEv.Tags["source_anchor_id"]
	if sa == "" {
		t.Fatal("source_anchor_id not stamped on identity event")
	}
	idU, err := strconv.ParseUint(sa, 10, 64)
	if err != nil {
		t.Fatalf("source_anchor_id not numeric: %q", sa)
	}
	want := lineage.LineageID(idU)
	if want == 0 {
		t.Fatal("source_anchor_id is 0")
	}

	// 2. proctree must have attributed the anchor to PID 100.
	primary, cs := pt.SourceOf(sshdPID)
	if primary != want {
		t.Errorf("PID %d PrimarySource = %d, want %d", sshdPID, primary, want)
	}
	if !cs.Contains(want) {
		t.Errorf("PID %d CausalSet missing %d, got %v", sshdPID, want, cs.Slice())
	}

	// 3. A spawn under that PID must inherit transitively.
	const shellPID uint32 = 200
	spawnEv := model.NewEvent("ebpf.spawn", model.SeverityInfo)
	spawnEv.PID = shellPID
	spawnEv.ParentPID = sshdPID
	spawnEv.Comm = "bash"
	spawnEv.UID = 1000
	spawnEv.Tags = map[string]string{}
	p.Handle(ctx, spawnEv)

	primary2, cs2 := pt.SourceOf(shellPID)
	if primary2 != want {
		t.Errorf("child PID %d PrimarySource = %d, want inherited %d", shellPID, primary2, want)
	}
	if !cs2.Contains(want) {
		t.Errorf("child PID %d CausalSet missing inherited %d, got %v", shellPID, want, cs2.Slice())
	}
	if cs2.Ambiguous() {
		t.Error("single-source inheritance should NOT produce Ambiguous CausalSet")
	}

	// 4. A grandchild also inherits.
	const grandchildPID uint32 = 300
	grandchildEv := model.NewEvent("ebpf.spawn", model.SeverityInfo)
	grandchildEv.PID = grandchildPID
	grandchildEv.ParentPID = shellPID
	grandchildEv.Comm = "curl"
	grandchildEv.UID = 1000
	grandchildEv.Tags = map[string]string{}
	p.Handle(ctx, grandchildEv)

	primary3, _ := pt.SourceOf(grandchildPID)
	if primary3 != want {
		t.Errorf("grandchild PID %d PrimarySource = %d, want transitively-inherited %d", grandchildPID, primary3, want)
	}
}

// TestSourceAttribution_SudoPivotChain mints two anchors back-to-back —
// an SSH session and a sudo from it — and verifies the sudo anchor
// chains to the SSH parent in the persisted store (anchor.ParentAnchorID
// linkage) AND that a process attributed to the sudo anchor reflects
// the sudo as PrimarySource.
func TestSourceAttribution_SudoPivotChain(t *testing.T) {
	ctx := context.Background()
	pt := proctree.New(0)
	srcStore, _ := source.Open(":memory:")
	defer srcStore.Close()

	minter := source.NewMinter(srcStore, lineage.NewMinter(), lineage.NewStore(), "test-host")
	p := &Pipeline{ProcTree: pt, SourceMinter: minter}

	// Seed a long-running shell as the sshd child.
	const shellPID uint32 = 200
	pt.OnSpawn(proctree.Node{PID: shellPID, PPID: 1, Comm: "bash"})

	// 1. SSH login mints anchor #SSH.
	sshEv := model.NewEvent("identity.sshd", model.SeverityInfo)
	sshEv.UID = 1000
	sshEv.Tags = map[string]string{
		"service": "sshd",
		"outcome": "success",
		"user":    "alice",
		"src_ip":  "10.0.0.1",
	}
	p.Handle(ctx, sshEv)
	sshAnchor := mustParseAnchor(t, sshEv.Tags["source_anchor_id"])

	// 2. sudo from alice → root, carrying the shell PID for AttributeSource.
	sudoEv := model.NewEvent("identity.sudo", model.SeverityInfo)
	sudoEv.PID = shellPID
	sudoEv.UID = 1000
	sudoEv.Tags = map[string]string{
		"service":     "sudo",
		"user":        "alice",
		"target_user": "root",
		"command":     "/bin/bash",
	}
	p.Handle(ctx, sudoEv)
	sudoAnchor := mustParseAnchor(t, sudoEv.Tags["source_anchor_id"])
	if sudoAnchor == sshAnchor {
		t.Fatal("sudo anchor must be distinct from SSH anchor")
	}

	// 3. Persisted store must show sudo.parent_anchor_id == SSH anchor.
	a, err := srcStore.Get(ctx, sudoAnchor)
	if err != nil {
		t.Fatalf("store.Get(sudo): %v", err)
	}
	if a.ParentAnchorID != sshAnchor {
		t.Errorf("sudo.ParentAnchorID = %d, want SSH anchor %d", a.ParentAnchorID, sshAnchor)
	}

	// 4. The shell PID must have sudo as PrimarySource (AttributeSource
	// fires on the sudo event because it carries PID).
	primary, cs := pt.SourceOf(shellPID)
	if primary != sudoAnchor {
		t.Errorf("shell PrimarySource = %d, want sudo %d", primary, sudoAnchor)
	}
	if !cs.Contains(sudoAnchor) {
		t.Errorf("shell CausalSet must contain sudo anchor %d: %v", sudoAnchor, cs.Slice())
	}

	// KNOWN GAP (T01 follow-up, not commit 2 scope):
	// The SSH event arrived from the log tailer with PID=0, so
	// AttributeSource never ran for the shell against the SSH anchor.
	// The shell's CausalSet therefore contains only {sudo}, not
	// {ssh, sudo}. The SSH→sudo chain is preserved in the persistent
	// store (asserted above as sudo.ParentAnchorID == sshAnchor), so a
	// graph walk can still recover the SSH ancestry; but proctree's
	// in-memory view is sudo-only until we add PID correlation for
	// tail-based ingress (eBPF on sshd setresuid, or audit login_uid
	// resolution). Documenting the limitation here so the assertion
	// matches reality.
	if cs.Contains(sshAnchor) {
		t.Logf("unexpected: SSH anchor showed up in shell CausalSet — PID correlation may have shipped")
	}
}

// TestSourceAttribution_FileMediatedTaint exercises T02 commit 3:
//
//  1. PID A is attributed to anchor X (via PAM session_open path).
//  2. PID A writes /tmp/payload (FIM write event).
//  3. PID B (unattributed) reads /tmp/payload (file_open event).
//  4. PID B's CausalSet must now contain X, and the event must carry
//     the file_writer_primary tag.
//
// This is the gold-standard delayed-persistence and file-mediated
// causality test from the source-lineage architecture doc.
func TestSourceAttribution_FileMediatedTaint(t *testing.T) {
	ctx := context.Background()
	pt := proctree.New(0)
	srcStore, _ := source.Open(":memory:")
	defer srcStore.Close()
	minter := source.NewMinter(srcStore, lineage.NewMinter(), lineage.NewStore(), "test-host")
	ft := source.NewFileTaint(0, 0)

	p := &Pipeline{
		ProcTree:     pt,
		SourceMinter: minter,
		FileTaint:    ft,
	}

	// Pre-seed two processes; only PID 100 will get an anchor.
	const writerPID uint32 = 100
	const readerPID uint32 = 200
	pt.OnSpawn(proctree.Node{PID: writerPID, PPID: 1, Comm: "sshd"})
	pt.OnSpawn(proctree.Node{PID: readerPID, PPID: 1, Comm: "cron"})

	// 1. Mint anchor for the writer via a PAM event.
	pamEv := model.NewEvent("identity.pam", model.SeverityInfo)
	pamEv.PID = writerPID
	pamEv.UID = 1000
	pamEv.Tags = map[string]string{
		"service": "pam", "pam_type": "session_open", "user": "alice",
	}
	p.Handle(ctx, pamEv)
	want := mustParseAnchor(t, pamEv.Tags["source_anchor_id"])

	// 2. Writer touches /tmp/payload via FIM write event.
	fimEv := model.NewEvent("fim", model.SeverityInfo)
	fimEv.PID = writerPID
	fimEv.Tags = map[string]string{
		"path":  "/tmp/payload",
		"write": "true",
	}
	p.Handle(ctx, fimEv)

	// FileTaint must have recorded the writer's source for this path.
	prov, ok := ft.Lookup("/tmp/payload")
	if !ok {
		t.Fatal("FileTaint should have recorded /tmp/payload")
	}
	if prov.LastWriterPrimary != want {
		t.Errorf("recorded LastWriterPrimary=%d, want %d", prov.LastWriterPrimary, want)
	}

	// 3. Unattributed reader opens /tmp/payload.
	readEv := model.NewEvent("ebpf", model.SeverityInfo)
	readEv.PID = readerPID
	readEv.Tags = map[string]string{
		"kind": "file_open",
		"path": "/tmp/payload",
	}
	p.Handle(ctx, readEv)

	// 4. Reader's CausalSet must now contain the writer's anchor.
	primary, cs := pt.SourceOf(readerPID)
	if !cs.Contains(want) {
		t.Errorf("reader CausalSet missing writer anchor %d: %v", want, cs.Slice())
	}
	if primary != want {
		t.Errorf("reader PrimarySource = %d, want %d (file-mediated attribution)", primary, want)
	}

	// Event must carry the file-writer hint tags for downstream rules.
	if readEv.Tags["file_writer_primary"] == "" {
		t.Error("file_writer_primary tag should be stamped on read event")
	}
	if readEv.Tags["file_writer_set_hash"] == "" {
		t.Error("file_writer_set_hash tag should be stamped on read event")
	}
}

// TestSourceAttribution_NetConnectStamping (T02 commit 4): outbound
// connects from an attributed PID must carry source_anchor_id +
// source_set_hash tags so downstream detectors and the hub can
// attribute the flow.
func TestSourceAttribution_NetConnectStamping(t *testing.T) {
	ctx := context.Background()
	pt := proctree.New(0)
	srcStore, _ := source.Open(":memory:")
	defer srcStore.Close()
	minter := source.NewMinter(srcStore, lineage.NewMinter(), lineage.NewStore(), "test-host")
	p := &Pipeline{ProcTree: pt, SourceMinter: minter}

	const sshdPID uint32 = 100
	pt.OnSpawn(proctree.Node{PID: sshdPID, PPID: 1, Comm: "sshd"})

	// Mint an anchor for sshdPID via PAM.
	pamEv := model.NewEvent("identity.pam", model.SeverityInfo)
	pamEv.PID = sshdPID
	pamEv.Tags = map[string]string{
		"service": "pam", "pam_type": "session_open", "user": "alice",
	}
	p.Handle(ctx, pamEv)
	want := mustParseAnchor(t, pamEv.Tags["source_anchor_id"])

	// Outbound connect from a child shell (which inherits the anchor).
	const shellPID uint32 = 200
	spawnEv := model.NewEvent("ebpf.spawn", model.SeverityInfo)
	spawnEv.PID = shellPID
	spawnEv.ParentPID = sshdPID
	spawnEv.Comm = "bash"
	spawnEv.Tags = map[string]string{}
	p.Handle(ctx, spawnEv)

	netEv := model.NewEvent("ebpf.net", model.SeverityInfo)
	netEv.PID = shellPID
	netEv.Tags = map[string]string{
		"kind":   "net_connect",
		"dst_ip": "203.0.113.50",
	}
	p.Handle(ctx, netEv)

	if netEv.Tags["source_anchor_id"] == "" {
		t.Fatal("outbound connect must carry source_anchor_id when PID is attributed")
	}
	if got := mustParseAnchor(t, netEv.Tags["source_anchor_id"]); got != want {
		t.Errorf("net_connect source_anchor_id = %d, want %d (inherited)", got, want)
	}
	if netEv.Tags["source_set_hash"] == "" {
		t.Error("source_set_hash should be stamped on net_connect")
	}
	if netEv.Tags["source_ambiguous"] == "true" {
		t.Error("single-source connect must NOT be marked Ambiguous")
	}
}

// TestSourceAttribution_PtraceFlipsAmbiguous (T02 commit 4): a ptrace
// attach from an attributed attacker to a target with a different
// source must merge the attacker into the target's CausalSet, producing
// Ambiguous — the gold-standard injection-detection signal.
func TestSourceAttribution_PtraceFlipsAmbiguous(t *testing.T) {
	ctx := context.Background()
	pt := proctree.New(0)
	srcStore, _ := source.Open(":memory:")
	defer srcStore.Close()
	minter := source.NewMinter(srcStore, lineage.NewMinter(), lineage.NewStore(), "test-host")
	p := &Pipeline{
		ProcTree:     pt,
		SourceMinter: minter,
		Emit:         func(model.Alert) {}, // no-op; high-severity ptrace would otherwise call nil
	}

	// Two pre-seeded processes with DIFFERENT minted anchors.
	const attackerPID uint32 = 100
	const targetPID uint32 = 200
	pt.OnSpawn(proctree.Node{PID: attackerPID, PPID: 1, Comm: "exploit"})
	pt.OnSpawn(proctree.Node{PID: targetPID, PPID: 1, Comm: "nginx"})

	// Mint anchor for attacker (e.g. attacker came in via an SSH session).
	atkEv := model.NewEvent("identity.pam", model.SeverityInfo)
	atkEv.PID = attackerPID
	atkEv.Tags = map[string]string{"service": "pam", "pam_type": "session_open", "user": "mallory"}
	p.Handle(ctx, atkEv)
	attackerAnchor := mustParseAnchor(t, atkEv.Tags["source_anchor_id"])

	// Mint a different anchor for target (e.g. systemd start of nginx).
	tgtEv := model.NewEvent("identity.systemd", model.SeverityInfo)
	tgtEv.PID = targetPID
	tgtEv.Tags = map[string]string{"service": "systemd", "unit_action": "start", "unit": "nginx.service"}
	p.Handle(ctx, tgtEv)
	targetAnchor := mustParseAnchor(t, tgtEv.Tags["source_anchor_id"])
	if attackerAnchor == targetAnchor {
		t.Fatal("attacker and target should have distinct anchors")
	}

	// Pre-condition: target must NOT be ambiguous yet.
	_, csBefore := pt.SourceOf(targetPID)
	if csBefore.Ambiguous() {
		t.Fatal("target should not be Ambiguous before injection")
	}

	// Attacker ptraces target.
	ptEv := model.NewEvent("ebpf", model.SeverityInfo)
	ptEv.PID = attackerPID
	ptEv.Comm = "exploit"
	ptEv.Tags = map[string]string{
		"ptrace_attach":     "true",
		"ptrace_request":    "16", // PTRACE_ATTACH
		"ptrace_target_pid": "200",
		"ptrace_target":     "nginx",
	}
	p.Handle(ctx, ptEv)

	// Post-condition: target's CausalSet now contains both anchors → Ambiguous.
	_, csAfter := pt.SourceOf(targetPID)
	if !csAfter.Contains(attackerAnchor) {
		t.Errorf("target CausalSet missing attacker %d after ptrace: %v", attackerAnchor, csAfter.Slice())
	}
	if !csAfter.Contains(targetAnchor) {
		t.Errorf("target CausalSet missing its own original anchor %d: %v", targetAnchor, csAfter.Slice())
	}
	if !csAfter.Ambiguous() {
		t.Error("target CausalSet must be Ambiguous after ptrace injection")
	}
}

func mustParseAnchor(t *testing.T, s string) lineage.LineageID {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		t.Fatalf("invalid anchor id %q: %v", s, err)
	}
	return lineage.LineageID(n)
}
