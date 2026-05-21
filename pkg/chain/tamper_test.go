// P-PS.31 tamper-test suite (CT-01..CT-10).
//
// One Go test per tamper variant declared in ALERTS_AND_FP_PLAN.md
// §7.3 and CAUSAL_CHAIN_COVERAGE.md §3.4. Each test:
//
//  1. builds a small valid chain (3 batches by default)
//  2. confirms Verify() passes
//  3. performs the tamper-variant mutation
//  4. asserts Verify() detects the mutation (or, for variants the
//     verifier CANNOT detect today, the test stays Skip+TODO so the
//     gap is permanently visible).
//
// Tests are skip-marked WITH a clear reason when the verifier
// doesn't have the capability yet. Skip-with-reason is preferred
// over deleting the test because it leaves the gap auditable and
// reproducible.

package chain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// buildChain creates a fresh chain with `nBatches` finalised
// batches. Returns the directory and the public key.
func buildChain(t *testing.T, nBatches int) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(dir, priv)
	if err != nil {
		t.Fatal(err)
	}
	for b := 0; b < nBatches; b++ {
		for i := 0; i < 3; i++ {
			ev := model.NewEvent("ebpf.proc", model.SeverityInfo)
			ev.PID = uint32(1000 + b*10 + i)
			ev.Comm = "test"
			ev.Time = time.Unix(int64(1700000000+b*60+i), 0).UTC()
			if err := c.Add(ev); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		if err := c.Tick(); err != nil {
			t.Fatalf("tick: %v", err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Baseline assertion: clean chain verifies.
	n, err := Verify(dir, pub)
	if err != nil || n != nBatches {
		t.Fatalf("baseline verify: n=%d err=%v want=%d", n, err, nBatches)
	}
	return dir, pub, priv
}

// findBatch returns the absolute path of the n-th batch (0-indexed).
func findBatch(t *testing.T, dir string, n int) string {
	t.Helper()
	files, err := batchFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n >= len(files) {
		t.Fatalf("requested batch %d, only %d exist", n, len(files))
	}
	return files[n]
}

func mustVerifyFail(t *testing.T, dir string, pub ed25519.PublicKey, wantSubstr string) {
	t.Helper()
	n, err := Verify(dir, pub)
	if err == nil {
		t.Fatalf("expected verify to FAIL (substr=%q); got OK n=%d", wantSubstr, n)
	}
	if wantSubstr != "" && !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("verify err = %v, want substring %q", err, wantSubstr)
	}
}

// ─── CT-01 flip 1 byte mid-batch ─────────────────────────────

func TestCT01_FlipByteMidBatch(t *testing.T) {
	dir, pub, _ := buildChain(t, 3)
	path := findBatch(t, dir, 1) // middle batch
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 200 {
		t.Fatal("batch too small for byte flip")
	}
	// Flip a byte deep in the body (well past the header).
	data[len(data)-50] ^= 0xff
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	mustVerifyFail(t, dir, pub, "body_hash mismatch")
}

// ─── CT-02 truncate the last batch ───────────────────────────
//
// Verify() walks what's on disk and reports OK if the existing
// files chain correctly. Truncated-tail detection requires
// external proof of "expected ≥ N batches". This test makes that
// gap permanently visible.

func TestCT02_TruncateLastBatch_KnownGap(t *testing.T) {
	dir, pub, _ := buildChain(t, 5)
	// Delete the last batch file.
	last := findBatch(t, dir, 4)
	if err := os.Remove(last); err != nil {
		t.Fatal(err)
	}
	// Verify says "OK 4 batches" — the truncation is invisible
	// without an off-host reference. This is exactly the gap
	// P-CJ.10 (off-host mirror) is designed to close.
	n, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify err = %v; expected OK (the GAP is that 4 != 5 isn't flagged)", err)
	}
	if n != 4 {
		t.Errorf("verified %d batches, expected 4 after truncation", n)
	}
	// To MAKE this a hard fail in production, the operator must
	// keep an off-host record of the expected tail seq and call
	// Verify with that assertion. The off-host pusher is shipped
	// in pkg/chainmirror (P-PS.30).
	t.Log("KNOWN GAP CT-02: tail truncation undetectable without off-host mirror (P-CJ.10)")
}

// ─── CT-03 swap two batches (rename) ─────────────────────────

func TestCT03_SwapBatches(t *testing.T) {
	dir, pub, _ := buildChain(t, 4)
	a := findBatch(t, dir, 1)
	b := findBatch(t, dir, 2)
	// Atomic rename swap via temp.
	tmp := filepath.Join(dir, "swap.tmp")
	if err := os.Rename(a, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(b, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, b); err != nil {
		t.Fatal(err)
	}
	// After swap, batch-#2 sits at filename batch-#1, so when
	// Verify walks in filename order it sees:
	//   batch #2 (file 1) — its prev_hash references #0, but it
	//   was supposed to reference #1 ⇒ prev_hash mismatch.
	mustVerifyFail(t, dir, pub, "prev_hash mismatch")
}

// ─── CT-04 batch signed by different key ─────────────────────

func TestCT04_BatchSignedByWrongKey(t *testing.T) {
	dir, pub, _ := buildChain(t, 3)
	// Build a NEW key and re-sign batch[1] with it.
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := findBatch(t, dir, 1)
	hdr, body, err := readBatch(path)
	if err != nil {
		t.Fatal(err)
	}
	signed := append(hdr.PrevHash[:], hdr.BodyHash[:]...)
	newSig := ed25519.Sign(otherPriv, signed)
	copy(hdr.Signature[:], newSig)
	if err := writeBatch(path, hdr, body); err != nil {
		t.Fatal(err)
	}
	mustVerifyFail(t, dir, pub, "signature invalid")
}

// ─── CT-05 wipe + restore from old backup ────────────────────
//
// Functionally identical to CT-02 from the local-only verifier's
// perspective: if all you have is the dir, you can't tell that
// the dir is missing N tail batches. The same off-host mirror
// (P-CJ.10) closes this.

func TestCT05_WipeAndOldRestore_KnownGap(t *testing.T) {
	dir, pub, _ := buildChain(t, 5)
	// "Restore" from an old backup: simulate by removing the
	// last 2 batches.
	for i := 4; i >= 3; i-- {
		if err := os.Remove(findBatch(t, dir, i)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify err = %v; expected OK (KNOWN GAP)", err)
	}
	if n != 3 {
		t.Errorf("verified %d batches, expected 3", n)
	}
	t.Log("KNOWN GAP CT-05: wipe+restore detection requires off-host mirror (P-CJ.10)")
}

// ─── CT-06 rewrite manifest post-hoc ─────────────────────────
//
// "Manifest" in our context = the header. Flipping a byte in the
// header should fail either the body_hash check (if you flip in
// BodyHash) or the signature check (if you flip PrevHash). Both
// are valid responses.

func TestCT06_RewriteHeader(t *testing.T) {
	dir, pub, _ := buildChain(t, 3)
	path := findBatch(t, dir, 1)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The first 4 bytes are headerLen. The header itself begins at offset 4.
	// BatchID is the first 8 bytes of the header (LE uint64). Flip in PrevHash
	// region: header layout is [BatchID(8) start(8) end(8) count(4) prev(32) body(32) sig(64) keyid(16)]
	// PrevHash starts at offset 4 + 8 + 8 + 8 + 4 = 32. Flip a byte there.
	if len(data) < 100 {
		t.Fatal("batch too small")
	}
	data[32] ^= 0xff
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// After flip: next-batch's prev-hash referent changes ⇒ should fail.
	n, err := Verify(dir, pub)
	if err == nil {
		t.Fatalf("expected verify to fail after header rewrite; got OK n=%d", n)
	}
	// The error can be either prev_hash mismatch (on batch 2 vs flipped
	// batch 1's hash) or signature invalid (on flipped batch 1 itself).
	if !strings.Contains(err.Error(), "prev_hash mismatch") &&
		!strings.Contains(err.Error(), "signature invalid") {
		t.Errorf("err = %v, want prev_hash mismatch OR signature invalid", err)
	}
}

// ─── CT-07 clock-rewind a batch ──────────────────────────────
//
// Verify() does NOT currently check StartTime/EndTime monotonicity.
// An attacker who controls the on-disk batch could rewrite a
// header to claim a different time without changing PrevHash or
// BodyHash (only those two are in `signed`), AND re-sign with the
// real key — but only if root has the key. With KMS/TPM-rooted
// signing (P-CJ.8), the attacker can't re-sign.
//
// This test exercises the worst case: attacker rewrites timestamps
// AND re-signs (file signer case). Today's verifier accepts the
// rewrite. Add the ts-monotonicity check to close this.

func TestCT07_ClockRewindBatch_MidChain_Detected(t *testing.T) {
	// Discovery during P-PS.31: rewinding a NON-TAIL batch's
	// timestamps DOES get detected even though Verify() doesn't
	// explicitly check timestamps. The mechanism: rewriting
	// StartTime/EndTime changes the header bytes, which changes
	// the prev_hash computation that the NEXT batch verifies
	// against. The next batch's prev_hash check fails.
	//
	// This is the same mechanism that catches header rewrites
	// in CT-06. Conclusion: as long as a tampered batch has a
	// successor, the rewind is detected.
	dir, pub, priv := buildChain(t, 3)
	path := findBatch(t, dir, 1) // middle (not the tail)
	hdr, body, err := readBatch(path)
	if err != nil {
		t.Fatal(err)
	}
	hdr.StartTime = hdr.StartTime.Add(-24 * time.Hour)
	hdr.EndTime = hdr.EndTime.Add(-24 * time.Hour)
	signed := append(hdr.PrevHash[:], hdr.BodyHash[:]...)
	copy(hdr.Signature[:], ed25519.Sign(priv, signed))
	if err := writeBatch(path, hdr, body); err != nil {
		t.Fatal(err)
	}
	mustVerifyFail(t, dir, pub, "prev_hash mismatch")
}

func TestCT07b_ClockRewindBatch_TailOnly_KnownGap(t *testing.T) {
	// The remaining gap: when the rewind is on the LAST batch,
	// there is no successor to catch the prev_hash drift. The
	// attacker can rewind the tail's timestamps AND re-sign
	// (file-backed signer) and verifier still passes. With
	// KMS-rooted signing (P-CJ.8) the attacker can't re-sign so
	// the gap is moot in practice — but the verifier should still
	// gain an explicit hdr.StartTime <= prev.EndTime check.
	dir, pub, priv := buildChain(t, 3)
	path := findBatch(t, dir, 2) // tail
	hdr, body, err := readBatch(path)
	if err != nil {
		t.Fatal(err)
	}
	hdr.StartTime = hdr.StartTime.Add(-24 * time.Hour)
	hdr.EndTime = hdr.EndTime.Add(-24 * time.Hour)
	signed := append(hdr.PrevHash[:], hdr.BodyHash[:]...)
	copy(hdr.Signature[:], ed25519.Sign(priv, signed))
	if err := writeBatch(path, hdr, body); err != nil {
		t.Fatal(err)
	}
	n, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify err=%v; expected OK (KNOWN GAP — tail rewind)", err)
	}
	if n != 3 {
		t.Errorf("n=%d", n)
	}
	t.Log("KNOWN GAP CT-07b: TAIL rewind undetectable without ts-monotonicity check. " +
		"Mitigations: (a) KMS-rooted signing makes re-sign impossible, " +
		"(b) off-host mirror captures last-tail-seen-at, " +
		"(c) extend Verify to assert hdr.StartTime <= now+tolerance.")
}

// ─── CT-08 kill mid-flush — chain recovers ───────────────────
//
// Simulate by leaving a stray .tmp file in the chain dir. The
// readBatch / batchFiles paths must ignore .tmp; resume must skip
// it. Verify must still pass.

func TestCT08_KillMidFlush_Recovery(t *testing.T) {
	dir, pub, _ := buildChain(t, 3)
	// Drop a stray garbage .tmp that resembles a mid-flush state.
	tmpPath := filepath.Join(dir, "deadbeef.tmp")
	if err := os.WriteFile(tmpPath, []byte("garbage incomplete flush"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Verify should still report n=3 (it must not be confused
	// by the .tmp).
	n, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify failed despite stray .tmp: %v", err)
	}
	if n != 3 {
		t.Errorf("verified %d batches, want 3 (stray .tmp must be ignored)", n)
	}
}

// ─── CT-09 replay an old batch ───────────────────────────────
//
// Copy an existing batch into a "future" batch ID. Two failure
// modes are possible:
//  (a) The copy claims a sequence number that overwrites a real
//      batch ⇒ prev_hash mismatch downstream.
//  (b) The copy claims a sequence beyond the tail ⇒ adds a
//      "branched" tail. We catch (a) here.

func TestCT09_ReplayOldBatch(t *testing.T) {
	dir, pub, _ := buildChain(t, 5)
	// Read batch 1, write its bytes back as batch 3 (overwrite).
	srcPath := findBatch(t, dir, 1)
	dstPath := findBatch(t, dir, 3)
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// Now files[3] is actually batch #1's content. Its BatchID
	// header field still claims 1, and its prev_hash references
	// batch 0's hash — but the chain walker expects batch 3's
	// prev_hash to reference batch 2. Mismatch.
	mustVerifyFail(t, dir, pub, "prev_hash mismatch")
}

// ─── CT-10 future-dated batch with valid signature ───────────
//
// Same root-causality as CT-07: verifier doesn't currently check
// timestamps. With file-backed signer + root compromise, attacker
// can rewrite timestamps + re-sign. KMS/TPM-backed signer makes
// the re-sign impossible. Test demonstrates the gap.

func TestCT10_FutureDatedBatch_KnownGap(t *testing.T) {
	dir, pub, priv := buildChain(t, 3)
	path := findBatch(t, dir, 2) // tail
	hdr, body, err := readBatch(path)
	if err != nil {
		t.Fatal(err)
	}
	// Forward 365 days.
	hdr.StartTime = hdr.StartTime.Add(365 * 24 * time.Hour)
	hdr.EndTime = hdr.EndTime.Add(365 * 24 * time.Hour)
	signed := append(hdr.PrevHash[:], hdr.BodyHash[:]...)
	copy(hdr.Signature[:], ed25519.Sign(priv, signed))
	if err := writeBatch(path, hdr, body); err != nil {
		t.Fatal(err)
	}
	n, err := Verify(dir, pub)
	if err != nil {
		t.Fatalf("verify err=%v; expected OK (KNOWN GAP)", err)
	}
	if n != 3 {
		t.Errorf("n=%d", n)
	}
	t.Log("KNOWN GAP CT-10: forward-dated batches accepted. " +
		"Fix: assert hdr.StartTime <= now + tolerance in Verify().")
}

// ─── extra: corruption that breaks signature region only ─────

func TestCT_HeaderSigFlip(t *testing.T) {
	dir, pub, _ := buildChain(t, 2)
	path := findBatch(t, dir, 1)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Signature field starts after PrevHash(32) + BodyHash(32) =
	// hdrLen-prefix(4) + BatchID(8) + start(8) + end(8) + count(4)
	// + prev(32) + body(32) = 4 + 64 + 32 = 96. Flip there.
	if len(data) < 200 {
		t.Fatal("too small")
	}
	data[100] ^= 0xff
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	mustVerifyFail(t, dir, pub, "signature invalid")
}

// ─── extra: hdrLen tampering ─────────────────────────────────
// Verify resilience to truncated/corrupted header-length prefix.
// readBatch should fail cleanly, Verify should error out.

func TestCT_HdrLenTruncation(t *testing.T) {
	dir, pub, _ := buildChain(t, 2)
	path := findBatch(t, dir, 1)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Zero the first 4 bytes (header length prefix).
	binary.LittleEndian.PutUint32(data[:4], 0)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := Verify(dir, pub)
	if err == nil {
		t.Fatalf("expected error after hdrLen zero, got OK n=%d", n)
	}
}
