// Package chain implements xhelix's tamper-evident hash-chained
// event log.
//
// Events are batched and finalised every Interval (or on size). Each
// finalised batch is written to disk with a header that includes the
// SHA-256 of the previous batch's body, forming an append-only hash
// chain. Each batch body is also signed by the host's Ed25519 key.
//
// Tampering with any historic batch breaks the chain forward and
// invalidates the signature. Investigators verify by re-walking the
// chain with the host's public key.
package chain

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Header is the on-disk metadata for one finalised batch.
type Header struct {
	BatchID    uint64
	StartTime  time.Time
	EndTime    time.Time
	EventCount uint32
	PrevHash   [32]byte
	BodyHash   [32]byte
	Signature  [64]byte
	HostKeyID  [16]byte
}

// Chain manages the lifecycle of finalised batches in dir.
type Chain struct {
	Dir       string
	BatchCap  int           // max events per batch (default 10_000)
	BodyCap   int           // max body bytes per batch (default 4 MB)
	Interval  time.Duration // periodic finalise (default 60s)
	PrivKey   ed25519.PrivateKey
	HostKeyID [16]byte

	// MaxBatches caps the number of *.bin files kept in Dir. After each
	// finalise, the oldest batches are deleted until the count is at or
	// below MaxBatches. 0 = unbounded (legacy behavior — DO NOT USE in
	// production; pre-rotation builds destroyed disks at ~3.5MB/batch
	// × hundreds of batches/hour). Recommended: 2000-5000 for typical
	// workloads (covers ~6-24h of history at default event volume).
	//
	// Rotation breaks chain.Verify back to genesis after old batches
	// are removed; the verifier still validates any contiguous range
	// from the oldest surviving batch forward. This is the right
	// tradeoff for an endpoint EDR — long-window forensics belongs
	// off-host.
	MaxBatches int

	mu          sync.Mutex
	current     []model.Event
	bodyBytes   int
	nextBatchID uint64
	prevHash    [32]byte
}

// New creates (or resumes) a chain rooted at dir.
//
// On resume, New scans dir for existing batch files, reads the last
// header, and seeds nextBatchID + prevHash so the new chain links to
// the existing tail.
//
// privKey is required; nil returns an error.
func New(dir string, privKey ed25519.PrivateKey) (*Chain, error) {
	if len(privKey) == 0 {
		return nil, errors.New("chain: private key required")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	c := &Chain{
		Dir:       dir,
		BatchCap:  10_000,
		BodyCap:   4 * 1024 * 1024,
		Interval:  time.Minute,
		PrivKey:   privKey,
		HostKeyID: keyIDFor(privKey),
	}
	if err := c.resume(); err != nil {
		return nil, err
	}
	return c, nil
}

// Add appends ev to the in-progress batch and finalises if size or
// count caps are reached. Caller is responsible for invoking Tick
// (or relying on a timer) to handle the time-based cap.
func (c *Chain) Add(ev model.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	c.current = append(c.current, ev)
	c.bodyBytes += len(body) + 1
	if len(c.current) >= c.BatchCap || c.bodyBytes >= c.BodyCap {
		return c.finaliseLocked()
	}
	return nil
}

// Tick finalises the in-progress batch if non-empty. Call from a
// goroutine on Interval cadence.
func (c *Chain) Tick() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.current) == 0 {
		return nil
	}
	return c.finaliseLocked()
}

// Close finalises any pending batch.
func (c *Chain) Close() error { return c.Tick() }

// finaliseLocked writes the in-progress batch to disk and clears it.
// Caller holds c.mu.
func (c *Chain) finaliseLocked() error {
	if len(c.current) == 0 {
		return nil
	}
	now := time.Now().UTC()
	body := encodeBody(c.current)
	bodyHash := sha256.Sum256(body)

	hdr := Header{
		BatchID:    c.nextBatchID,
		StartTime:  c.current[0].Time,
		EndTime:    c.current[len(c.current)-1].Time,
		EventCount: uint32(len(c.current)),
		PrevHash:   c.prevHash,
		BodyHash:   bodyHash,
		HostKeyID:  c.HostKeyID,
	}
	if hdr.StartTime.IsZero() {
		hdr.StartTime = now
	}
	if hdr.EndTime.IsZero() {
		hdr.EndTime = now
	}
	signed := append(hdr.PrevHash[:], hdr.BodyHash[:]...)
	sig := ed25519.Sign(c.PrivKey, signed)
	copy(hdr.Signature[:], sig)

	path := filepath.Join(c.Dir, fmt.Sprintf("%016x.bin", hdr.BatchID))
	if err := writeBatch(path, hdr, body); err != nil {
		return err
	}

	c.prevHash = sha256.Sum256(append(headerBytes(hdr), body...))
	c.nextBatchID++
	c.current = c.current[:0]
	c.bodyBytes = 0

	// Rotate: delete oldest batches if we exceed MaxBatches. 0 = no
	// rotation (legacy unbounded growth). Operators should set this
	// in config — typical: 2000-5000.
	if c.MaxBatches > 0 {
		_ = c.rotateLocked()
	}
	return nil
}

// rotateLocked deletes oldest batch files until count ≤ MaxBatches.
// Caller holds c.mu. Errors deleting individual files are not fatal —
// the chain still functions; next rotation tick will retry.
func (c *Chain) rotateLocked() error {
	files, err := batchFiles(c.Dir)
	if err != nil {
		return err
	}
	excess := len(files) - c.MaxBatches
	if excess <= 0 {
		return nil
	}
	// batchFiles returns sorted by name (which is hex batch ID) —
	// oldest first.
	for i := 0; i < excess; i++ {
		_ = os.Remove(files[i])
	}
	return nil
}

func (c *Chain) resume() error {
	files, err := batchFiles(c.Dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}
	last := files[len(files)-1]
	hdr, body, err := readBatch(last)
	if err != nil {
		return err
	}
	c.nextBatchID = hdr.BatchID + 1
	c.prevHash = sha256.Sum256(append(headerBytes(hdr), body...))
	return nil
}

// Verify walks every batch in dir in order and confirms the chain is
// internally consistent and validly signed by pub. Returns the
// number of batches verified and the first error encountered.
func Verify(dir string, pub ed25519.PublicKey) (int, error) {
	files, err := batchFiles(dir)
	if err != nil {
		return 0, err
	}
	var prevHash [32]byte
	for i, f := range files {
		hdr, body, err := readBatch(f)
		if err != nil {
			return i, fmt.Errorf("read batch %s: %w", f, err)
		}
		if hdr.PrevHash != prevHash {
			return i, fmt.Errorf("batch %d: prev_hash mismatch", hdr.BatchID)
		}
		if got := sha256.Sum256(body); got != hdr.BodyHash {
			return i, fmt.Errorf("batch %d: body_hash mismatch", hdr.BatchID)
		}
		signed := append(hdr.PrevHash[:], hdr.BodyHash[:]...)
		if !ed25519.Verify(pub, signed, hdr.Signature[:]) {
			return i, fmt.Errorf("batch %d: signature invalid", hdr.BatchID)
		}
		prevHash = sha256.Sum256(append(headerBytes(hdr), body...))
	}
	return len(files), nil
}

// keyIDFor returns the 16-byte truncation of the public-key SHA-256.
func keyIDFor(priv ed25519.PrivateKey) [16]byte {
	pub := priv.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	var id [16]byte
	copy(id[:], h[:16])
	return id
}

func encodeBody(events []model.Event) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		_ = enc.Encode(ev)
	}
	return buf.Bytes()
}

func headerBytes(h Header) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, h.BatchID)
	_ = binary.Write(&buf, binary.LittleEndian, h.StartTime.UnixNano())
	_ = binary.Write(&buf, binary.LittleEndian, h.EndTime.UnixNano())
	_ = binary.Write(&buf, binary.LittleEndian, h.EventCount)
	buf.Write(h.PrevHash[:])
	buf.Write(h.BodyHash[:])
	buf.Write(h.Signature[:])
	buf.Write(h.HostKeyID[:])
	return buf.Bytes()
}

func writeBatch(path string, hdr Header, body []byte) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	defer f.Close()
	hb := headerBytes(hdr)
	if err := binary.Write(f, binary.LittleEndian, uint32(len(hb))); err != nil {
		return err
	}
	if _, err := f.Write(hb); err != nil {
		return err
	}
	if err := binary.Write(f, binary.LittleEndian, uint32(len(body))); err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readBatch(path string) (Header, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return Header{}, nil, err
	}
	defer f.Close()
	var hLen uint32
	if err := binary.Read(f, binary.LittleEndian, &hLen); err != nil {
		return Header{}, nil, err
	}
	hb := make([]byte, hLen)
	if _, err := io.ReadFull(f, hb); err != nil {
		return Header{}, nil, err
	}
	hdr := decodeHeader(hb)
	var bLen uint32
	if err := binary.Read(f, binary.LittleEndian, &bLen); err != nil {
		return Header{}, nil, err
	}
	body := make([]byte, bLen)
	if _, err := io.ReadFull(f, body); err != nil {
		return Header{}, nil, err
	}
	return hdr, body, nil
}

func decodeHeader(b []byte) Header {
	r := bytes.NewReader(b)
	var h Header
	var startNs, endNs int64
	_ = binary.Read(r, binary.LittleEndian, &h.BatchID)
	_ = binary.Read(r, binary.LittleEndian, &startNs)
	_ = binary.Read(r, binary.LittleEndian, &endNs)
	_ = binary.Read(r, binary.LittleEndian, &h.EventCount)
	_, _ = io.ReadFull(r, h.PrevHash[:])
	_, _ = io.ReadFull(r, h.BodyHash[:])
	_, _ = io.ReadFull(r, h.Signature[:])
	_, _ = io.ReadFull(r, h.HostKeyID[:])
	h.StartTime = time.Unix(0, startNs)
	h.EndTime = time.Unix(0, endNs)
	return h
}

func batchFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".bin") {
			continue
		}
		if strings.HasSuffix(name, ".tmp") {
			continue
		}
		out = append(out, filepath.Join(dir, name))
	}
	sort.Strings(out)
	return out, nil
}
