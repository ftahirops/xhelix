package credbroker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SealedFile is one on-disk sealed-credential file.
//
// File layout (text, line-delimited; small footprint, diffable in
// git for ops audit visibility, ciphertext is base64):
//
//	xhelix-sealed-v1
//	{json metadata}
//	---
//	<base64-encoded ciphertext>
//
// The header line identifies the schema version. The metadata is
// human-readable JSON for `xhelixctl credbroker status <path>` to
// show class/purpose/issuer without unsealing. The `---` separator
// + base64 body keep the file ASCII-only so it survives `git diff`,
// `scp`, `rsync` without binary-mode quirks.
//
// We deliberately don't use Go's encoding/gob, protobuf, or any
// other binary format here: the file is operator-readable for the
// trust audit and operator-editable for metadata fixes (re-sealing
// doesn't require touching ciphertext if only Purpose/Issuer changed).
type SealedFile struct {
	Meta       Meta
	Ciphertext []byte
}

const sealHeader = "xhelix-sealed-v1"
const sealSeparator = "---"

// Write serialises the SealedFile to path with mode 0600.
// Atomic write via tmp+rename so a crash mid-write doesn't leave
// a corrupted credential file.
func (sf *SealedFile) Write(path string) error {
	metaJSON, err := json.MarshalIndent(sf.Meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal meta: %w", err)
	}
	var buf bytes.Buffer
	buf.WriteString(sealHeader)
	buf.WriteByte('\n')
	buf.Write(metaJSON)
	buf.WriteByte('\n')
	buf.WriteString(sealSeparator)
	buf.WriteByte('\n')
	buf.WriteString(base64.StdEncoding.EncodeToString(sf.Ciphertext))
	buf.WriteByte('\n')

	// Ensure parent dir exists with reasonable perms (0700 — sealed
	// files alongside it should be unreadable to non-owners).
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	return os.Rename(tmp, path)
}

// ReadSealed parses a sealed file at path.
func ReadSealed(path string) (*SealedFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseSealed(data)
}

// ParseSealed parses sealed-file bytes. Exposed so callers can feed
// a buffer from any source (FUSE, memory, network).
func ParseSealed(data []byte) (*SealedFile, error) {
	// Header: first line.
	lines := bytes.SplitN(data, []byte("\n"), 2)
	if len(lines) < 2 {
		return nil, errors.New("sealed file: missing header")
	}
	if !bytes.Equal(lines[0], []byte(sealHeader)) {
		return nil, fmt.Errorf("sealed file: unexpected header %q (want %q)",
			lines[0], sealHeader)
	}
	rest := lines[1]
	// Find separator "---" on its own line.
	sep := []byte("\n" + sealSeparator + "\n")
	idx := bytes.Index(rest, sep)
	if idx < 0 {
		return nil, errors.New("sealed file: missing separator")
	}
	metaJSON := rest[:idx]
	body := rest[idx+len(sep):]

	var meta Meta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, fmt.Errorf("sealed file: parse metadata: %w", err)
	}
	// Strip trailing whitespace/newline from base64.
	body = bytes.TrimSpace(body)
	ct, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return nil, fmt.Errorf("sealed file: decode ciphertext: %w", err)
	}
	return &SealedFile{Meta: meta, Ciphertext: ct}, nil
}
