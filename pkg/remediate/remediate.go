// Package remediate restores tampered files from xhelix's backup
// store and reverts common persistence techniques.
//
// Conservative by design: every remediate moves the offending file
// into a quarantine dir before restoring, so operators have full
// rollback. Never delete; always quarantine.
package remediate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Remediator is the public API.
type Remediator struct {
	BackupDir    string // golden copies of monitored files
	QuarantineDir string // where bad files go before restore

	mu       sync.Mutex
	hashes   map[string]string // path → known-good sha256 (populated from backups)
}

// New constructs a Remediator. Callers populate Backup() before any
// Restore can succeed.
func New(backupDir, quarantineDir string) (*Remediator, error) {
	if backupDir == "" {
		return nil, errors.New("remediate: backup dir required")
	}
	if quarantineDir == "" {
		quarantineDir = filepath.Join(backupDir, "quarantine")
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return nil, err
	}
	r := &Remediator{
		BackupDir:    backupDir,
		QuarantineDir: quarantineDir,
		hashes:       map[string]string{},
	}
	return r, nil
}

// Backup creates / refreshes the known-good copy of path.
//
// Operators run Backup at install time on every file they want to
// be able to auto-restore: /etc/passwd, /etc/shadow, /etc/sudoers,
// /etc/ld.so.preload (empty/missing), ssh authorized_keys baselines.
func (r *Remediator) Backup(path string) error {
	src, err := os.Open(path)
	if err != nil {
		// /etc/ld.so.preload typically doesn't exist; we model that
		// by creating an empty backup so Restore wipes the malicious
		// file.
		if os.IsNotExist(err) {
			return r.backupEmpty(path)
		}
		return err
	}
	defer src.Close()

	dst, err := os.Create(r.backupPath(path))
	if err != nil {
		return err
	}
	defer dst.Close()

	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		return err
	}
	r.mu.Lock()
	r.hashes[path] = hex.EncodeToString(h.Sum(nil))
	r.mu.Unlock()
	return nil
}

func (r *Remediator) backupEmpty(path string) error {
	bp := r.backupPath(path)
	if err := os.WriteFile(bp, nil, 0o600); err != nil {
		return err
	}
	r.mu.Lock()
	r.hashes[path] = sha256Empty()
	r.mu.Unlock()
	return nil
}

// Restore copies the known-good version of path back into place,
// quarantining the current (presumably malicious) version first.
//
// Returns an error if no backup exists. Reason is recorded in the
// quarantine filename.
func (r *Remediator) Restore(path, reason string) error {
	bp := r.backupPath(path)
	if _, err := os.Stat(bp); err != nil {
		return fmt.Errorf("remediate: no backup for %s", path)
	}

	// 1. Quarantine the current file
	if _, err := os.Stat(path); err == nil {
		if err := r.quarantine(path, reason); err != nil {
			return fmt.Errorf("quarantine: %w", err)
		}
	}

	// 2. Verify the backup hasn't been tampered with since Backup()
	// recorded it. An attacker who can write to BackupDir could
	// otherwise corrupt the "restore" into installing their own
	// content. r.hashes was populated at Backup() time.
	if want, ok := r.hashes[path]; ok && want != "" {
		got, hashErr := sha256File(bp)
		if hashErr != nil {
			return fmt.Errorf("remediate: hash backup: %w", hashErr)
		}
		if got != want {
			return fmt.Errorf("remediate: backup integrity check failed for %s "+
				"(have %s, expected %s) — refusing to restore tampered content",
				bp, got, want)
		}
	}

	// 3. Copy backup into place atomically
	tmp := path + ".xh-tmp"
	src, err := os.Open(bp)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		_ = os.Remove(tmp)
		return err
	}
	dst.Close()
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	// 3. Restore mode bits to a sane default for the path
	r.fixMode(path)
	return nil
}

func (r *Remediator) quarantine(path, reason string) error {
	stamp := time.Now().UTC().Format("20060102T150405")
	name := stamp + "_" + reason + "_" + filepath.Base(path)
	dst := filepath.Join(r.QuarantineDir, name)

	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o400)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func (r *Remediator) backupPath(orig string) string {
	// Map "/etc/passwd" → "<backupDir>/etc_passwd.bak" (sanitised)
	clean := filepath.Clean(orig)
	safe := ""
	for _, c := range clean {
		switch c {
		case '/':
			safe += "_"
		default:
			safe += string(c)
		}
	}
	return filepath.Join(r.BackupDir, safe+".bak")
}

// fixMode applies a sane permissions baseline for known sensitive
// paths. Avoid clobbering anything we don't recognise.
func (r *Remediator) fixMode(path string) {
	switch path {
	case "/etc/passwd":
		_ = os.Chmod(path, 0o644)
	case "/etc/shadow":
		_ = os.Chmod(path, 0o640)
	case "/etc/sudoers":
		_ = os.Chmod(path, 0o440)
	case "/etc/ld.so.preload":
		_ = os.Chmod(path, 0o644)
	}
}

// sha256File hashes the contents of a file. Returns hex string.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sha256Empty() string {
	h := sha256.New()
	return hex.EncodeToString(h.Sum(nil))
}

// Stats reports how many restores have been performed.
type Stats struct {
	Restores uint64
}
