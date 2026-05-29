package egresspolicy

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Store loads + caches SignedPolicy files from a directory. Files are
// <sanitized-binary>.yaml. A periodic re-scan (StartWatcher) keeps the
// in-memory map fresh; we deliberately avoid fsnotify to stay
// dependency-free.
type Store struct {
	dir       string
	publicKey ed25519.PublicKey
	mu        sync.RWMutex
	policies  map[string]SignedPolicy // key = Policy.Binary
}

// NewStore creates a Store rooted at dir. The directory does not need
// to exist; an absent directory is treated as "no policies loaded yet".
// pub must be a valid ed25519 public key — without one we cannot verify
// any policy on disk and the constructor errors.
func NewStore(dir string, pub ed25519.PublicKey) (*Store, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	if dir == "" {
		return nil, errors.New("dir is required")
	}
	return &Store{
		dir:       dir,
		publicKey: pub,
		policies:  map[string]SignedPolicy{},
	}, nil
}

// Reload re-scans dir. Returns count loaded + first parse / verify
// error encountered (later policies are still loaded). A missing dir
// is not an error — it just means no policies.
func (s *Store) Reload() (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			s.mu.Lock()
			s.policies = map[string]SignedPolicy{}
			s.mu.Unlock()
			return 0, nil
		}
		return 0, fmt.Errorf("read dir: %w", err)
	}
	loaded := map[string]SignedPolicy{}
	var firstErr error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		// Skip the operator public key file (well-known name).
		if name == "operator.pub" || name == "operator.pub.yaml" {
			continue
		}
		path := filepath.Join(s.dir, name)
		sp, err := loadSignedFile(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", name, err)
			}
			continue
		}
		if err := Verify(sp, s.publicKey); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: verify: %w", name, err)
			}
			continue
		}
		loaded[sp.Policy.Binary] = sp
	}
	s.mu.Lock()
	s.policies = loaded
	s.mu.Unlock()
	return len(loaded), firstErr
}

// Get returns the policy for a binary, or nil if absent. Nil means
// "no policy — use default observe mode". Both full path and basename
// are checked (in that order).
func (s *Store) Get(binary string) *SignedPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sp, ok := s.policies[binary]; ok {
		return &sp
	}
	base := filepath.Base(binary)
	if base != binary {
		if sp, ok := s.policies[base]; ok {
			return &sp
		}
	}
	return nil
}

// All returns a snapshot of all loaded policies (for review CLI).
// Returned slice is owned by caller; safe to sort/modify.
func (s *Store) All() []SignedPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SignedPolicy, 0, len(s.policies))
	for _, sp := range s.policies {
		out = append(out, sp)
	}
	return out
}

// Save writes a SignedPolicy back to disk as <sanitized-binary>.yaml.
// The caller is expected to have signed sp; Save does NOT re-verify
// (use VerifyAndSave for that).
func (s *Store) Save(sp SignedPolicy) error {
	if sp.Policy.Binary == "" {
		return errors.New("policy.binary is required")
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", s.dir, err)
	}
	data, err := yaml.Marshal(sp)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	path := filepath.Join(s.dir, sanitizeBinary(sp.Policy.Binary)+".yaml")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	s.mu.Lock()
	s.policies[sp.Policy.Binary] = sp
	s.mu.Unlock()
	return nil
}

// VerifyAndSave verifies sp against the store's public key before
// writing. Use this when accepting a policy from an external source.
func (s *Store) VerifyAndSave(sp SignedPolicy) error {
	if err := Verify(sp, s.publicKey); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return s.Save(sp)
}

// Delete removes a policy file and drops it from the in-memory cache.
// Not-found is not an error (idempotent).
func (s *Store) Delete(binary string) error {
	path := filepath.Join(s.dir, sanitizeBinary(binary)+".yaml")
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", path, err)
	}
	s.mu.Lock()
	delete(s.policies, binary)
	s.mu.Unlock()
	return nil
}

// StartWatcher begins a periodic re-scan (every 30s). It returns a
// stop function that the caller can invoke to halt the watcher; the
// watcher also exits when ctx is cancelled. The first reload runs
// inline so the cache is warm before this returns.
func (s *Store) StartWatcher(ctx context.Context) func() {
	_, _ = s.Reload()
	done := make(chan struct{})
	stop := func() {
		select {
		case <-done:
			// already closed
		default:
			close(done)
		}
	}
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-t.C:
				_, _ = s.Reload()
			}
		}
	}()
	return stop
}

// PublicKey returns the public key used to verify policies. Exposed so
// the CLI can show it during keygen / inspect commands.
func (s *Store) PublicKey() ed25519.PublicKey { return s.publicKey }

// Dir returns the on-disk directory the store was initialised with.
func (s *Store) Dir() string { return s.dir }

func loadSignedFile(path string) (SignedPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SignedPolicy{}, err
	}
	var sp SignedPolicy
	if err := yaml.Unmarshal(data, &sp); err != nil {
		return SignedPolicy{}, fmt.Errorf("unmarshal: %w", err)
	}
	return sp, nil
}

// sanitizeBinary turns a binary path/name into a safe filename
// component. Strips leading slash, replaces path separators and
// other unsafe characters with "_".
func sanitizeBinary(binary string) string {
	b := strings.TrimPrefix(binary, "/")
	b = strings.ReplaceAll(b, "/", "_")
	b = strings.ReplaceAll(b, "\\", "_")
	b = strings.ReplaceAll(b, "..", "_")
	b = strings.ReplaceAll(b, " ", "_")
	if b == "" {
		b = "unnamed"
	}
	return b
}
