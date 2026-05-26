package brp

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Edge declares an allowed inter-app interaction at runtime. A signed
// EdgeProfile carries one or more Edges and is loaded alongside per-app
// BRP profiles. The verifier's CrossApp domain consults the matched
// EdgeSet to attenuate (or compound) score for the observed
// (actor_app → target_app) edge.
//
// Wire format (JSON, signed envelope mirrors SignedProfile):
//
//	{
//	  "schema_version": 1,
//	  "from_app":   "nginx",
//	  "to_app":     "php-fpm",
//	  "allowed_actions": ["net_connect"],
//	  "destinations": ["unix:/run/php/php-fpm.sock", "127.0.0.1:9000"],
//	  "note":       "nginx → php-fpm via FastCGI"
//	}
//
// EdgeSet is the loaded, indexed collection.
type Edge struct {
	SchemaVersion  int      `json:"schema_version"`
	FromApp        string   `json:"from_app"`
	ToApp          string   `json:"to_app"`
	AllowedActions []string `json:"allowed_actions,omitempty"`
	Destinations   []string `json:"destinations,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// SignedEdge wraps an Edge with an Ed25519 signature in the same shape
// as SignedProfile. Loaded by EdgeSet.LoadDir which honors the same
// trust root as the profile matcher.
type SignedEdge struct {
	Edge      Edge   `json:"edge"`
	Signer    string `json:"signer"`
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

// EdgeSet holds the daemon's loaded inter-app edges, keyed for fast
// (from_app, to_app, action) lookup.
//
// Thread-safe; LoadDir replaces the index atomically.
type EdgeSet struct {
	mu             sync.RWMutex
	byPair         map[string][]Edge // "from→to" → matching edges
	trustedPubKeys map[string]ed25519.PublicKey
}

// NewEdgeSet returns an empty set with the given trust root. Pass nil
// to disable signature verification (test/dev only — production
// configurations MUST pass a trust root).
func NewEdgeSet(trustedKeys map[string]ed25519.PublicKey) *EdgeSet {
	if trustedKeys == nil {
		trustedKeys = map[string]ed25519.PublicKey{}
	}
	return &EdgeSet{
		byPair:         map[string][]Edge{},
		trustedPubKeys: trustedKeys,
	}
}

// edgeCanonicalBytes returns the canonical JSON bytes of an Edge for
// signing/verification. Field order is fixed by struct order (Go spec
// guarantees source-order for encoding/json).
func edgeCanonicalBytes(e Edge) ([]byte, error) {
	return json.Marshal(e)
}

// SignEdge produces a SignedEdge with the given signer name + Ed25519
// private key. Caller responsibility: store the signer's PUBLIC key
// in the daemon's trust root for verification at load time.
func SignEdge(e Edge, signer string, priv ed25519.PrivateKey) (SignedEdge, error) {
	if e.SchemaVersion == 0 {
		e.SchemaVersion = 1
	}
	buf, err := edgeCanonicalBytes(e)
	if err != nil {
		return SignedEdge{}, fmt.Errorf("canonicalize: %w", err)
	}
	sig := ed25519.Sign(priv, buf)
	return SignedEdge{
		Edge:      e,
		Signer:    signer,
		Algorithm: "ed25519",
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyEdge re-derives the canonical bytes of se.Edge and verifies the
// signature against pub. Returns nil if valid.
func VerifyEdge(se SignedEdge, pub ed25519.PublicKey) error {
	if se.Algorithm != "ed25519" {
		return fmt.Errorf("unsupported algorithm %q", se.Algorithm)
	}
	sig, err := base64.StdEncoding.DecodeString(se.Signature)
	if err != nil {
		return fmt.Errorf("base64: %w", err)
	}
	buf, err := edgeCanonicalBytes(se.Edge)
	if err != nil {
		return fmt.Errorf("canonicalize: %w", err)
	}
	if !ed25519.Verify(pub, buf, sig) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

// AddEdge inserts an Edge into the index. Validates basic shape.
func (s *EdgeSet) AddEdge(e Edge) error {
	if e.SchemaVersion == 0 {
		return fmt.Errorf("schema_version required")
	}
	if e.FromApp == "" || e.ToApp == "" {
		return fmt.Errorf("from_app and to_app are required")
	}
	key := e.FromApp + "→" + e.ToApp
	s.mu.Lock()
	s.byPair[key] = append(s.byPair[key], e)
	s.mu.Unlock()
	return nil
}

// LoadDir loads every *.edge.json file under dir into the set. Each
// file is signature-verified against the EdgeSet's trust root before
// joining the index — files signed by an untrusted signer or with an
// invalid signature are REJECTED. This matches the profile load path's
// security posture: no "load anyway and warn" mode.
//
// Missing dir is not an error — returns (0, nil).
func (s *EdgeSet) LoadDir(dir string) (loaded, rejected int, err error) {
	if _, statErr := os.Stat(dir); statErr != nil {
		if os.IsNotExist(statErr) {
			return 0, 0, nil
		}
		return 0, 0, statErr
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".edge.json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			rejected++
			continue
		}
		var se SignedEdge
		if err := json.Unmarshal(data, &se); err != nil {
			rejected++
			continue
		}
		if se.Signer == "" || se.Signature == "" {
			rejected++
			continue
		}
		pub, ok := s.trustedPubKeys[se.Signer]
		if !ok {
			rejected++
			continue
		}
		if err := VerifyEdge(se, pub); err != nil {
			rejected++
			continue
		}
		if err := s.AddEdge(se.Edge); err != nil {
			rejected++
			continue
		}
		loaded++
	}
	return loaded, rejected, nil
}

// Allows reports whether the given actor→target pair is explicitly
// allowed for the given action and destination. dest may be "" — when
// edge declares destinations and dest is empty, the lookup returns
// false (the edge wants a specific destination match).
//
// Returns (allowed, edge) — the matched Edge is returned for audit.
func (s *EdgeSet) Allows(fromApp, toApp, action, dest string) (bool, Edge) {
	if fromApp == "" || toApp == "" {
		return false, Edge{}
	}
	s.mu.RLock()
	edges := s.byPair[fromApp+"→"+toApp]
	s.mu.RUnlock()
	for _, e := range edges {
		if !actionAllowed(e, action) {
			continue
		}
		if len(e.Destinations) == 0 {
			return true, e
		}
		if dest == "" {
			continue
		}
		for _, d := range e.Destinations {
			if d == dest || strings.HasPrefix(dest, d) {
				return true, e
			}
		}
	}
	return false, Edge{}
}

func actionAllowed(e Edge, action string) bool {
	if len(e.AllowedActions) == 0 {
		return true // no restriction = any action
	}
	for _, a := range e.AllowedActions {
		if a == action {
			return true
		}
	}
	return false
}

// Size returns the count of edges in the set (test helper).
func (s *EdgeSet) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, v := range s.byPair {
		n += len(v)
	}
	return n
}
