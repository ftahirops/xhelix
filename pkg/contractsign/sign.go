// Package contractsign signs and verifies compiled behavioral contracts
// (P7). A signature attests that a specific contract VERSION (its
// content-addressed ArtifactSHA) was reviewed/approved by a trusted
// signer — typically CI holding a private key whose public half is in the
// daemon's trust root. Sealed-mode arming requires a valid signature for
// the current ArtifactSHA, so any unsigned drift (a changed declaration →
// changed hash) is blocked until re-signed.
//
// The signature covers a domain-separated message, NOT the raw hash, so a
// signature can never be replayed across a different app or scheme version.
package contractsign

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// domain namespaces the signed message; bump the version suffix only on a
// breaking change to the signing scheme.
const domain = "xhelix-contract-sig-v1"

// Message returns the canonical bytes signed for (app, artifactSHA).
func Message(app, artifactSHA string) []byte {
	return []byte(domain + "|" + app + "|" + artifactSHA)
}

// Sign produces a detached Ed25519 signature over Message(app, artifactSHA).
// Used by CI / xhelixctl; the daemon only ever verifies.
func Sign(app, artifactSHA string, priv ed25519.PrivateKey) []byte {
	return ed25519.Sign(priv, Message(app, artifactSHA))
}

// Verify checks sig against the named signer's trusted public key.
func Verify(app, artifactSHA, signer string, sig []byte, trust map[string]ed25519.PublicKey) error {
	pub, ok := trust[signer]
	if !ok {
		return fmt.Errorf("contractsign: signer %q not in trust root", signer)
	}
	if !ed25519.Verify(pub, Message(app, artifactSHA), sig) {
		return errors.New("contractsign: signature does not verify")
	}
	return nil
}

// Signature is a stored attestation.
type Signature struct {
	App         string    `json:"app"`
	ArtifactSHA string    `json:"artifact_sha"`
	Signer      string    `json:"signer"`
	Sig         []byte    `json:"-"`
	SigB64      string    `json:"signature_b64"`
	AddedAt     time.Time `json:"added_at"`
}

// Store persists trusted signatures and answers "is this contract version
// signed?" for the sealed-mode arm gate.
type Store struct {
	db    *sql.DB
	trust map[string]ed25519.PublicKey
}

// Open opens the signature store. trust is the same Ed25519 public-key set
// used elsewhere (BRP trusted-keys.d). An empty trust map means nothing
// will ever verify — sealed arming stays blocked, which is the safe default.
func Open(path string, trust map[string]ed25519.PublicKey) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_journal=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("contractsign: open: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("contractsign: schema: %w", err)
	}
	if trust == nil {
		trust = map[string]ed25519.PublicKey{}
	}
	return &Store{db: db, trust: trust}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

// Add verifies a signature against the trust root and, if valid, stores it.
// Rejects untrusted or malformed signatures — only verifiable attestations
// are ever persisted.
func (s *Store) Add(app, artifactSHA, signer, sigB64 string) (Signature, error) {
	if app == "" || artifactSHA == "" || signer == "" {
		return Signature{}, errors.New("contractsign: app, artifact_sha, signer required")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return Signature{}, fmt.Errorf("contractsign: bad base64 signature: %w", err)
	}
	if err := Verify(app, artifactSHA, signer, sig, s.trust); err != nil {
		return Signature{}, err
	}
	now := time.Now()
	_, err = s.db.ExecContext(context.Background(),
		`INSERT OR REPLACE INTO signatures (app, artifact_sha, signer, sig_b64, added_at)
		 VALUES (?,?,?,?,?)`,
		app, artifactSHA, signer, sigB64, now.Unix(),
	)
	if err != nil {
		return Signature{}, fmt.Errorf("contractsign: insert: %w", err)
	}
	return Signature{App: app, ArtifactSHA: artifactSHA, Signer: signer,
		Sig: sig, SigB64: sigB64, AddedAt: now}, nil
}

// HasValid reports whether a TRUSTED signature exists for (app, artifactSHA),
// RE-VERIFYING against the current trust root so a revoked signer's old
// signature no longer counts. Returns the signer name on success.
func (s *Store) HasValid(app, artifactSHA string) (bool, string) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT signer, sig_b64 FROM signatures WHERE app=? AND artifact_sha=?`,
		app, artifactSHA)
	if err != nil {
		return false, ""
	}
	defer rows.Close()
	for rows.Next() {
		var signer, sigB64 string
		if err := rows.Scan(&signer, &sigB64); err != nil {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			continue
		}
		if Verify(app, artifactSHA, signer, sig, s.trust) == nil {
			return true, signer
		}
	}
	return false, ""
}

// ListForApp returns stored signatures for an app (any version).
func (s *Store) ListForApp(app string) ([]Signature, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT app, artifact_sha, signer, sig_b64, added_at FROM signatures
		 WHERE app=? ORDER BY added_at DESC`, app)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Signature
	for rows.Next() {
		var sg Signature
		var added int64
		if err := rows.Scan(&sg.App, &sg.ArtifactSHA, &sg.Signer, &sg.SigB64, &added); err != nil {
			return nil, err
		}
		sg.AddedAt = time.Unix(added, 0)
		out = append(out, sg)
	}
	return out, rows.Err()
}

// RegisterTrustKey adds a trusted signer at runtime (mirrors the pattern in
// pkg/maintenancechain).
func (s *Store) RegisterTrustKey(name string, pub ed25519.PublicKey) {
	s.trust[name] = pub
}

const schema = `
CREATE TABLE IF NOT EXISTS signatures (
  app          TEXT NOT NULL,
  artifact_sha TEXT NOT NULL,
  signer       TEXT NOT NULL,
  sig_b64      TEXT NOT NULL,
  added_at     INTEGER NOT NULL,
  PRIMARY KEY (app, artifact_sha, signer)
);
CREATE INDEX IF NOT EXISTS idx_sig_app ON signatures(app);
`
