package brp

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEdgeSet_AddAndLookup(t *testing.T) {
	s := NewEdgeSet(nil)
	if err := s.AddEdge(Edge{
		SchemaVersion: 1,
		FromApp:       "nginx",
		ToApp:         "php-fpm",
		AllowedActions: []string{"net_connect"},
		Destinations:   []string{"unix:/run/php/php-fpm.sock"},
	}); err != nil {
		t.Fatal(err)
	}
	ok, e := s.Allows("nginx", "php-fpm", "net_connect", "unix:/run/php/php-fpm.sock")
	if !ok {
		t.Error("exact match should be allowed")
	}
	if e.Note == "" && e.FromApp != "nginx" {
		t.Errorf("matched edge wrong: %+v", e)
	}
}

func TestEdgeSet_PrefixMatch(t *testing.T) {
	s := NewEdgeSet(nil)
	s.AddEdge(Edge{
		SchemaVersion: 1, FromApp: "nginx", ToApp: "php-fpm",
		Destinations: []string{"127.0.0.1:"},
	})
	ok, _ := s.Allows("nginx", "php-fpm", "net_connect", "127.0.0.1:9000")
	if !ok {
		t.Error("prefix match on host:port should be allowed")
	}
}

func TestEdgeSet_ActionRestriction(t *testing.T) {
	s := NewEdgeSet(nil)
	s.AddEdge(Edge{
		SchemaVersion: 1, FromApp: "nginx", ToApp: "php-fpm",
		AllowedActions: []string{"net_connect"},
	})
	if ok, _ := s.Allows("nginx", "php-fpm", "exec", ""); ok {
		t.Error("non-allowed action must reject")
	}
}

func TestEdgeSet_AnyActionWhenUnrestricted(t *testing.T) {
	s := NewEdgeSet(nil)
	s.AddEdge(Edge{
		SchemaVersion: 1, FromApp: "nginx", ToApp: "php-fpm",
		// no AllowedActions = any action
	})
	if ok, _ := s.Allows("nginx", "php-fpm", "anything", ""); !ok {
		t.Error("empty AllowedActions must allow any action")
	}
}

func TestEdgeSet_UnknownPairRejected(t *testing.T) {
	s := NewEdgeSet(nil)
	if ok, _ := s.Allows("foo", "bar", "x", ""); ok {
		t.Error("unknown pair should reject")
	}
}

func TestEdgeSet_AddEdgeValidation(t *testing.T) {
	s := NewEdgeSet(nil)
	if err := s.AddEdge(Edge{FromApp: "a", ToApp: "b"}); err == nil {
		t.Error("missing schema_version should error")
	}
	if err := s.AddEdge(Edge{SchemaVersion: 1, ToApp: "b"}); err == nil {
		t.Error("missing from_app should error")
	}
}

func TestEdgeSet_LoadDirFromDisk(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(nil)

	signedGood, err := SignEdge(Edge{
		SchemaVersion:  1,
		FromApp:        "nginx",
		ToApp:          "php-fpm",
		AllowedActions: []string{"net_connect"},
		Destinations:   []string{"unix:/run/php/php-fpm.sock"},
	}, "ops-local", priv)
	if err != nil {
		t.Fatal(err)
	}
	goodB, _ := json.Marshal(signedGood)
	bad := `{"edge":{"schema_version":1,"from_app":"a","to_app":"b"}}` // no signature
	untrustedSigned, _ := SignEdge(Edge{SchemaVersion: 1, FromApp: "x", ToApp: "y"},
		"untrusted-signer", priv)
	untrustedB, _ := json.Marshal(untrustedSigned)

	os.WriteFile(filepath.Join(dir, "good.edge.json"), goodB, 0o644)
	os.WriteFile(filepath.Join(dir, "bad.edge.json"), []byte(bad), 0o644)
	os.WriteFile(filepath.Join(dir, "untrusted.edge.json"), untrustedB, 0o644)
	os.WriteFile(filepath.Join(dir, "ignore.txt"), []byte("not an edge"), 0o644)

	s := NewEdgeSet(map[string]ed25519.PublicKey{"ops-local": pub})
	loaded, rejected, err := s.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != 1 {
		t.Errorf("loaded=%d, want 1", loaded)
	}
	if rejected != 2 {
		t.Errorf("rejected=%d, want 2 (missing signature + untrusted signer)", rejected)
	}
}

func TestSignAndVerifyEdge_Roundtrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	e := Edge{SchemaVersion: 1, FromApp: "a", ToApp: "b"}
	se, err := SignEdge(e, "signer1", priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEdge(se, pub); err != nil {
		t.Errorf("verify failed: %v", err)
	}
	// Tamper with the edge content.
	se.Edge.ToApp = "c"
	if err := VerifyEdge(se, pub); err == nil {
		t.Error("tampered edge should fail verification")
	}
}

func TestEdgeSet_LoadDirMissingNotError(t *testing.T) {
	s := NewEdgeSet(nil)
	loaded, rejected, err := s.LoadDir("/nonexistent/path")
	if err != nil {
		t.Errorf("missing dir should not error, got %v", err)
	}
	if loaded != 0 || rejected != 0 {
		t.Errorf("missing dir should return zero counts")
	}
}
