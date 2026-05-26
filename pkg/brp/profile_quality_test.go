package brp

import (
	"strings"
	"testing"
	"time"

	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

func validBaseProfile() Profile {
	return Profile{
		SchemaVersion: SchemaVersion,
		ProfileID:     "test-v1",
		Confidence:    ConfidenceStrict,
		SigningEpoch:  time.Now().UnixNano(),
		Key:           parser.ProfileKey{App: "nginx", Role: "nginx-reverse-proxy"},
		Behavior: parser.ConfigDerivedBehavior{
			ListenPorts:   []int{80, 443},
			UpstreamHosts: []string{"127.0.0.1:8080"},
		},
	}
}

func TestQualityWarnings_CleanProfileNoWarnings(t *testing.T) {
	p := validBaseProfile()
	if ws := p.QualityWarnings(); len(ws) != 0 {
		t.Errorf("clean profile got %d warnings: %v", len(ws), ws)
	}
}

func TestQualityWarnings_WideWriteRoots(t *testing.T) {
	p := validBaseProfile()
	for i := 0; i < 15; i++ {
		p.Behavior.WriteRoots = append(p.Behavior.WriteRoots, "/tmp/path")
	}
	ws := p.QualityWarnings()
	if !hasSubstring(ws, "WriteRoots has 15") {
		t.Errorf("expected wide-WriteRoots warning, got %v", ws)
	}
}

func TestQualityWarnings_NginxNoUpstreams(t *testing.T) {
	p := validBaseProfile()
	p.Behavior.UpstreamHosts = nil
	p.Behavior.UpstreamSockets = nil
	ws := p.QualityWarnings()
	if !hasSubstring(ws, "no declared UpstreamHosts") {
		t.Errorf("expected no-upstreams warning, got %v", ws)
	}
}

func TestQualityWarnings_WebRoleWithShellInExecAllowed(t *testing.T) {
	p := validBaseProfile()
	p.Behavior.ExecAllowed = []string{"/bin/sh", "/usr/bin/python3"}
	ws := p.QualityWarnings()
	if !hasSubstring(ws, "/bin/sh") {
		t.Errorf("expected dangerous-exec warning, got %v", ws)
	}
	// Both dangerous entries should warn.
	if len(ws) < 2 {
		t.Errorf("expected ≥2 warnings (one per dangerous exec), got %d: %v", len(ws), ws)
	}
}

func TestQualityWarnings_ApacheNoListenPorts(t *testing.T) {
	p := validBaseProfile()
	p.Key.App = "apache"
	p.Behavior.ListenPorts = nil
	p.Behavior.ListenSockets = nil
	ws := p.QualityWarnings()
	if !hasSubstring(ws, "no declared ListenPorts") {
		t.Errorf("expected no-listen warning, got %v", ws)
	}
}

func TestQualityWarnings_NonWebDBRoleSkipsExecCheck(t *testing.T) {
	// A custom app with /bin/sh in ExecAllowed but role not in the
	// web-or-db set — no warning fires.
	p := validBaseProfile()
	p.Key.App = "custom-tool"
	p.Key.Role = "custom-helper"
	p.Behavior.ExecAllowed = []string{"/bin/sh"}
	ws := p.QualityWarnings()
	for _, w := range ws {
		if strings.Contains(w, "/bin/sh") {
			t.Errorf("custom role should not warn about ExecAllowed, got %v", ws)
		}
	}
}

func hasSubstring(ws []string, sub string) bool {
	for _, w := range ws {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}
