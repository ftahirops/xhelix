package credbroker

import (
	"bytes"
	"strings"
	"testing"
)

func TestHoneyGenerate(t *testing.T) {
	h := NewHoneyFactory()
	cases := []struct {
		name       string
		class      Class
		sealedPath string
		mustContain []string
	}{
		{"aws", ClassCredentials, "/root/.aws/credentials.sealed",
			[]string{"AKIA", "aws_secret_access_key", "xhelix-marker"}},
		{"ssh", ClassCredentials, "/root/.ssh/id_ed25519.sealed",
			[]string{"BEGIN OPENSSH PRIVATE KEY", "END OPENSSH PRIVATE KEY", "xhelix-marker"}},
		{"kube", ClassCredentials, "/root/.kube/config.sealed",
			[]string{"apiVersion: v1", "current-context", "xhelix-marker"}},
		{"api", ClassAPIKey, "/etc/myapp/token.sealed",
			[]string{"API_KEY", "xhelix-marker"}},
		{"generic", ClassBackup, "/srv/backup.sealed",
			[]string{markerPrefix}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			content, origin := h.Generate(c.class, c.sealedPath, Request{})
			for _, s := range c.mustContain {
				if !bytes.Contains(content, []byte(s)) {
					t.Errorf("%s: honey content missing %q\n--\n%s", c.name, s, content)
				}
			}
			if !strings.HasPrefix(origin.Marker, markerPrefix) {
				t.Errorf("origin marker should start with prefix, got %q", origin.Marker)
			}
			if !bytes.Contains(content, []byte(origin.Marker)) {
				t.Errorf("honey content should contain marker %q", origin.Marker)
			}
		})
	}
}

func TestHoneyMarkerUnique(t *testing.T) {
	h := NewHoneyFactory()
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		_, o := h.Generate(ClassAPIKey, "/x.sealed", Request{})
		if seen[o.Marker] {
			t.Fatalf("marker collision: %s", o.Marker)
		}
		seen[o.Marker] = true
	}
}

func TestHoneyLookup(t *testing.T) {
	h := NewHoneyFactory()
	_, o := h.Generate(ClassAPIKey, "/x.sealed", Request{PID: 42})
	got, ok := h.Lookup(o.Marker)
	if !ok {
		t.Fatal("lookup should find issued marker")
	}
	if got.SealedPath != "/x.sealed" || got.RequestPID != 42 {
		t.Errorf("origin fields wrong: %+v", got)
	}
	if _, ok := h.Lookup("xhx_h_nonexistent"); ok {
		t.Error("lookup of unknown marker should miss")
	}
}

func TestIsHoneyMarkerDetection(t *testing.T) {
	h := NewHoneyFactory()
	_, o := h.Generate(ClassAPIKey, "/x.sealed", Request{})
	// Embedded in arbitrary surrounding text.
	wire := "GET /api HTTP/1.1\r\nAuthorization: Bearer " + o.Marker + "\r\n"
	got, ok := IsHoneyMarker(wire)
	if !ok {
		t.Fatal("marker should be detected in wire payload")
	}
	if got != o.Marker {
		t.Errorf("extracted marker %q != issued %q", got, o.Marker)
	}
	if _, ok := IsHoneyMarker("nothing to see here"); ok {
		t.Error("plain text should not match")
	}
}
