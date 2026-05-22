//go:build linux

package credbroker

import "testing"

func TestPlaintextReaderAllowed(t *testing.T) {
	g := &FanGate{}
	g.SetPlaintextAllowlist(
		[]string{"aws", "kubectl"},
		[]string{"/usr/local/bin/myagent"},
		[]string{"/opt/security/*"},
	)

	tests := []struct {
		name string
		req  Request
		want bool
	}{
		{
			name: "allowed by comm",
			req:  Request{Lineage: []LineageNode{{Comm: "aws", Image: "/usr/local/bin/aws"}}},
			want: true,
		},
		{
			name: "allowed by exact image",
			req:  Request{Lineage: []LineageNode{{Comm: "x", Image: "/usr/local/bin/myagent"}}},
			want: true,
		},
		{
			name: "allowed by image glob",
			req:  Request{Lineage: []LineageNode{{Comm: "x", Image: "/opt/security/scanner"}}},
			want: true,
		},
		{
			name: "denied: webshell-shape reader",
			req:  Request{Lineage: []LineageNode{{Comm: "bash", Image: "/bin/bash"}}},
			want: false,
		},
		{
			name: "denied: tmp dropper",
			req:  Request{Lineage: []LineageNode{{Comm: "evil", Image: "/tmp/x"}}},
			want: false,
		},
		{
			name: "denied: empty lineage (fail-closed)",
			req:  Request{Lineage: nil},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.plaintextReaderAllowed(tc.req); got != tc.want {
				t.Errorf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultsAreNonEmpty(t *testing.T) {
	if len(DefaultPlaintextPaths()) == 0 {
		t.Fatal("DefaultPlaintextPaths empty")
	}
	if len(DefaultPlaintextReaderComms()) == 0 {
		t.Fatal("DefaultPlaintextReaderComms empty")
	}
	// Spot check that aws-cli is allowlisted (would be a regression
	// if someone trimmed the list and forgot the most-common tool).
	found := false
	for _, c := range DefaultPlaintextReaderComms() {
		if c == "aws" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("aws missing from default reader comm allowlist")
	}
}
