package credbroker

import (
	"path/filepath"
	"os"
	"testing"
)

func TestContractMatchAllowsLegitimateBinary(t *testing.T) {
	c := DefaultContract()
	// Compile (DefaultContract returns rules without re cached).
	for i := range c.Rules {
		// Force compile by re-running LoadContract path.
		c.Rules = c.Rules[:i+1]
		break
	}
	// Easier: load from YAML.
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
default_deny: true
rules:
  - name: aws_cli
    image_regex: '(^|/)aws$'
    allowed_classes: [api_key, credentials]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadContract(path)
	if err != nil {
		t.Fatal(err)
	}
	lineage := []LineageNode{
		{Image: "/usr/local/bin/aws", Comm: "aws", UID: 1000},
	}
	r := c.Match(lineage, ClassAPIKey)
	if !r.Matched || r.RuleName != "aws_cli" {
		t.Errorf("expected aws_cli match, got %+v", r)
	}
}

func TestContractDeniesUnknownBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.yaml")
	_ = os.WriteFile(path, []byte(`
version: 1
default_deny: true
rules:
  - name: aws_cli
    image_regex: '(^|/)aws$'
    allowed_classes: [api_key]
`), 0o600)
	c, _ := LoadContract(path)
	// Lineage = python (not aws).
	lineage := []LineageNode{{Image: "/usr/bin/python3", Comm: "python3"}}
	r := c.Match(lineage, ClassAPIKey)
	if r.Matched {
		t.Errorf("expected no match for python on api_key, got %+v", r)
	}
}

func TestContractRefusesClassMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.yaml")
	_ = os.WriteFile(path, []byte(`
version: 1
default_deny: true
rules:
  - name: git_lim
    image_regex: '(^|/)git$'
    allowed_classes: [source_code]
`), 0o600)
	c, _ := LoadContract(path)
	lineage := []LineageNode{{Image: "/usr/bin/git", Comm: "git"}}
	// git is allowed source_code but NOT api_key — must NOT match
	// and must NOT fall through to a more permissive rule.
	r := c.Match(lineage, ClassAPIKey)
	if r.Matched {
		t.Errorf("git matched on api_key (class isolation broken): %+v", r)
	}
	if r.RuleName != "git_lim" {
		t.Errorf("expected matched rule name to be the image-match (git_lim) "+
			"even though class denied; got %+v", r)
	}
}

func TestBrokerWithContractDecide(t *testing.T) {
	b := newTestBroker(t)
	// Wire a strict contract: only aws is allowed to read api_key.
	dir := t.TempDir()
	path := filepath.Join(dir, "ct.yaml")
	_ = os.WriteFile(path, []byte(`
version: 1
default_deny: true
rules:
  - name: aws_cli
    image_regex: '(^|/)aws$'
    allowed_classes: [api_key]
`), 0o600)
	c, err := LoadContract(path)
	if err != nil {
		t.Fatal(err)
	}
	b.WithContract(c)

	pt := []byte("aws creds")
	sf, _ := b.Seal(pt, Meta{Class: ClassAPIKey, Purpose: "test"})

	// 1) legit aws lineage → allow
	res := b.Decide(sf, Request{
		PID:     100,
		Lineage: []LineageNode{{Image: "/usr/local/bin/aws", Comm: "aws"}},
	})
	if res.Outcome != OutcomeAllow {
		t.Errorf("legit aws lineage: got %s want allow (reason=%s)",
			res.Outcome, res.Reason)
	}

	// 2) malicious python lineage → deny
	res = b.Decide(sf, Request{
		PID:     200,
		Lineage: []LineageNode{{Image: "/usr/bin/python3", Comm: "python3"}},
	})
	if res.Outcome != OutcomeDeny {
		t.Errorf("python lineage: got %s want deny (reason=%s)",
			res.Outcome, res.Reason)
	}
	if len(res.Plaintext) != 0 {
		t.Errorf("denied request must not return plaintext (got %d bytes)",
			len(res.Plaintext))
	}

	// 3) attestation-required path is exercised by aws here only
	// because attest_required isn't set on aws_cli in this test.
	// Audit must record the rule that matched.
	hist := b.History()
	if len(hist) != 2 {
		t.Errorf("history len = %d, want 2", len(hist))
	}
}
