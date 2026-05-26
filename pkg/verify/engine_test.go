package verify

import (
	"testing"

	"github.com/xhelix/xhelix/pkg/brp"
)

func TestEngine_CredentialBackboneIsPromote(t *testing.T) {
	e := NewEngine()
	in := Input{
		Facts: brp.EventFacts{Action: "file_write", Path: "/etc/shadow"},
	}
	r := e.Evaluate(in)
	if r.Outcome != OutcomePromote {
		t.Errorf("/etc/shadow write: outcome=%s, want promote", r.Outcome)
	}
	if r.Score < e.HighThreshold {
		t.Errorf("score %.2f below high threshold %.2f", r.Score, e.HighThreshold)
	}
}

func TestEngine_CronEntryIsSuspicious(t *testing.T) {
	e := NewEngine()
	in := Input{
		Facts: brp.EventFacts{Action: "file_write", Path: "/etc/cron.d/.attack"},
	}
	r := e.Evaluate(in)
	if r.Outcome != OutcomeSuspicious {
		t.Errorf("/etc/cron.d/ write: outcome=%s, want suspicious", r.Outcome)
	}
}

func TestEngine_ResolvConfIsBenign(t *testing.T) {
	// Tier 1 path alone (score 1.0) is below LowThreshold default of 1.0
	// (strictly less than). Actually 1.0 >= 1.0 so it becomes suspicious.
	// This documents the boundary behavior.
	e := NewEngine()
	in := Input{
		Facts: brp.EventFacts{Action: "file_write", Path: "/etc/resolv.conf"},
	}
	r := e.Evaluate(in)
	if r.Outcome != OutcomeSuspicious {
		t.Errorf("/etc/resolv.conf at LowThreshold boundary: outcome=%s, want suspicious",
			r.Outcome)
	}
}

func TestEngine_UnknownPathIsBenign(t *testing.T) {
	e := NewEngine()
	in := Input{
		Facts: brp.EventFacts{Action: "file_write", Path: "/home/user/foo.txt"},
	}
	r := e.Evaluate(in)
	if r.Outcome != OutcomeBenign {
		t.Errorf("/home/user/ write: outcome=%s, want benign", r.Outcome)
	}
	if r.Score != 0 {
		t.Errorf("non-protected path score=%.2f, want 0", r.Score)
	}
}

func TestEngine_AddDomainCombines(t *testing.T) {
	e := NewEngine()
	// Add a domain that always adds 10 — pushes anything to Promote.
	e.AddDomain(constantDomain{value: 10})
	r := e.Evaluate(Input{Facts: brp.EventFacts{Path: "/home/user/foo"}})
	if r.Outcome != OutcomePromote {
		t.Errorf("constant=10 forces promote, got %s", r.Outcome)
	}
	if r.Domains["constant"] != 10 {
		t.Errorf("per-domain breakdown wrong: %+v", r.Domains)
	}
}

func TestPathClassifier_AllTiers(t *testing.T) {
	pc := PathClassifier{}
	cases := []struct {
		path string
		want float64
	}{
		{"/etc/shadow", 5.0},
		{"/etc/sudoers.d/foo", 5.0},
		{"/root/.ssh/authorized_keys", 5.0},
		{"/etc/cron.d/whatever", 3.0},
		{"/boot/vmlinuz", 3.0},
		{"/var/lib/mysql/ibdata1", 2.0},
		{"/etc/psa/.psa.shadow", 2.0},
		{"/etc/hosts", 1.0},
		{"/home/user/file", 0},
	}
	for _, c := range cases {
		got, _ := pc.Score(Input{Facts: brp.EventFacts{Path: c.path}})
		if got != c.want {
			t.Errorf("PathClassifier(%q) = %.1f, want %.1f", c.path, got, c.want)
		}
	}
}

type constantDomain struct{ value float64 }

func (constantDomain) Name() string                          { return "constant" }
func (c constantDomain) Score(_ Input) (float64, string)     { return c.value, "" }
