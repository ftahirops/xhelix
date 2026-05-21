package labels

import (
	"testing"
	"time"
)

func TestPutGetRoundtrip(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	in := Label{
		EventID:   "01ABC",
		RuleID:    "shell_with_socket_fd",
		Verdict:   VerdictFP,
		Tag:       "ansible-deploy",
		By:        "alice",
		At:        time.Unix(1700000000, 0).UTC(),
		HostClass: "dev_workstation",
		RuleVer:   "rev-2026-05-21",
		Notes:     "false alarm during config push",
	}
	if err := s.Put(in); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("01ABC")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.Verdict != VerdictFP || got.Tag != "ansible-deploy" || got.By != "alice" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestPut_Idempotent(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for i := 0; i < 3; i++ {
		err := s.Put(Label{EventID: "X", RuleID: "memfd", Verdict: VerdictTP})
		if err != nil {
			t.Fatal(err)
		}
	}
	n, _ := s.Count()
	if n != 1 {
		t.Errorf("expected 1 row after 3 puts on same id, got %d", n)
	}
}

func TestVerdict_Validate(t *testing.T) {
	for _, v := range []Verdict{VerdictTP, VerdictFP, VerdictBenign, VerdictUnknown} {
		if err := v.Validate(); err != nil {
			t.Errorf("%q should validate: %v", v, err)
		}
	}
	if err := Verdict("garbage").Validate(); err == nil {
		t.Error("garbage verdict should error")
	}
}

func TestPerRule(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	for i, l := range []Label{
		{EventID: "A1", RuleID: "memfd_run_pattern", Verdict: VerdictFP, Tag: "node-jit"},
		{EventID: "A2", RuleID: "memfd_run_pattern", Verdict: VerdictFP, Tag: "node-jit"},
		{EventID: "A3", RuleID: "memfd_run_pattern", Verdict: VerdictTP, Tag: "real-attack"},
		{EventID: "B1", RuleID: "shell_with_socket_fd", Verdict: VerdictTP},
	} {
		_ = i
		if err := s.Put(l); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := s.PerRule(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range stats {
		switch st.RuleID {
		case "memfd_run_pattern":
			if st.TP != 1 || st.FP != 2 {
				t.Errorf("memfd: want tp=1 fp=2, got tp=%d fp=%d", st.TP, st.FP)
			}
		case "shell_with_socket_fd":
			if st.TP != 1 {
				t.Errorf("shell: want tp=1, got tp=%d", st.TP)
			}
		}
	}
}

func TestFPSet(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()
	_ = s.Put(Label{EventID: "A", RuleID: "memfd_run_pattern", Verdict: VerdictFP, Tag: "node-jit"})
	_ = s.Put(Label{EventID: "B", RuleID: "memfd_run_pattern", Verdict: VerdictFP, Tag: "node-jit"})
	_ = s.Put(Label{EventID: "C", RuleID: "memfd_run_pattern", Verdict: VerdictFP, Tag: "claude-shell"})
	_ = s.Put(Label{EventID: "D", RuleID: "memfd_run_pattern", Verdict: VerdictTP, Tag: "real-attack"})

	set, err := s.FPSet(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if set[FPKey{"memfd_run_pattern", "node-jit"}] != 2 {
		t.Errorf("node-jit FP count = %d, want 2", set[FPKey{"memfd_run_pattern", "node-jit"}])
	}
	if set[FPKey{"memfd_run_pattern", "claude-shell"}] != 1 {
		t.Errorf("claude-shell FP count = %d, want 1", set[FPKey{"memfd_run_pattern", "claude-shell"}])
	}
	if _, has := set[FPKey{"memfd_run_pattern", "real-attack"}]; has {
		t.Error("TP should not appear in FPSet")
	}
}
