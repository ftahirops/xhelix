package sourcescore

import "testing"

func TestScore_EmptyIsZero(t *testing.T) {
	if got := Score(nil); got != 0 {
		t.Errorf("Score(nil)=%d want 0", got)
	}
}

func TestScore_DedupesTokens(t *testing.T) {
	a := Score([]Token{"shell_spawn"})
	b := Score([]Token{"shell_spawn", "shell_spawn", "shell_spawn"})
	if a != b {
		t.Errorf("dedup failed: %d vs %d", a, b)
	}
}

func TestScore_CapsAt100(t *testing.T) {
	toks := []Token{
		"shell_spawn", "priv_esc", "cred_access", "c2_beacon",
		"data_exfil", "encryption_burst", "data_destruction",
	}
	if s := Score(toks); s != 100 {
		t.Errorf("cap failed: %d want 100", s)
	}
}

func TestScore_UnknownTokenContributesBaseline(t *testing.T) {
	a := Score([]Token{"shell_spawn"})
	b := Score([]Token{"shell_spawn", "novel_ttp_xyz"})
	if b <= a {
		t.Errorf("unknown token should add baseline; %d -> %d", a, b)
	}
}

func TestBand_Thresholds(t *testing.T) {
	cases := []struct {
		s    int
		want Severity
	}{
		{0, SeverityInfo}, {19, SeverityInfo},
		{20, SeverityWarn}, {49, SeverityWarn},
		{50, SeverityHigh}, {79, SeverityHigh},
		{80, SeverityCritical}, {100, SeverityCritical},
	}
	for _, c := range cases {
		if got := Band(c.s); got != c.want {
			t.Errorf("Band(%d)=%q want %q", c.s, got, c.want)
		}
	}
}

func TestTracker_AddScoreForget(t *testing.T) {
	tr := NewTracker()
	tr.Add("src-1", "shell_spawn")
	tr.Add("src-1", "cred_access")
	tr.Add("src-2", "c2_beacon")
	if s := tr.Score("src-1"); s < 50 {
		t.Errorf("src-1 score=%d want >=50", s)
	}
	if s := tr.Score("src-3"); s != 0 {
		t.Errorf("unknown source score=%d want 0", s)
	}
	tr.Forget("src-1")
	if s := tr.Score("src-1"); s != 0 {
		t.Errorf("forget failed: src-1 score=%d", s)
	}
}

func TestTracker_SnapshotSorted(t *testing.T) {
	tr := NewTracker()
	tr.Add("low", "recon")                       // ~6
	tr.Add("high", "shell_spawn")                // ~30
	tr.Add("high", "data_exfil")                 // +40 → 70
	tr.Add("mid", "lolbin_exec")                 // ~22
	snap := tr.Snapshot()
	if len(snap) != 3 {
		t.Fatalf("snapshot len=%d want 3", len(snap))
	}
	if snap[0].SourceID != "high" {
		t.Errorf("snap[0]=%q want high (got %+v)", snap[0].SourceID, snap)
	}
	if snap[2].SourceID != "low" {
		t.Errorf("snap[2]=%q want low", snap[2].SourceID)
	}
}

func TestTracker_NilSafe(t *testing.T) {
	var tr *Tracker
	tr.Add("x", "y")
	tr.Forget("x")
	if s := tr.Score("x"); s != 0 {
		t.Errorf("nil tracker score=%d want 0", s)
	}
	if got := tr.Snapshot(); got != nil {
		t.Errorf("nil snapshot=%v want nil", got)
	}
}
