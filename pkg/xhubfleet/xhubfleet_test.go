package xhubfleet

import (
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/baseline"
	"github.com/xhelix/xhelix/pkg/baselinehub"
)

// --- CohortKey ---

func TestCohortKeyString_EmptyFieldsRenderAsDash(t *testing.T) {
	k := CohortKey{HostRole: "web"}
	got := k.String()
	want := "web|-|-|-|-|-|-|-"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestCohortKeyString_AllFieldsJoined(t *testing.T) {
	k := CohortKey{
		HostRole: "web", AppRole: "nginx", OSFamily: "debian12",
		PackageOrigin: "apt", VersionFamily: "1.24.x", Environment: "prod",
		ControlPanel: "none", NetworkZone: "public-web",
	}
	got := k.String()
	if strings.Count(got, "|") != 7 {
		t.Fatalf("expected 7 separators, got %q", got)
	}
	if !strings.HasPrefix(got, "web|nginx|debian12|") {
		t.Fatalf("unexpected order: %q", got)
	}
}

func TestFromTags_DropsTenant(t *testing.T) {
	tags := baselinehub.CohortTags{HostRole: "web", Tenant: "acme"}
	k := FromTags(tags)
	if k.HostRole != "web" {
		t.Fatalf("HostRole lost: %+v", k)
	}
	// Tenant is not a field on CohortKey — confirm by checking String stable.
	if !strings.Contains(k.String(), "web") {
		t.Fatalf("HostRole not in key string: %q", k.String())
	}
}

// --- RarityIndex / Cohort ---

func mkWindow(binary string, children, endpoints map[string]uint64) *baseline.Window {
	w := &baseline.Window{
		Binary:         binary,
		Hour:           time.Now().Truncate(time.Hour),
		Children:       children,
		Endpoints:      endpoints,
		FileWrites:     map[string]uint64{},
		SensitivePaths: map[string]uint64{},
		BinarySHAs:     map[string]uint64{},
		ListenPorts:    map[string]uint64{},
	}
	return w
}

func TestRarityIndex_IngestAndRarityFraction(t *testing.T) {
	idx := NewRarityIndex()
	tags := baselinehub.CohortTags{HostRole: "web", AppRole: "nginx"}
	for i, host := range []string{"h1", "h2", "h3", "h4"} {
		children := map[string]uint64{"worker": 5}
		if i == 0 {
			children["bash"] = 1 // bash only on h1
		}
		idx.Ingest(baselinehub.Upload{
			HostTag: host, Cohort: tags,
			Windows: []*baseline.Window{mkWindow("nginx", children, nil)},
		})
	}
	c := idx.Cohort(FromTags(tags))
	if c == nil {
		t.Fatal("cohort missing")
	}
	if c.HostCount() != 4 {
		t.Fatalf("HostCount=%d want 4", c.HostCount())
	}
	// worker on all 4 hosts → 1.0
	if got := c.RarityFraction(ClassChild, "nginx", "worker"); got != 1.0 {
		t.Fatalf("worker rarity=%v want 1.0", got)
	}
	// bash only on 1 → 0.25
	if got := c.RarityFraction(ClassChild, "nginx", "bash"); got != 0.25 {
		t.Fatalf("bash rarity=%v want 0.25", got)
	}
	// unknown feature → 0
	if got := c.RarityFraction(ClassChild, "nginx", "nope"); got != 0 {
		t.Fatalf("nope rarity=%v want 0", got)
	}
}

func TestRarityIndex_Reset(t *testing.T) {
	idx := NewRarityIndex()
	idx.Ingest(baselinehub.Upload{
		HostTag: "h1", Cohort: baselinehub.CohortTags{HostRole: "web"},
		Windows: []*baseline.Window{mkWindow("nginx", map[string]uint64{"worker": 1}, nil)},
	})
	if len(idx.Cohorts()) != 1 {
		t.Fatalf("expected 1 cohort")
	}
	idx.Reset()
	if len(idx.Cohorts()) != 0 {
		t.Fatalf("Reset did not clear")
	}
}

func TestRarityIndex_EmptyWindowsIgnored(t *testing.T) {
	idx := NewRarityIndex()
	idx.Ingest(baselinehub.Upload{HostTag: "h1", Windows: nil})
	if len(idx.Cohorts()) != 0 {
		t.Fatalf("empty upload should not create a cohort")
	}
}

// --- Score ---

func TestScore_RareChildContributes(t *testing.T) {
	c := newCohort(CohortKey{HostRole: "web"})
	// Populate 50 hosts each seeing "worker" — bash never appears.
	for i := 0; i < 50; i++ {
		host := "h" + string(rune('A'+i%26))
		c.AddWindow(host+string(rune('0'+i/26)), mkWindow("nginx", map[string]uint64{"worker": 1}, nil))
	}
	w := DefaultWeights()
	f := Score(w, ScoreContext{
		Cohort: c, HostTag: "h1", Binary: "nginx", ChildProcess: "bash",
	})
	found := false
	for _, c := range f.Contributions {
		if c.Condition == "rare_child" && c.Delta == w.RareChild {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected rare_child contribution, got %+v (score=%d)", f.Contributions, f.Score)
	}
}

func TestScore_CommonInCohortDiscount(t *testing.T) {
	c := newCohort(CohortKey{HostRole: "web"})
	for i := 0; i < 10; i++ {
		host := "h" + string(rune('A'+i))
		c.AddWindow(host, mkWindow("nginx", map[string]uint64{"worker": 1}, nil))
	}
	w := DefaultWeights()
	f := Score(w, ScoreContext{
		Cohort: c, HostTag: "h1", Binary: "nginx", ChildProcess: "worker",
	})
	if f.Score != w.CommonInCohort {
		t.Fatalf("Score=%d want %d (CommonInCohort)", f.Score, w.CommonInCohort)
	}
}

func TestScore_PositiveConditionsCompose(t *testing.T) {
	w := DefaultWeights()
	f := Score(w, ScoreContext{
		HostTag: "h1", Binary: "nginx",
		SensitivePath:    "/etc/shadow",
		FileWritePath:    "/etc/systemd/system/evil.service",
		DangerousSyscall: true,
		SecretThenEgress: true,
	})
	want := w.SensitiveAccess + w.PersistenceWrite + w.DangerousSyscall + w.SecretThenEgress
	if f.Score != want {
		t.Fatalf("Score=%d want %d", f.Score, want)
	}
	if f.Verdict != VerdictCritical {
		t.Fatalf("Verdict=%s want critical", f.Verdict)
	}
}

func TestScore_NegativeConditionsApply(t *testing.T) {
	w := DefaultWeights()
	f := Score(w, ScoreContext{
		HostTag: "h1", Binary: "nginx",
		InSignedBRP:    true,
		PackageManaged: true,
	})
	want := w.InSignedBRP + w.PackageManagedSHA
	if f.Score != want {
		t.Fatalf("Score=%d want %d", f.Score, want)
	}
	if f.Verdict != VerdictNormal {
		t.Fatalf("Verdict=%s want normal", f.Verdict)
	}
}

func TestScoreToVerdict_Thresholds(t *testing.T) {
	cases := []struct {
		score int
		want  Verdict
	}{
		{-100, VerdictNormal},
		{0, VerdictNormal},
		{19, VerdictNormal},
		{20, VerdictWatch},
		{49, VerdictWatch},
		{50, VerdictSuspicious},
		{79, VerdictSuspicious},
		{80, VerdictHigh},
		{119, VerdictHigh},
		{120, VerdictCritical},
		{500, VerdictCritical},
	}
	for _, c := range cases {
		if got := ScoreToVerdict(c.score); got != c.want {
			t.Errorf("score=%d got=%s want=%s", c.score, got, c.want)
		}
	}
}

func TestScore_IsPersistencePath(t *testing.T) {
	cases := map[string]bool{
		"/etc/cron.d/foo":           true,
		"/etc/systemd/system/x":     true,
		"/etc/pam.d/sshd":           true,
		"/etc/ssh/sshd_config":      true,
		"/root/.ssh/authorized_keys": true,
		"/var/spool/cron/root":      true,
		"/etc/sudoers":              true,
		"/boot/grub/grub.cfg":       true,
		"/tmp/foo":                  false,
		"/var/log/x":                false,
		"/home/user/file":           false,
	}
	for p, want := range cases {
		if got := isPersistencePath(p); got != want {
			t.Errorf("isPersistencePath(%q)=%v want %v", p, got, want)
		}
	}
}

func TestScore_ContributionsSortedByDeltaDesc(t *testing.T) {
	w := DefaultWeights()
	f := Score(w, ScoreContext{
		HostTag: "h1", Binary: "nginx",
		SensitivePath:    "/etc/shadow",
		SecretThenEgress: true,
		SourceFromWeb:    true,
	})
	if len(f.Contributions) < 2 {
		t.Fatalf("expected multiple contributions")
	}
	for i := 1; i < len(f.Contributions); i++ {
		if f.Contributions[i-1].Delta < f.Contributions[i].Delta {
			t.Fatalf("contributions not sorted desc by delta: %+v", f.Contributions)
		}
	}
}

// --- TrustRanker ---

func TestTrustRanker_NewHostIsUntrusted(t *testing.T) {
	r := NewTrustRanker(DefaultTrustPolicy())
	now := time.Now()
	r.See("h1", now)
	if got := r.Evaluate("h1", now); got != TrustUntrusted {
		t.Fatalf("Trust=%s want untrusted", got)
	}
	if r.CanTeach("h1") {
		t.Fatal("new host should not be allowed to teach")
	}
}

func TestTrustRanker_PromotionLifecycle(t *testing.T) {
	pol := DefaultTrustPolicy()
	r := NewTrustRanker(pol)
	start := time.Now()
	r.See("h1", start)

	// After 4 days → Candidate
	mid := start.Add(time.Duration(pol.MinObservedDays+1) * 24 * time.Hour)
	if got := r.Evaluate("h1", mid); got != TrustCandidate {
		t.Fatalf("at MinObservedDays+1 Trust=%s want candidate", got)
	}

	// After 11 days → Trusted
	late := start.Add(time.Duration(pol.MinObservedDays+pol.MinCandidateDays+1) * 24 * time.Hour)
	if got := r.Evaluate("h1", late); got != TrustTrusted {
		t.Fatalf("at full trust window Trust=%s want trusted", got)
	}
	if !r.CanTeach("h1") {
		t.Fatal("trusted host should be allowed to teach")
	}
}

func TestTrustRanker_CriticalAlertQuarantines(t *testing.T) {
	r := NewTrustRanker(DefaultTrustPolicy())
	now := time.Now()
	r.See("h1", now)
	r.RecordAlert("h1", "critical", now)
	if got := r.Evaluate("h1", now.Add(30*24*time.Hour)); got != TrustQuarantined {
		t.Fatalf("after critical Trust=%s want quarantined", got)
	}
	if r.CanTeach("h1") {
		t.Fatal("quarantined host must not teach")
	}
}

func TestTrustRanker_AlertBurstDemotesTrusted(t *testing.T) {
	pol := DefaultTrustPolicy()
	r := NewTrustRanker(pol)
	start := time.Now()
	r.See("h1", start)
	late := start.Add(time.Duration(pol.MinObservedDays+pol.MinCandidateDays+1) * 24 * time.Hour)
	// Promote to trusted.
	if got := r.Evaluate("h1", late); got != TrustTrusted {
		t.Fatalf("setup: want trusted got %s", got)
	}
	// Burst alerts above threshold.
	for i := 0; i <= pol.MaxAlerts24hForTrust; i++ {
		r.RecordAlert("h1", "high", late)
	}
	if got := r.Evaluate("h1", late); got != TrustCandidate {
		t.Fatalf("after alert burst Trust=%s want candidate (demoted)", got)
	}
}

func TestTrustRanker_DecayAlertsHalves(t *testing.T) {
	r := NewTrustRanker(DefaultTrustPolicy())
	now := time.Now()
	r.See("h1", now)
	for i := 0; i < 10; i++ {
		r.RecordAlert("h1", "high", now)
	}
	r.DecayAlerts()
	all := r.All()
	if len(all) != 1 {
		t.Fatalf("want 1 host got %d", len(all))
	}
	if all[0].AlertCount24h != 5 {
		t.Fatalf("decay: AlertCount24h=%d want 5", all[0].AlertCount24h)
	}
}
