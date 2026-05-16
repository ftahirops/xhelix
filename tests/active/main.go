// Active-response end-to-end harness.
//
// Wires every piece of the detect→trace→block→remediate→notify
// pipeline and runs real attacks against itself. Reports per-attack
// which actions actually fired.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xhelix/xhelix/pkg/alert"
	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/netban"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/remediate"
	"github.com/xhelix/xhelix/pkg/response"
	"github.com/xhelix/xhelix/pkg/rules"
	"github.com/xhelix/xhelix/pkg/session"
	"github.com/xhelix/xhelix/sensors/decoy"
	xhebpf "github.com/xhelix/xhelix/sensors/ebpf"
	fimsensor "github.com/xhelix/xhelix/sensors/fim"
)

// fakeXDP is an in-memory netban target so we don't touch the
// host's real packet path during testing.
type fakeXDP struct {
	mu   sync.Mutex
	bans map[string]bool
}

func (f *fakeXDP) Add(ip net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.bans == nil {
		f.bans = map[string]bool{}
	}
	f.bans[ip.String()] = true
	return nil
}
func (f *fakeXDP) Remove(ip net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.bans, ip.String())
	return nil
}
func (f *fakeXDP) List() ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]net.IP, 0, len(f.bans))
	for s := range f.bans {
		out = append(out, net.ParseIP(s))
	}
	return out, nil
}
func (f *fakeXDP) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.bans))
	for s := range f.bans {
		out = append(out, s)
	}
	return out
}

// captured tracks every action the response engine took.
type captured struct {
	mu          sync.Mutex
	alerts      []model.Alert
	rulesFired  map[string]int
	stoppedPIDs []uint32
	bannedIPs   map[string]bool
	remediated  map[string]bool
	webhookHits []string // rule_ids
}

func newCaptured() *captured {
	return &captured{
		rulesFired: map[string]int{},
		bannedIPs:  map[string]bool{},
		remediated: map[string]bool{},
	}
}

// quarantineProxy wraps the real Quarantine so we can record SIGSTOPs
// without actually stopping processes (that would lock up the harness).
type quarantineProxy struct {
	rec  *captured
	real *enforce.Quarantine
}

func (q *quarantineProxy) Stop(pid uint32, comm, image, ruleID string) (*enforce.QuarantineRecord, error) {
	q.rec.mu.Lock()
	q.rec.stoppedPIDs = append(q.rec.stoppedPIDs, pid)
	q.rec.mu.Unlock()
	// Don't actually SIGSTOP — pid may be the harness's own descendants.
	return &enforce.QuarantineRecord{PID: pid, RuleID: ruleID, State: "stopped"}, nil
}
func (q *quarantineProxy) Resume(pid uint32) error                    { return nil }
func (q *quarantineProxy) Kill(pid uint32) error                      { return nil }
func (q *quarantineProxy) Snapshot() []enforce.QuarantineRecord       { return nil }

func main() {
	rec := newCaptured()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Webhook receiver (local httptest)
	var webhookCount atomic.Uint64
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCount.Add(1)
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)
		var parsed map[string]any
		_ = json.Unmarshal(body, &parsed)
		if rid, ok := parsed["rule_id"].(string); ok {
			rec.mu.Lock()
			rec.webhookHits = append(rec.webhookHits, rid)
			rec.mu.Unlock()
		}
		w.WriteHeader(200)
	}))
	defer webhookSrv.Close()
	webhookSink := alert.NewWebhookSink(webhookSrv.URL, "test-host")
	fmt.Printf("[harness] webhook receiver: %s\n", webhookSrv.URL)

	// 2. Netban with in-memory XDP, nftables OFF (we don't want to
	// touch the host's real firewall in this test).
	xdp := &fakeXDP{}
	banner := netban.NewBanner(xdp, false)

	// 3. Remediator + backups
	remDir, _ := os.MkdirTemp("", "xh-remediate")
	defer os.RemoveAll(remDir)
	rem, err := remediate.New(filepath.Join(remDir, "backup"), filepath.Join(remDir, "quarantine"))
	must(err)

	// 4. Watched files (we treat tmp paths as if they were /etc/X)
	watchedEtc, _ := os.MkdirTemp("", "xh-fim")
	defer os.RemoveAll(watchedEtc)
	passwdPath := filepath.Join(watchedEtc, "passwd")
	preloadPath := filepath.Join(watchedEtc, "ld.so.preload")
	goodPasswd := []byte("root:x:0:0:root:/root:/bin/bash\n")
	must(os.WriteFile(passwdPath, goodPasswd, 0o644))
	must(os.WriteFile(preloadPath, []byte(""), 0o644))
	must(rem.Backup(passwdPath))
	must(rem.Backup(preloadPath))
	fmt.Printf("[harness] backups taken for: %s, %s\n", passwdPath, preloadPath)

	// 5. Session tracker
	tracker := session.New(0)

	// 6. Quarantine proxy (real Quarantine would actually SIGSTOP)
	realQ := enforce.NewQuarantine(enforce.DefaultSignalFn)
	_ = realQ
	qProxy := &quarantineProxy{rec: rec, real: realQ}

	// 7. Response engine
	respEng := response.New(response.Config{
		NetBanner:    banner,
		Remediator:   &remediateProxy{real: rem, rec: rec},
		Quarantine:   nil, // we use the proxy via direct OnAlert override below
		PanicSwitch:  enforce.NewPanicSwitch(filepath.Join(remDir, "panic")),
		Webhook: func(c context.Context, a model.Alert) error {
			return webhookSink.Send(c, a)
		},
	})
	// Wrap OnAlert to also feed our quarantine proxy (the engine only
	// supports the real *Quarantine type but our proxy implements the
	// same shape — we patch by intercepting).
	emitAlert := func(a model.Alert) {
		rec.mu.Lock()
		rec.alerts = append(rec.alerts, a)
		rec.rulesFired[a.RuleID]++
		rec.mu.Unlock()
		tracker.IngestAlert(a)
		respEng.OnAlert(a)
		// Also evaluate the quarantine policy via proxy
		policy := response.Default()
		mask := policy[a.RuleID]
		if mask&response.ActionQuarantine != 0 && a.Event.PID != 0 {
			_, _ = qProxy.Stop(a.Event.PID, a.Event.Comm, a.Event.Image, a.RuleID)
		}
	}

	// 8. Rule engine
	eng, err := rules.NewEngine(emitAlert)
	must(err)
	rls, err := rules.LoadDir("/home/rctop/xhelix/ruleset/core")
	must(err)
	must(eng.Load(rls))
	fmt.Printf("[harness] loaded %d rules\n", len(rls))

	procTree := proctree.New(0)
	eng.SetTreeFn(procTree.Ancestors)

	// 9. Correlator with the ssh-brute rule
	corr, _ := correlator.New(emitAlert)
	must(corr.Load([]correlator.Rule{{
		ID:          "ssh_brute_then_success",
		Desc:        "ssh brute then success",
		SeverityRaw: "critical",
		Window:      time.Minute * 10,
		GroupBy:     []string{"src_ip"},
		Steps: []correlator.Step{
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "failure"`,
				Within: 10 * time.Minute},
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "success" && event.tags["src_ip"] == group.src_ip`,
				Within: time.Minute},
		},
	}}))

	// 10. Sensors
	events := make(chan model.Event, 4096)
	ebpfS := xhebpf.New(xhebpf.Config{RingbufSizeMB: 1, SelfPID: uint32(os.Getpid())})
	must(ebpfS.Start(ctx, events))
	defer ebpfS.Stop(context.Background())

	fimDB := filepath.Join(remDir, "fim.db")
	fimS := fimsensor.NewSensor(fimDB, []string{watchedEtc}, "test-host", 1500*time.Millisecond)
	must(fimS.Start(ctx, events))
	defer fimS.Stop(context.Background())

	// Decoys
	decoyDir, _ := os.MkdirTemp("", "xh-decoy")
	defer os.RemoveAll(decoyDir)
	honeyFile := filepath.Join(decoyDir, "credentials.txt")
	dF := decoy.NewFilesSensor([]decoy.HoneyFile{
		{Path: honeyFile, Persona: "passwd-list"},
	}, "test-host")
	must(dF.Start(ctx, events))
	defer dF.Stop(context.Background())

	dS := decoy.NewServicesSensor([]decoy.HoneyService{
		{Persona: "redis", Bind: "127.0.0.1:0"},
	}, "test-host")
	must(dS.Start(ctx, events))
	addrs := dS.Addrs()
	defer dS.Stop(context.Background())

	// 11. Dispatch loop — feeds tracker, proc tree, rule engine, correlator
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				tracker.Ingest(ev)
				if ev.Sensor == "ebpf.proc" {
					procTree.OnSpawn(proctree.Node{
						PID: ev.PID, PPID: ev.ParentPID, Comm: ev.Comm, UID: ev.UID,
					})
				}
				eng.Eval(ctx, ev)
				corr.Ingest(ctx, ev)
			}
		}
	}()

	time.Sleep(800 * time.Millisecond)

	// =================================================================
	fmt.Println("\n========== RUNNING ATTACKS ==========")

	// Synthetic SSH login → opens session "alice@198.51.100.5"
	loginEv := model.NewEvent("identity.sshd", model.SeverityInfo)
	loginEv.Tags["outcome"] = "success"
	loginEv.Tags["user"] = "alice"
	loginEv.Tags["src_ip"] = "198.51.100.5"
	loginEv.Tags["method"] = "publickey"
	loginEv.PID = uint32(os.Getpid())
	loginEv.Time = time.Now()
	tracker.Ingest(loginEv)

	type attack struct {
		ID, Title string
		Run       func()
		Expect    []string // categories expected: alert, webhook, stop, ban, remediate
	}
	attacks := []attack{
		{
			ID:    "B1",
			Title: "Honey file open → expect alert + webhook",
			Expect: []string{"alert", "webhook"},
			Run: func() { _, _ = os.ReadFile(honeyFile) },
		},
		{
			ID:    "B2",
			Title: "Honey service connect from 198.51.100.5 → alert + webhook + ban",
			Expect: []string{"alert", "webhook", "ban"},
			Run: func() {
				if len(addrs) > 0 {
					// Connect locally; we'll ALSO synthesise an event
					// with a public src_ip so netban actually fires
					// (the engine refuses to ban loopback).
					c, err := net.DialTimeout("tcp", addrs[0], 500*time.Millisecond)
					if err == nil {
						c.Close()
					}
					synth := model.NewEvent("decoy", model.SeverityCritical)
					synth.Tags["honey_service_connect"] = "true"
					synth.Tags["persona"] = "redis"
					synth.Tags["src"] = "203.0.113.10:54321"
					events <- synth
				}
			},
		},
		{
			ID:    "B3",
			Title: "/etc/passwd tampered → alert + webhook + remediate",
			Expect: []string{"alert", "webhook", "remediate"},
			Run: func() {
				_ = os.WriteFile(passwdPath,
					[]byte("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh\n"),
					0o644)
			},
		},
		{
			ID:    "B4",
			Title: "ld.so.preload modified → alert + webhook + remediate",
			Expect: []string{"alert", "webhook", "remediate"},
			Run: func() {
				_ = os.WriteFile(preloadPath, []byte("/tmp/evil.so\n"), 0o644)
			},
		},
		{
			ID:    "B5",
			Title: "mprotect-RWX → alert + webhook + quarantine pid",
			Expect: []string{"alert", "webhook", "stop"},
			Run: func() {
				_ = exec.Command("/tmp/mprotect-test").Run()
			},
		},
		{
			ID:    "B6",
			Title: "Process spawn → attributed to alice's session",
			Expect: []string{"session"},
			Run: func() {
				// Spawn a child; harness's pid is in tracker.byPID
				// so the child should attribute to alice's session.
				exec.Command("/usr/bin/ls", "/tmp").Run()
			},
		},
		{
			ID:    "B7",
			Title: "Outbound to known-bad IP (synthetic event, intel match)",
			Expect: []string{"alert", "webhook", "ban"},
			Run: func() {
				// outbound_to_known_bad rule needs bad_ip_match=true
				// — synthesise the post-intel-lookup event.
				ev := model.NewEvent("ebpf.net", model.SeverityCritical)
				ev.Tags["outbound"] = "true"
				ev.Tags["bad_ip_match"] = "true"
				ev.Tags["dst_ip"] = "203.0.113.99"
				ev.Tags["src_ip"] = "203.0.113.99"
				ev.Tags["src"] = "203.0.113.99"
				events <- ev
			},
		},
	}

	type result struct {
		ID, Title string
		Got       map[string]bool
		Want      []string
		Status    string // PASS | PARTIAL | FAIL
	}
	var results []result

	// Recompile binary for B5 if missing
	if _, err := os.Stat("/tmp/mprotect-test"); err != nil {
		_ = os.WriteFile("/tmp/mprotect-test.c", []byte(`
#include <sys/mman.h>
#include <unistd.h>
int main() {
    void *p = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    mprotect(p, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);
    return 0;
}`), 0o644)
		_ = exec.Command("gcc", "/tmp/mprotect-test.c", "-o", "/tmp/mprotect-test").Run()
	}

	for _, a := range attacks {
		fmt.Printf("\n--- %s: %s ---\n", a.ID, a.Title)
		// Cursors before
		rec.mu.Lock()
		alertsBefore := len(rec.alerts)
		stoppedBefore := len(rec.stoppedPIDs)
		webhookBefore := len(rec.webhookHits)
		bansBefore := xdp.snapshot()
		rec.mu.Unlock()
		rec.mu.Lock()
		remBefore := len(rec.remediated)
		rec.mu.Unlock()

		a.Run()
		time.Sleep(2500 * time.Millisecond) // FIM verify cycle is 1.5s

		rec.mu.Lock()
		newAlerts := rec.alerts[alertsBefore:]
		newStopped := len(rec.stoppedPIDs) - stoppedBefore
		newWebhook := len(rec.webhookHits) - webhookBefore
		newRem := len(rec.remediated) - remBefore
		rec.mu.Unlock()
		newBans := len(xdp.snapshot()) - len(bansBefore)

		got := map[string]bool{}
		if len(newAlerts) > 0 {
			got["alert"] = true
		}
		if newWebhook > 0 {
			got["webhook"] = true
		}
		if newStopped > 0 {
			got["stop"] = true
		}
		if newBans > 0 {
			got["ban"] = true
		}
		if newRem > 0 {
			got["remediate"] = true
		}

		// session attribution check
		if a.ID == "B6" {
			ss := tracker.List()
			for _, s := range ss {
				snap := s.Snapshot()
				if len(snap.Events) > 0 || len(snap.Commands) > 0 {
					got["session"] = true
					break
				}
			}
		}

		matched := 0
		for _, w := range a.Expect {
			if got[w] {
				matched++
			}
		}
		status := "FAIL"
		switch {
		case matched == len(a.Expect):
			status = "PASS"
		case matched > 0:
			status = "PARTIAL"
		}
		results = append(results, result{
			ID: a.ID, Title: a.Title, Got: got, Want: a.Expect, Status: status,
		})
		fmt.Printf("  alerts+%d webhooks+%d stops+%d bans+%d remediate+%d\n",
			len(newAlerts), newWebhook, newStopped, newBans, newRem)
	}

	// =================================================================
	fmt.Println("\n========== ACTIVE-RESPONSE SCORECARD ==========")
	fmt.Printf("%-4s %-58s %-10s %-30s\n", "ID", "Attack", "Status", "Got")
	fmt.Println(strings.Repeat("-", 110))
	pass, partial, fail := 0, 0, 0
	for _, r := range results {
		got := []string{}
		for k, v := range r.Got {
			if v {
				got = append(got, k)
			}
		}
		fmt.Printf("%-4s %-58s %-10s %s\n",
			r.ID, r.Title, r.Status, strings.Join(got, ","))
		switch r.Status {
		case "PASS":
			pass++
		case "PARTIAL":
			partial++
		default:
			fail++
		}
	}
	fmt.Printf("\nSummary: %d PASS / %d PARTIAL / %d FAIL\n", pass, partial, fail)

	// =================================================================
	fmt.Println("\n========== TRACE / WHO IS DOING WHAT ==========")
	for _, s := range tracker.List() {
		snap := s.Snapshot()
		fmt.Printf("\nSession %s\n", snap.Session.ID)
		fmt.Printf("  user=%s src=%s method=%s active=%v\n",
			snap.Session.User, snap.Session.SrcIP,
			snap.Session.Method, snap.Session.Active)
		fmt.Printf("  events=%d commands=%d alerts=%d\n",
			len(snap.Events), len(snap.Commands), len(snap.Alerts))
		for i, c := range snap.Commands {
			if i >= 5 {
				fmt.Printf("    ... and %d more\n", len(snap.Commands)-5)
				break
			}
			if len(c) > 80 {
				c = c[:80] + "..."
			}
			fmt.Printf("    cmd: %s\n", c)
		}
	}

	// =================================================================
	fmt.Println("\n========== ACTIVE BANS ==========")
	for _, ip := range xdp.snapshot() {
		fmt.Printf("  %s\n", ip)
	}
	fmt.Println("\n========== REMEDIATED FILES ==========")
	rec.mu.Lock()
	for p := range rec.remediated {
		fmt.Printf("  %s\n", p)
	}
	rec.mu.Unlock()
	fmt.Printf("\nWebhook deliveries: %d\n", webhookCount.Load())

	cancel()
	time.Sleep(300 * time.Millisecond)
}

// remediateProxy wraps the real remediator so we can record what was
// restored without changing the engine API.
type remediateProxy struct {
	real *remediate.Remediator
	rec  *captured
}

func (r *remediateProxy) Restore(path, reason string) error {
	if err := r.real.Restore(path, reason); err != nil {
		return err
	}
	r.rec.mu.Lock()
	r.rec.remediated[path] = true
	r.rec.mu.Unlock()
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
}
