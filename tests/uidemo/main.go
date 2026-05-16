// UI demo: wires the full active-response stack + enterprise UI,
// runs a few attacks to populate it, and serves on :18888.
//
// Use:  ./uidemo (binds 127.0.0.1:18888) then visit /ui in browser.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
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
	"github.com/xhelix/xhelix/ui/web"
)

// fakeXDP — same in-memory netban target as the active-response harness.
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

// adapters — bridge harness types into the UI's required interfaces.

type sessionAdapter struct{ t *session.Tracker }

func (s *sessionAdapter) List() []web.SessionView {
	out := []web.SessionView{}
	for _, sess := range s.t.List() {
		snap := sess.Snapshot()
		out = append(out, web.SessionView{
			ID: snap.Session.ID, User: snap.Session.User,
			SrcIP: snap.Session.SrcIP, Method: snap.Session.Method,
			LoginAt: snap.Session.LoginAt, LogoutAt: snap.Session.LogoutAt,
			Active: snap.Session.Active,
			Commands: snap.Commands,
			Events: len(snap.Events), Alerts: len(snap.Alerts),
		})
	}
	return out
}

type bansAdapter struct {
	xdp  *fakeXDP
	bans *netban.Banner
}

func (b *bansAdapter) ListBans() []web.BanView {
	out := []web.BanView{}
	for _, ip := range b.xdp.snapshot() {
		out = append(out, web.BanView{
			IP: ip, Reason: "auto-banned by xhelix",
			AddedAt: time.Now(),
			Expires: time.Now().Add(time.Hour),
		})
	}
	return out
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

type ruleAdapter struct {
	rules []model.Rule
	soak  *enforce.Soak
	stats map[string]uint64 // rule_id → fire count
	mu    sync.Mutex
}

func (r *ruleAdapter) ListRules() []web.RuleView {
	r.mu.Lock()
	stats := make(map[string]uint64, len(r.stats))
	for k, v := range r.stats {
		stats[k] = v
	}
	r.mu.Unlock()
	out := []web.RuleView{}
	now := time.Now()
	for _, rl := range r.rules {
		fp, soakRec := uint64(0), (*enforce.Record)(nil)
		clean := uint(0)
		promotable := false
		if r.soak != nil {
			ok, rec := r.soak.Promotable(rl.ID, now)
			if rec != nil {
				soakRec = rec
				fp = rec.FPCount
				clean = rec.ConsecutiveCleanDays
			}
			promotable = ok
		}
		_ = soakRec
		out = append(out, web.RuleView{
			ID: rl.ID, Severity: rl.Severity.String(),
			Mode: rl.Mode.String(), FireCount: stats[rl.ID],
			FPCount: fp, ConsecutiveCleanDays: clean,
			Promotable: promotable, Description: rl.Desc,
		})
	}
	return out
}

func (r *ruleAdapter) bump(id string) {
	r.mu.Lock()
	if r.stats == nil {
		r.stats = map[string]uint64{}
	}
	r.stats[id]++
	r.mu.Unlock()
}

type statsAdapter struct {
	events, alerts, crit, high atomic.Uint64
	sessionsActive             func() int
	bansActive                 func() int
	remediated                 atomic.Uint64
	webhooks                   atomic.Uint64
	startedAt                  time.Time
	fpMarked                   atomic.Uint64
}

func (s *statsAdapter) Stats() web.DashboardStats {
	return web.DashboardStats{
		EventsTotal:      s.events.Load(),
		AlertsTotal:      s.alerts.Load(),
		AlertsCritical:   s.crit.Load(),
		AlertsHigh:       s.high.Load(),
		SensorsHealthy:   6,
		SensorsDegraded:  0,
		SessionsActive:   s.sessionsActive(),
		BansActive:       s.bansActive(),
		RemediatedTotal:  s.remediated.Load(),
		WebhookDelivered: s.webhooks.Load(),
		UptimeSeconds:    int64(time.Since(s.startedAt).Seconds()),
		FPMarkedTotal:    s.fpMarked.Load(),
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// — workspace —
	work, _ := os.MkdirTemp("", "xh-uidemo")
	defer os.RemoveAll(work)
	watchedEtc := filepath.Join(work, "etc")
	os.MkdirAll(watchedEtc, 0o755)
	os.WriteFile(filepath.Join(watchedEtc, "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644)
	os.WriteFile(filepath.Join(watchedEtc, "ld.so.preload"), []byte(""), 0o644)

	// — netban —
	xdp := &fakeXDP{}
	banner := netban.NewBanner(xdp, false)

	// — remediator —
	rem, _ := remediate.New(filepath.Join(work, "backup"), filepath.Join(work, "quar"))
	rem.Backup(filepath.Join(watchedEtc, "passwd"))
	rem.Backup(filepath.Join(watchedEtc, "ld.so.preload"))

	// — session, soak, panic, quarantine —
	tracker := session.New(0)
	soak := enforce.NewSoak(30)
	pSwitch := enforce.NewPanicSwitch(filepath.Join(work, "panic"))
	q := enforce.NewQuarantine(func(pid int, sig os.Signal) error {
		// Don't actually SIGSTOP — we want the demo to keep running.
		return nil
	})

	// — stats adapter wired first so other components can update it —
	stats := &statsAdapter{startedAt: time.Now().UTC()}

	// — webhook receiver mock for the dashboard's webhook count —
	webhookSink := alert.NewWebhookSink("", "uidemo-host") // empty URL → no-op send

	// — response engine —
	respEng := response.New(response.Config{
		NetBanner: banner,
		Remediator: &remediateProxy{
			real: rem,
			cb:   func() { stats.remediated.Add(1) },
		},
		Quarantine:  q,
		PanicSwitch: pSwitch,
		Webhook: func(c context.Context, a model.Alert) error {
			stats.webhooks.Add(1)
			_ = webhookSink.Send(c, a) // no-op when URL empty
			return nil
		},
	})

	// — load rules —
	rls, err := rules.LoadDir("/home/rctop/xhelix/ruleset/core")
	must(err)

	rAdapter := &ruleAdapter{rules: rls, soak: soak}
	bAdapter := &bansAdapter{xdp: xdp, bans: banner}
	sAdapter := &sessionAdapter{t: tracker}
	stats.sessionsActive = func() int { return len(sAdapter.List()) }
	stats.bansActive = func() int { return len(bAdapter.ListBans()) }

	// emit fans an alert through bus + tracker + response + stats.
	emit := func(a model.Alert) {
		stats.alerts.Add(1)
		switch a.Event.Severity {
		case model.SeverityCritical:
			stats.crit.Add(1)
		case model.SeverityHigh:
			stats.high.Add(1)
		}
		rAdapter.bump(a.RuleID)
		tracker.IngestAlert(a)
		respEng.OnAlert(a)
		// publish to UI live stream
		webSrv.EmitToUI(a)
	}

	eng, err := rules.NewEngine(emit)
	must(err)
	must(eng.Load(rls))

	procTree := proctree.New(0)
	eng.SetTreeFn(procTree.Ancestors)

	corr, _ := correlator.New(emit)
	must(corr.Load([]correlator.Rule{{
		ID:          "ssh_brute_then_success",
		Desc:        "ssh brute then success",
		SeverityRaw: "critical",
		Window:      10 * time.Minute,
		GroupBy:     []string{"src_ip"},
		Steps: []correlator.Step{
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "failure"`,
				Within: 10 * time.Minute},
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "success" && event.tags["src_ip"] == group.src_ip`,
				Within: time.Minute},
		},
	}}))

	// — sensors —
	events := make(chan model.Event, 4096)
	ebpfS := xhebpf.New(xhebpf.Config{RingbufSizeMB: 1, SelfPID: uint32(os.Getpid())})
	must(ebpfS.Start(ctx, events))
	defer ebpfS.Stop(context.Background())

	fimDB := filepath.Join(work, "fim.db")
	fimS := fimsensor.NewSensor(fimDB, []string{watchedEtc}, "uidemo-host", 1500*time.Millisecond)
	must(fimS.Start(ctx, events))
	defer fimS.Stop(context.Background())

	honeyFile := filepath.Join(work, "credentials.txt")
	dF := decoy.NewFilesSensor([]decoy.HoneyFile{
		{Path: honeyFile, Persona: "passwd-list"},
	}, "uidemo-host")
	must(dF.Start(ctx, events))
	defer dF.Stop(context.Background())

	dS := decoy.NewServicesSensor([]decoy.HoneyService{
		{Persona: "redis", Bind: "127.0.0.1:0"},
	}, "uidemo-host")
	must(dS.Start(ctx, events))
	defer dS.Stop(context.Background())
	dsAddrs := dS.Addrs()

	// — dispatcher —
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				stats.events.Add(1)
				tracker.Ingest(ev)
				if ev.Sensor == "ebpf.proc" {
					procTree.OnSpawn(proctree.Node{
						PID: ev.PID, PPID: ev.ParentPID,
						Comm: ev.Comm, UID: ev.UID,
					})
				}
				eng.Eval(ctx, ev)
				corr.Ingest(ctx, ev)
			}
		}
	}()

	// — UI server —
	webSrv = web.NewServer(web.Config{
		Addr: "127.0.0.1:18888",
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})
	webSrv.EnterprisePages(web.EnterpriseConfig{
		SessionLister: sAdapter,
		BansLister:    bAdapter,
		RuleLister:    rAdapter,
		StatsProvider: stats,
	}, mux)
	go func() {
		fmt.Println("[uidemo] http://127.0.0.1:18888/ui")
		_ = http.ListenAndServe("127.0.0.1:18888", mux)
	}()

	time.Sleep(800 * time.Millisecond)

	// — synthetic activity to populate the dashboard —
	fmt.Println("[uidemo] populating with attack data...")

	// SSH login → opens session
	loginEv := model.NewEvent("identity.sshd", model.SeverityInfo)
	loginEv.Tags["outcome"] = "success"
	loginEv.Tags["user"] = "alice"
	loginEv.Tags["src_ip"] = "198.51.100.5"
	loginEv.Tags["method"] = "publickey"
	loginEv.PID = uint32(os.Getpid())
	loginEv.Time = time.Now()
	tracker.Ingest(loginEv)

	// Honey file open
	os.ReadFile(honeyFile)
	time.Sleep(300 * time.Millisecond)

	// Decoy service connect from synthetic public IP
	if len(dsAddrs) > 0 {
		c, _ := net.DialTimeout("tcp", dsAddrs[0], 500*time.Millisecond)
		if c != nil {
			c.Close()
		}
		ev := model.NewEvent("decoy", model.SeverityCritical)
		ev.Tags["honey_service_connect"] = "true"
		ev.Tags["persona"] = "redis"
		ev.Tags["src"] = "203.0.113.10:54321"
		events <- ev
	}

	// Tamper passwd → expect remediate
	os.WriteFile(filepath.Join(watchedEtc, "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh\n"),
		0o644)
	os.WriteFile(filepath.Join(watchedEtc, "ld.so.preload"),
		[]byte("/tmp/evil.so\n"), 0o644)

	// /tmp binary execution
	tmpBin := filepath.Join("/tmp", "uidemo-attacker")
	exec.Command("cp", "/bin/echo", tmpBin).Run()
	exec.Command("chmod", "+x", tmpBin).Run()
	exec.Command(tmpBin, "compromised").Run()
	os.Remove(tmpBin)

	// Outbound to known-bad
	ev := model.NewEvent("ebpf.net", model.SeverityCritical)
	ev.Tags["outbound"] = "true"
	ev.Tags["bad_ip_match"] = "true"
	ev.Tags["dst_ip"] = "203.0.113.99"
	ev.Tags["src_ip"] = "203.0.113.99"
	ev.Tags["src"] = "203.0.113.99"
	events <- ev

	// Cloud metadata probe
	exec.Command("curl", "-s", "-m1", "http://169.254.169.254/").Run()

	// Synth ssh brute attempts
	now := time.Now()
	for i := 0; i < 51; i++ {
		ev := model.NewEvent("identity.sshd", model.SeverityWarn)
		ev.Tags["outcome"] = "failure"
		ev.Tags["user"] = "root"
		ev.Tags["src_ip"] = "192.0.2.99"
		ev.Time = now.Add(time.Duration(i) * time.Second)
		events <- ev
	}
	ok := model.NewEvent("identity.sshd", model.SeverityInfo)
	ok.Tags["outcome"] = "success"
	ok.Tags["user"] = "root"
	ok.Tags["src_ip"] = "192.0.2.99"
	ok.Time = now.Add(60 * time.Second)
	events <- ok

	time.Sleep(3 * time.Second)
	fmt.Printf("[uidemo] populated. Open http://127.0.0.1:18888/ui in a browser.\n")
	fmt.Printf("[uidemo] press Ctrl-C to stop.\n")

	<-ctx.Done()
}

var webSrv *web.Server

type remediateProxy struct {
	real *remediate.Remediator
	cb   func()
}

func (r *remediateProxy) Restore(path, reason string) error {
	if err := r.real.Restore(path, reason); err != nil {
		return err
	}
	r.cb()
	return nil
}

func must(err error) {
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
}
