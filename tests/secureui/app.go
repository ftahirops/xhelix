package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/xhelix/xhelix/ui/web"
)

type app struct {
	web      *web.Server
	tracker  *session.Tracker
	xdp      *fakeXDP
	banner   *netban.Banner
	rem      *remediate.Remediator
	stats    *appStats
	rules    *rulesAdapter
	events   chan model.Event
	honeyAdd []string
	honeyFile string
	watchedEtc string
}

type fakeXDP struct {
	mu   sync.Mutex
	bans map[string]bool
}

func (f *fakeXDP) Add(ip net.IP) error {
	f.mu.Lock(); defer f.mu.Unlock()
	if f.bans == nil { f.bans = map[string]bool{} }
	f.bans[ip.String()] = true
	return nil
}
func (f *fakeXDP) Remove(ip net.IP) error {
	f.mu.Lock(); defer f.mu.Unlock()
	delete(f.bans, ip.String())
	return nil
}
func (f *fakeXDP) List() ([]net.IP, error) {
	f.mu.Lock(); defer f.mu.Unlock()
	out := make([]net.IP, 0, len(f.bans))
	for s := range f.bans { out = append(out, net.ParseIP(s)) }
	return out, nil
}
func (f *fakeXDP) snapshot() []string {
	f.mu.Lock(); defer f.mu.Unlock()
	out := make([]string, 0, len(f.bans))
	for s := range f.bans { out = append(out, s) }
	return out
}

type appStats struct {
	startedAt time.Time
	events, alerts, crit, high atomic.Uint64
	remediated, webhooks atomic.Uint64
	bansFn, sessFn func() int
}

func (s *appStats) Stats() web.DashboardStats {
	return web.DashboardStats{
		EventsTotal: s.events.Load(),
		AlertsTotal: s.alerts.Load(),
		AlertsCritical: s.crit.Load(),
		AlertsHigh: s.high.Load(),
		SessionsActive: s.sessFn(),
		BansActive: s.bansFn(),
		RemediatedTotal: s.remediated.Load(),
		WebhookDelivered: s.webhooks.Load(),
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
		SensorsHealthy: 6,
	}
}

type sessionAdapter struct{ t *session.Tracker }
func (s *sessionAdapter) List() []web.SessionView {
	out := []web.SessionView{}
	for _, sess := range s.t.List() {
		snap := sess.Snapshot()
		out = append(out, web.SessionView{
			ID: snap.Session.ID, User: snap.Session.User,
			SrcIP: snap.Session.SrcIP, Method: snap.Session.Method,
			LoginAt: snap.Session.LoginAt, LogoutAt: snap.Session.LogoutAt,
			Active: snap.Session.Active, Commands: snap.Commands,
			Events: len(snap.Events), Alerts: len(snap.Alerts),
		})
	}
	return out
}

type bansAdapter struct{ xdp *fakeXDP }
func (b *bansAdapter) ListBans() []web.BanView {
	out := []web.BanView{}
	for _, ip := range b.xdp.snapshot() {
		out = append(out, web.BanView{
			IP: ip, Reason: "auto-banned",
			AddedAt: time.Now(), Expires: time.Now().Add(time.Hour),
		})
	}
	return out
}

type rulesAdapter struct {
	mu    sync.Mutex
	rules []model.Rule
	soak  *enforce.Soak
	stats map[string]uint64
}
func (r *rulesAdapter) ListRules() []web.RuleView {
	r.mu.Lock()
	stats := map[string]uint64{}
	for k, v := range r.stats { stats[k] = v }
	r.mu.Unlock()
	out := []web.RuleView{}
	for _, rl := range r.rules {
		out = append(out, web.RuleView{
			ID: rl.ID, Severity: rl.Severity.String(),
			Mode: rl.Mode.String(), FireCount: stats[rl.ID],
			Description: rl.Desc,
		})
	}
	return out
}
func (r *rulesAdapter) bump(id string) {
	r.mu.Lock()
	if r.stats == nil { r.stats = map[string]uint64{} }
	r.stats[id]++
	r.mu.Unlock()
}

func buildApp(ctx context.Context) *app {
	work, _ := os.MkdirTemp("", "xh-secureui")
	watchedEtc := filepath.Join(work, "etc")
	os.MkdirAll(watchedEtc, 0o755)
	os.WriteFile(filepath.Join(watchedEtc, "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644)
	os.WriteFile(filepath.Join(watchedEtc, "ld.so.preload"), []byte(""), 0o644)

	xdp := &fakeXDP{}
	banner := netban.NewBanner(xdp, false)

	rem, _ := remediate.New(filepath.Join(work, "backup"), filepath.Join(work, "quar"))
	rem.Backup(filepath.Join(watchedEtc, "passwd"))
	rem.Backup(filepath.Join(watchedEtc, "ld.so.preload"))

	tracker := session.New(0)
	soak := enforce.NewSoak(30)
	pSwitch := enforce.NewPanicSwitch(filepath.Join(work, "panic"))
	q := enforce.NewQuarantine(func(pid int, sig os.Signal) error { return nil })

	stats := &appStats{startedAt: time.Now().UTC()}
	stats.sessFn = func() int { return len(tracker.List()) }
	stats.bansFn = func() int { return len(xdp.snapshot()) }

	webSink := alert.NewWebhookSink("", "secureui-host")

	respEng := response.New(response.Config{
		NetBanner: banner,
		Remediator: &remProxy{real: rem, cb: func() { stats.remediated.Add(1) }},
		Quarantine: q,
		PanicSwitch: pSwitch,
		Webhook: func(c context.Context, a model.Alert) error {
			stats.webhooks.Add(1)
			return webSink.Send(c, a)
		},
	})

	rls, _ := rules.LoadDir("/home/rctop/xhelix/ruleset/core")
	rAd := &rulesAdapter{rules: rls, soak: soak}

	emit := func(a model.Alert) {
		stats.alerts.Add(1)
		switch a.Event.Severity {
		case model.SeverityCritical: stats.crit.Add(1)
		case model.SeverityHigh:    stats.high.Add(1)
		}
		rAd.bump(a.RuleID)
		tracker.IngestAlert(a)
		respEng.OnAlert(a)
	}

	eng, _ := rules.NewEngine(emit)
	eng.Load(rls)
	procTree := proctree.New(0)
	eng.SetTreeFn(procTree.Ancestors)

	corr, _ := correlator.New(emit)
	corr.Load([]correlator.Rule{{
		ID: "ssh_brute_then_success", SeverityRaw: "critical",
		Window: 10*time.Minute, GroupBy: []string{"src_ip"},
		Steps: []correlator.Step{
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "failure"`, Within: 10*time.Minute},
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "success" && event.tags["src_ip"] == group.src_ip`, Within: time.Minute},
		},
	}})

	events := make(chan model.Event, 4096)
	ebpfS := xhebpf.New(xhebpf.Config{RingbufSizeMB: 1, SelfPID: uint32(os.Getpid())})
	_ = ebpfS.Start(ctx, events)

	fimDB := filepath.Join(work, "fim.db")
	fimS := fimsensor.NewSensor(fimDB, []string{watchedEtc}, "secureui-host", 1500*time.Millisecond)
	_ = fimS.Start(ctx, events)

	honeyFile := filepath.Join(work, "credentials.txt")
	dF := decoy.NewFilesSensor([]decoy.HoneyFile{
		{Path: honeyFile, Persona: "passwd-list"},
	}, "secureui-host")
	_ = dF.Start(ctx, events)

	dS := decoy.NewServicesSensor([]decoy.HoneyService{
		{Persona: "redis", Bind: "127.0.0.1:0"},
	}, "secureui-host")
	_ = dS.Start(ctx, events)

	go func() {
		for {
			select {
			case <-ctx.Done(): return
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

	srv := web.NewServer(web.Config{Addr: "0.0.0.0:18443"})

	a := &app{
		web: srv, tracker: tracker, xdp: xdp, banner: banner,
		rem: rem, stats: stats, rules: rAd,
		events: events, honeyAdd: dS.Addrs(),
		honeyFile: honeyFile, watchedEtc: watchedEtc,
	}
	return a
}

func (a *app) attachUI(mux *http.ServeMux) {
	a.web.EnterprisePages(web.EnterpriseConfig{
		SessionLister: &sessionAdapter{t: a.tracker},
		BansLister:    &bansAdapter{xdp: a.xdp},
		RuleLister:    a.rules,
		StatsProvider: a.stats,
	}, mux)
}

func populate(ctx context.Context, a *app) {
	time.Sleep(500 * time.Millisecond)

	loginEv := model.NewEvent("identity.sshd", model.SeverityInfo)
	loginEv.Tags["outcome"] = "success"
	loginEv.Tags["user"] = "alice"
	loginEv.Tags["src_ip"] = "198.51.100.5"
	loginEv.Tags["method"] = "publickey"
	loginEv.PID = uint32(os.Getpid())
	loginEv.Time = time.Now()
	a.tracker.Ingest(loginEv)

	os.ReadFile(a.honeyFile)
	if len(a.honeyAdd) > 0 {
		ev := model.NewEvent("decoy", model.SeverityCritical)
		ev.Tags["honey_service_connect"] = "true"
		ev.Tags["persona"] = "redis"
		ev.Tags["src"] = "203.0.113.10:54321"
		a.events <- ev
	}
	os.WriteFile(filepath.Join(a.watchedEtc, "passwd"),
		[]byte("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh\n"),
		0o644)

	tmpBin := "/tmp/xh-secureui-attacker"
	exec.Command("cp", "/bin/echo", tmpBin).Run()
	exec.Command("chmod", "+x", tmpBin).Run()
	exec.Command(tmpBin, "x").Run()
	os.Remove(tmpBin)
}

type remProxy struct {
	real *remediate.Remediator
	cb   func()
}
func (r *remProxy) Restore(path, reason string) error {
	if err := r.real.Restore(path, reason); err != nil { return err }
	r.cb()
	return nil
}
