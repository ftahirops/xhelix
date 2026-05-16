// Test harness: wires xhelix's core sensors + rule engine the way
// the daemon does, runs a battery of attack simulations, prints
// honest pass/fail per attack.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/correlator"
	"github.com/xhelix/xhelix/pkg/enforce"
	"github.com/xhelix/xhelix/pkg/hub"
	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/proctree"
	"github.com/xhelix/xhelix/pkg/rules"
	"github.com/xhelix/xhelix/sensors/decoy"
	xhebpf "github.com/xhelix/xhelix/sensors/ebpf"
	fimsensor "github.com/xhelix/xhelix/sensors/fim"
	"github.com/xhelix/xhelix/sensors/memory"
	"github.com/xhelix/xhelix/sensors/netids"
)

type record struct {
	mu          sync.Mutex
	events      []model.Event
	alerts      []model.Alert
	rulesFired  map[string]int
	sensorEvts  map[string]int
	netByDst    map[string]int
	procByComm  map[string]int
}

func newRecord() *record {
	return &record{
		rulesFired: map[string]int{},
		sensorEvts: map[string]int{},
		netByDst:   map[string]int{},
		procByComm: map[string]int{},
	}
}
func (r *record) onEvent(ev model.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	r.sensorEvts[ev.Sensor]++
	if ev.Sensor == "ebpf.proc" {
		r.procByComm[ev.Comm]++
	}
	if ev.Sensor == "ebpf.net" {
		r.netByDst[ev.Tags["dst_ip"]]++
	}
}
func (r *record) onAlert(a model.Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
	r.rulesFired[a.RuleID]++
}

// snapshotSince returns alerts/events fired since (or matching) the
// given checkpoint. Used to score per-test detection.
func (r *record) snapshotSince(start int) (newEvents []model.Event, newAlerts []model.Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if start < len(r.events) {
		newEvents = append([]model.Event{}, r.events[start:]...)
	}
	if start < len(r.alerts) {
		newAlerts = append([]model.Alert{}, r.alerts[start:]...)
	}
	return
}
func (r *record) cursor() (eC, aC int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events), len(r.alerts)
}

func main() {
	rec := newRecord()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Rule engine
	eng, err := rules.NewEngine(rec.onAlert)
	must(err)
	rls, err := rules.LoadDir("/home/rctop/xhelix/ruleset/core")
	must(err)
	must(eng.Load(rls))
	fmt.Printf("[harness] loaded %d rules\n", len(rls))

	// 2. Correlator (host-level) with ssh-brute rule loaded
	corr, err := correlator.New(rec.onAlert)
	must(err)
	sshBrute := correlator.Rule{
		ID:          "ssh_brute_then_success",
		Desc:        "ssh brute force followed by success",
		SeverityRaw: "critical",
		Window:      10 * time.Minute,
		GroupBy:     []string{"src_ip"},
		Steps: []correlator.Step{
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "failure"`,
				Within: 10 * time.Minute},
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "success" && event.tags["src_ip"] == group.src_ip`,
				Within: time.Minute},
		},
	}
	must(corr.Load([]correlator.Rule{sshBrute}))

	// 3. Process tree (ancestry for rules)
	procTree := proctree.New(0)
	eng.SetTreeFn(procTree.Ancestors)

	// 4. Soak (used to track rule firings)
	soak := enforce.NewSoak(30)

	// 5. Event channel
	events := make(chan model.Event, 4096)

	// 6. eBPF backend
	ebpfSensor := xhebpf.New(xhebpf.Config{
		RingbufSizeMB: 1,
		SelfPID:       uint32(os.Getpid()),
	})
	if err := ebpfSensor.Start(ctx, events); err != nil {
		fmt.Printf("[harness] ebpf start: %v\n", err)
	} else {
		fmt.Println("[harness] eBPF backend started")
	}
	defer ebpfSensor.Stop(context.Background())

	// 7. FIM
	fimDir, _ := os.MkdirTemp("", "harness-fim")
	defer os.RemoveAll(fimDir)
	watchedEtc := filepath.Join(fimDir, "etc")
	os.MkdirAll(watchedEtc, 0o755)
	os.WriteFile(filepath.Join(watchedEtc, "passwd"), []byte("root:x:0:0:root:/root:/bin/bash\n"), 0o644)
	os.WriteFile(filepath.Join(watchedEtc, "ld.so.preload"), []byte(""), 0o644)
	fimS := fimsensor.NewSensor(filepath.Join(fimDir, "fim.db"), []string{watchedEtc}, "test-host", 2*time.Second)
	must(fimS.Start(ctx, events))
	fmt.Println("[harness] FIM sensor started (2s verify interval)")
	defer fimS.Stop(context.Background())

	// 8. Decoys
	decoyDir, _ := os.MkdirTemp("", "harness-decoy")
	defer os.RemoveAll(decoyDir)
	honeyFile := filepath.Join(decoyDir, "credentials.txt")
	df := decoy.NewFilesSensor([]decoy.HoneyFile{
		{Path: honeyFile, Persona: "passwd-list"},
	}, "test-host")
	must(df.Start(ctx, events))
	fmt.Printf("[harness] honey file: %s\n", honeyFile)
	defer df.Stop(context.Background())

	ds := decoy.NewServicesSensor([]decoy.HoneyService{
		{Persona: "redis", Bind: "127.0.0.1:0"},
	}, "test-host")
	must(ds.Start(ctx, events))
	addrs := ds.Addrs()
	fmt.Printf("[harness] honey redis: %v\n", addrs)
	defer ds.Stop(context.Background())

	cr := decoy.NewCanaryReceiver("127.0.0.1:0", "test-host",
		[]decoy.Token{{ID: "tok_test_xyz", Type: "passwd-list", Persona: "passwd-list"}})
	must(cr.Start(ctx, events))
	fmt.Printf("[harness] canary receiver: http://%s/<token>\n", cr.Addr())
	defer cr.Stop(context.Background())

	// 9. Memory dmesg
	mw := memory.NewDmesgWatcher("/dev/kmsg", "test-host")
	if err := mw.Start(ctx, events); err == nil {
		fmt.Println("[harness] dmesg watcher started")
		defer mw.Stop(context.Background())
	}

	// 10. Hub for multi-host correlation (in-process)
	hubServer, err := hub.NewServer("127.0.0.1:0", rec.onAlert)
	must(err)
	mhRule := correlator.Rule{
		ID:          "fleet_lateral_move",
		Desc:        "ssh on host-a then exec on host-b same src_ip within 60s",
		SeverityRaw: "critical",
		Window:      time.Minute,
		GroupBy:     []string{"src_ip"},
		Steps: []correlator.Step{
			{Select: `event.sensor == "identity.sshd" && event.tags["outcome"] == "success"`, Within: time.Minute},
			{Select: `event.sensor == "ebpf.proc" && event.tags["src_ip"] == group.src_ip`, Within: time.Minute},
		},
	}
	must(hubServer.LoadCorrelations([]correlator.Rule{mhRule}))

	// 11. Dispatcher: route events to all consumers
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-events:
				rec.onEvent(ev)
				if ev.Tags["dns_qname"] != "" {
					if score := netids.DGAScore(ev.Tags["dns_qname"]); score > 0.7 {
						rec.onAlert(model.Alert{
							Event:  ev,
							RuleID: "netids.dga",
							Reason: fmt.Sprintf("DGA score %.2f for %s", score, ev.Tags["dns_qname"]),
						})
					}
				}
				if ev.Sensor == "ebpf.proc" || ev.Sensor == "ebpf.spawn" {
					procTree.OnSpawn(proctree.Node{
						PID: ev.PID, PPID: ev.ParentPID,
						Comm: ev.Comm, Image: ev.Image, UID: ev.UID,
					})
				}
				eng.Eval(ctx, ev)
				corr.Ingest(ctx, ev)
				if ev.Severity >= model.SeverityCritical && ev.Rule != "" {
					soak.Track(ev.Rule, ev.Time)
				}
			}
		}
	}()

	fmt.Println("[harness] settling 1s...")
	time.Sleep(1 * time.Second)

	// =================================================================
	fmt.Println("\n========== ATTACK SIMULATIONS ==========")

	type attack struct {
		ID    string
		Title string
		Want  []string // alert rule IDs we hope to see
		Run   func()
	}

	attacks := []attack{
		{
			ID: "A1", Title: "reverse-shell pattern (bash + socket)",
			Want: []string{"shell_with_socket_fd"},
			Run: func() {
				// nc -l listener stays up; bash dups socket to fd 0/1
				// and runs *sleep 2* so /proc/pid/fd is alive when the
				// userspace decoder looks it up.
				exec.Command("bash", "-c", `
(nc -l -p 65503 -W1 -w3 < /dev/zero > /dev/null 2>&1 &) ; sleep 0.3
exec 3<>/dev/tcp/127.0.0.1/65503 2>/dev/null && bash -c 'sleep 1.5' <&3 >&3 2>&3
pkill -f 'nc -l -p 65503' 2>/dev/null
true`).Run()
				time.Sleep(200 * time.Millisecond)
			},
		},
		{
			ID: "A2", Title: "binary runs from /tmp",
			Want: []string{"binary_runs_from_tmp"},
			Run: func() {
				bin := "/tmp/xh-attack-" + fmt.Sprint(time.Now().UnixNano())
				exec.Command("cp", "/bin/echo", bin).Run()
				exec.Command("chmod", "+x", bin).Run()
				exec.Command(bin, "compromised").Run()
				os.Remove(bin)
			},
		},
		{
			ID: "A3", Title: "memfd payload (fileless)",
			Want: []string{"memfd_run_pattern"},
			Run: func() {
				exec.Command("python3", "-c", `
import ctypes, os
libc = ctypes.CDLL("libc.so.6")
fd = libc.memfd_create(b"xh-memfd", 0)
with open("/bin/true","rb") as f: os.write(fd, f.read())
try: os.execv("/proc/self/fd/%d" % fd, ["fileless"])
except: pass
`).Run()
			},
		},
		{
			ID: "A4", Title: "/etc/passwd write (FIM drift)",
			Want: []string{"fim.drift"},
			Run: func() {
				// Touch the harness-watched passwd. FIM's verify will
				// catch the SHA mismatch on the next 2s tick.
				p := filepath.Join(watchedEtc, "passwd")
				os.WriteFile(p, []byte("root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/root:/bin/sh\n"), 0o644)
			},
		},
		{
			ID: "A5", Title: "ld.so.preload modified (rootkit pattern)",
			Want: []string{"fim.drift"},
			Run: func() {
				// Same FIM-watched path; modify and rely on verify.
				p := filepath.Join(watchedEtc, "ld.so.preload")
				os.WriteFile(p, []byte("/tmp/evil.so\n"), 0o644)
			},
		},
		{
			ID: "A6", Title: "honey file open (decoy)",
			Want: []string{"decoy_file_opened"},
			Run: func() {
				os.ReadFile(honeyFile)
			},
		},
		{
			ID: "A7", Title: "honey service connect (decoy)",
			Want: []string{"decoy_service_connect"},
			Run: func() {
				if len(addrs) > 0 {
					c, err := net.DialTimeout("tcp", addrs[0], 500*time.Millisecond)
					if err == nil {
						c.Write([]byte("PING\r\n"))
						buf := make([]byte, 64)
						c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
						c.Read(buf)
						c.Close()
					}
				}
			},
		},
		{
			ID: "A8", Title: "canary token used (HTTP)",
			Want: []string{"decoy_canary_token_used"},
			Run: func() {
				exec.Command("curl", "-s", "-m1", "http://"+cr.Addr()+"/tok_test_xyz/use").Run()
			},
		},
		{
			ID: "A9", Title: "outbound HTTPS connect to public IP",
			Want: nil, // captures via ebpf.net only — no rule for benign outbound by default
			Run: func() {
				exec.Command("curl", "-s", "-m2", "https://1.1.1.1/").Run()
			},
		},
		{
			ID: "A10", Title: "cloud metadata IP probe",
			Want: []string{"metadata_svc_unexpected"},
			Run: func() {
				exec.Command("curl", "-s", "-m1", "http://169.254.169.254/latest/meta-data/").Run()
			},
		},
		{
			ID: "A11", Title: "mprotect-RWX shellcode page",
			Want: []string{"mem_mprotect_rwx", "mprotect_rwx", "shell_with_socket_fd"},
			Run: func() {
				exec.Command("python3", "-c", `
import ctypes, mmap
libc = ctypes.CDLL("libc.so.6")
buf = mmap.mmap(-1, 4096, mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS, mmap.PROT_READ|mmap.PROT_WRITE)
addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
libc.mprotect(ctypes.c_void_p(addr), 4096, 7)  # RWX
`).Run()
			},
		},
		{
			ID: "A12", Title: "ptrace_attach (debugger pattern)",
			Want: []string{"any_ptrace"},
			Run: func() {
				// strace triggers PTRACE_ATTACH on the target. Works
				// even with yama ptrace_scope=1 because the tracee
				// is a direct child of strace.
				exec.Command("strace", "-e", "trace=write",
					"-o", "/dev/null", "/bin/true").Run()
			},
		},
		{
			ID: "A13", Title: "kernel module load attempt",
			Want: []string{"kernel_module_load"},
			Run: func() {
				exec.Command("modprobe", "dummy").Run()
				exec.Command("rmmod", "dummy").Run()
			},
		},
		{
			ID: "A14", Title: "DGA-looking DNS qname (synthetic)",
			Want: []string{"netids.dga"},
			Run: func() {
				ev := model.NewEvent("netids", model.SeverityNotice)
				ev.Tags["event_type"] = "dns"
				ev.Tags["dns_qname"] = "asdfqwerzxcv1234567.evil.io"
				events <- ev
			},
		},
		{
			ID: "A15", Title: "SSH brute-force then success (correlation)",
			Want: []string{"fleet_lateral_move", "ssh_brute_then_success"},
			Run: func() {
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
			},
		},
		{
			ID: "A16", Title: "self-defence: bpf() syscall by other process",
			Want: []string{"bpf_syscall_unexpected"},
			Run: func() {
				exec.Command("bpftool", "prog", "list").Run()
			},
		},
	}

	type result struct {
		ID, Title  string
		EventDelta int
		AlertDelta int
		AlertsHit  []string
		Want       []string
		Status     string // PASS | PARTIAL | FAIL
	}
	results := []result{}

	for _, a := range attacks {
		fmt.Printf("\n--- %s: %s ---\n", a.ID, a.Title)
		eC, aC := rec.cursor()
		a.Run()
		time.Sleep(800 * time.Millisecond)
		newEv, newAl := rec.snapshotSince(eC)
		_, newAl2 := rec.snapshotSince(aC)
		_ = newAl
		ruleHit := map[string]bool{}
		hits := []string{}
		for _, x := range newAl2 {
			if !ruleHit[x.RuleID] {
				hits = append(hits, x.RuleID)
				ruleHit[x.RuleID] = true
			}
		}
		status := "FAIL"
		if a.Want == nil {
			status = "OBSERVE"
			if len(newEv) > 0 {
				status = "OBSERVED"
			}
		} else {
			matched := 0
			for _, w := range a.Want {
				if ruleHit[w] {
					matched++
				}
			}
			switch {
			case matched == len(a.Want):
				status = "PASS"
			case matched > 0:
				status = "PARTIAL"
			case len(hits) > 0:
				status = "OTHER-RULE"
			}
		}
		results = append(results, result{
			ID: a.ID, Title: a.Title,
			EventDelta: len(newEv), AlertDelta: len(newAl2),
			AlertsHit: hits, Want: a.Want, Status: status,
		})
		fmt.Printf("  events=%d alerts=%d hits=%v\n", len(newEv), len(newAl2), hits)
	}

	// Final FIM cycle to ensure 2s+ verify catches the writes
	fmt.Println("\n[harness] waiting 4s for final FIM verify cycle...")
	time.Sleep(4 * time.Second)

	// Re-score the FIM tests after the verify pass
	for i := range results {
		if results[i].ID == "A4" || results[i].ID == "A5" {
			rec.mu.Lock()
			ruleHit := map[string]bool{}
			for _, x := range rec.alerts {
				ruleHit[x.RuleID] = true
			}
			rec.mu.Unlock()
			for _, w := range results[i].Want {
				if ruleHit[w] {
					results[i].Status = "PASS"
					results[i].AlertsHit = append(results[i].AlertsHit, w)
				}
			}
		}
	}

	fmt.Println("\n========== RESULTS ==========")
	rec.mu.Lock()
	fmt.Printf("Total events: %d\n", len(rec.events))
	fmt.Printf("Total alerts: %d\n", len(rec.alerts))
	fmt.Println("\nEvents by sensor:")
	for s, c := range rec.sensorEvts {
		fmt.Printf("  %-20s %d\n", s, c)
	}
	fmt.Println("\nNet events by dst_ip:")
	for ip, c := range rec.netByDst {
		fmt.Printf("  %-20s %d\n", ip, c)
	}
	rec.mu.Unlock()

	fmt.Println("\n========== PER-ATTACK SCORECARD ==========")
	pass, partial, fail, observed := 0, 0, 0, 0
	fmt.Printf("%-4s %-50s %-12s %s\n", "ID", "Attack", "Status", "Hits")
	fmt.Println(strings.Repeat("-", 100))
	for _, r := range results {
		hits := strings.Join(r.AlertsHit, ",")
		if hits == "" {
			hits = "-"
		}
		fmt.Printf("%-4s %-50s %-12s %s\n", r.ID, r.Title, r.Status, hits)
		switch r.Status {
		case "PASS":
			pass++
		case "PARTIAL", "OTHER-RULE":
			partial++
		case "OBSERVED", "OBSERVE":
			observed++
		default:
			fail++
		}
	}
	fmt.Printf("\nSummary: %d PASS / %d PARTIAL / %d FAIL / %d OBSERVED-ONLY (no rule expected)\n",
		pass, partial, fail, observed)

	// Dump raw alerts for inspection
	fmt.Println("\n========== RAW ALERT FEED (first 25) ==========")
	rec.mu.Lock()
	for i, a := range rec.alerts {
		if i >= 25 {
			fmt.Printf("  ... and %d more\n", len(rec.alerts)-25)
			break
		}
		j, _ := json.Marshal(a.Event.Tags)
		fmt.Printf("  [%2d] rule=%-30s sev=%-9s comm=%-12s tags=%s\n",
			i, a.RuleID, a.Event.Severity.String(), a.Event.Comm, string(j))
	}
	rec.mu.Unlock()

	cancel()
	time.Sleep(300 * time.Millisecond)
}

func must(err error) {
	if err != nil {
		fmt.Printf("FATAL: %v\n", err)
		os.Exit(1)
	}
}
