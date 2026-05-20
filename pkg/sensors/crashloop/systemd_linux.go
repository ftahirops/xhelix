//go:build linux

package crashloop

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SystemdPoller polls `systemctl show <unit> --property=...` at a
// configurable interval and emits a CrashEvent whenever NRestarts
// increments or a unit transitions ActiveState=activating with
// Result≠success (catches crashes during startup too).
//
// Polling rather than D-Bus subscription keeps the dependency
// surface tiny: just exec systemctl, no godbus. systemctl is on
// every systemd host. Cost: ~1ms per service per poll.
type SystemdPoller struct {
	// Units to poll. Each entry is one unit name (e.g. "nginx.service")
	// + the protectedsvc Name + lineage_id that should be attached
	// to emitted CrashEvents.
	Units []UnitWatch

	// Interval between polls. Default 5s.
	Interval time.Duration

	// Wire receives CrashEvents. Required.
	Wire *Wire

	// SystemctlPath overrides the systemctl binary location. Default
	// "/usr/bin/systemctl" → falls back to PATH lookup if absent.
	SystemctlPath string

	mu      sync.Mutex
	state   map[string]*unitState // by UnitName
	stopped bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// UnitWatch ties a systemd unit name to the protectedsvc identity.
type UnitWatch struct {
	UnitName    string
	ServiceName string
	LineageID   uint64
}

type unitState struct {
	lastNRestarts uint32
	lastInvID     string
}

// Start begins polling. Returns nil immediately; the goroutine
// runs until Stop().
func (p *SystemdPoller) Start(ctx context.Context) error {
	if p.Wire == nil {
		return fmt.Errorf("crashloop: SystemdPoller needs a Wire")
	}
	if p.Interval <= 0 {
		p.Interval = 5 * time.Second
	}
	if p.SystemctlPath == "" {
		p.SystemctlPath = systemctlBinary()
	}
	if p.state == nil {
		p.state = map[string]*unitState{}
	}

	ctx, cancel := context.WithCancel(ctx)
	p.mu.Lock()
	p.cancel = cancel
	p.stopped = false
	p.mu.Unlock()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(p.Interval)
		defer t.Stop()
		// First poll immediately to seed lastNRestarts.
		p.pollAll()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.pollAll()
			}
		}
	}()
	return nil
}

// Stop halts the poller and waits for the goroutine.
func (p *SystemdPoller) Stop() {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	if p.cancel != nil {
		p.cancel()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

func (p *SystemdPoller) pollAll() {
	for _, u := range p.Units {
		st, err := queryUnit(p.SystemctlPath, u.UnitName)
		if err != nil {
			continue // unit not loaded or systemctl error — try next tick
		}
		p.process(u, st)
	}
}

// process compares the current systemctl status against the
// previous poll and emits a CrashEvent for each new restart or
// failed activation.
func (p *SystemdPoller) process(u UnitWatch, st systemctlStatus) {
	p.mu.Lock()
	prev, ok := p.state[u.UnitName]
	if !ok {
		prev = &unitState{}
		p.state[u.UnitName] = prev
	}
	p.mu.Unlock()

	// Detect crash via NRestarts delta. systemd increments NRestarts
	// every time it re-starts a unit after non-clean exit.
	if st.NRestarts > prev.lastNRestarts {
		delta := int(st.NRestarts - prev.lastNRestarts)
		for i := 0; i < delta; i++ {
			ev := CrashEvent{
				At:          time.Now().UTC(),
				ServiceName: u.ServiceName,
				UnitName:    u.UnitName,
				PID:         st.MainPID,
				LineageID:   u.LineageID,
				ExitCode:    st.ExecMainStatus,
				Source:      "systemd",
			}
			if st.Result == "signal" && st.ExecMainStatus != 0 {
				ev.Signal = signalNumberToName(st.ExecMainStatus)
			}
			_ = p.Wire.Handle(ev)
		}
	}

	// Detect "InvocationID changed AND Result == failed" — catches
	// the case where systemd has Restart=no (or hit StartLimitBurst)
	// and NRestarts didn't increment but the unit DID fail.
	if st.InvocationID != prev.lastInvID && prev.lastInvID != "" &&
		st.Result != "success" && st.Result != "" {
		ev := CrashEvent{
			At:          time.Now().UTC(),
			ServiceName: u.ServiceName,
			UnitName:    u.UnitName,
			LineageID:   u.LineageID,
			ExitCode:    st.ExecMainStatus,
			Source:      "systemd",
			Signal:      st.Result, // "core-dump", "signal", "exit-code", ...
		}
		_ = p.Wire.Handle(ev)
	}

	prev.lastNRestarts = st.NRestarts
	prev.lastInvID = st.InvocationID
}

// systemctlStatus is the subset of `systemctl show` properties we
// care about for crash detection.
type systemctlStatus struct {
	ActiveState     string
	SubState        string
	Result          string // "success", "signal", "exit-code", "core-dump", "watchdog"
	NRestarts       uint32
	MainPID         uint32
	ExecMainStatus  int
	InvocationID    string
}

func queryUnit(systemctlPath, unit string) (systemctlStatus, error) {
	out, err := exec.Command(systemctlPath, "show", unit,
		"--property=ActiveState,SubState,Result,NRestarts,MainPID,ExecMainStatus,InvocationID",
	).Output()
	if err != nil {
		return systemctlStatus{}, err
	}
	return parseSystemctlShow(string(out)), nil
}

func parseSystemctlShow(s string) systemctlStatus {
	var st systemctlStatus
	for _, line := range strings.Split(s, "\n") {
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		key, val := line[:i], line[i+1:]
		switch key {
		case "ActiveState":
			st.ActiveState = val
		case "SubState":
			st.SubState = val
		case "Result":
			st.Result = val
		case "NRestarts":
			if n, err := strconv.ParseUint(val, 10, 32); err == nil {
				st.NRestarts = uint32(n)
			}
		case "MainPID":
			if n, err := strconv.ParseUint(val, 10, 32); err == nil {
				st.MainPID = uint32(n)
			}
		case "ExecMainStatus":
			if n, err := strconv.Atoi(val); err == nil {
				st.ExecMainStatus = n
			}
		case "InvocationID":
			st.InvocationID = val
		}
	}
	return st
}

// signalNumberToName maps the most common termination signals.
// systemd reports the signal number in ExecMainStatus when
// Result=signal.
func signalNumberToName(n int) string {
	switch n {
	case 1:
		return "SIGHUP"
	case 2:
		return "SIGINT"
	case 3:
		return "SIGQUIT"
	case 4:
		return "SIGILL"
	case 6:
		return "SIGABRT"
	case 7:
		return "SIGBUS"
	case 8:
		return "SIGFPE"
	case 9:
		return "SIGKILL"
	case 11:
		return "SIGSEGV"
	case 13:
		return "SIGPIPE"
	case 14:
		return "SIGALRM"
	case 15:
		return "SIGTERM"
	}
	return fmt.Sprintf("SIG_%d", n)
}

func systemctlBinary() string {
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl", "/usr/sbin/systemctl"} {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("systemctl"); err == nil {
		return p
	}
	return "/usr/bin/systemctl"
}

// SystemctlHalter returns a Halter that runs `systemctl stop` +
// `systemctl mask` on the unit when a crash loop fires. Halts in
// the background so it doesn't block the dispatch path; failures
// surface via the OnHaltError callback.
func SystemctlHalter(systemctlPath string) Halter {
	if systemctlPath == "" {
		systemctlPath = systemctlBinary()
	}
	return HalterFunc(func(svc, unit string, _ *Decision) error {
		if unit == "" {
			return fmt.Errorf("crashloop: halt %s: empty unit", svc)
		}
		// stop first — clean shutdown attempt.
		if out, err := exec.Command(systemctlPath, "stop", unit).CombinedOutput(); err != nil {
			return fmt.Errorf("crashloop: systemctl stop %s: %w (%s)", unit, err, strings.TrimSpace(string(out)))
		}
		// mask — refuse subsequent start attempts until operator unmasks.
		if out, err := exec.Command(systemctlPath, "mask", unit).CombinedOutput(); err != nil {
			return fmt.Errorf("crashloop: systemctl mask %s: %w (%s)", unit, err, strings.TrimSpace(string(out)))
		}
		return nil
	})
}
