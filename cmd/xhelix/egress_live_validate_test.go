//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/contractarm"
	"github.com/xhelix/xhelix/pkg/egressrefresh"
)

// scriptedResolver returns whatever IPs the test currently sets — used to
// simulate an FQDN resolving to A, then rotating to B.
type scriptedResolver struct{ ips []net.IP }

func (s *scriptedResolver) LookupIP(_ context.Context, _ string) ([]net.IP, error) {
	if len(s.ips) == 0 {
		return nil, errors.New("scripted: resolve failure")
	}
	return s.ips, nil
}

type oneUnitSource struct{ u egressrefresh.Unit }

func (o oneUnitSource) Units() []egressrefresh.Unit { return []egressrefresh.Unit{o.u} }

// TestLiveEgressValidation drives the REAL refresher + liveEgressApplier
// against a throwaway systemd unit. Gated: skipped unless XHELIX_LIVE_VALIDATE=1
// AND running as root on a dev box. See
// docs/superpowers/plans/2026-06-23-sp1b2b2-live-validation.md.
func TestLiveEgressValidation(t *testing.T) {
	if os.Getenv("XHELIX_LIVE_VALIDATE") != "1" {
		t.Skip("gated live validation; set XHELIX_LIVE_VALIDATE=1 and run as root on the dev box")
	}
	if os.Geteuid() != 0 {
		t.Fatal("must run as root: writes /etc/systemd/system and runs systemctl")
	}

	const unit = "xhelix-egress-validate.service"
	const sysDir = "/etc/systemd/system"
	sc := func(args ...string) error {
		out, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return errors.New("systemctl " + strings.Join(args, " ") + ": " + err.Error() + " " + string(out))
		}
		return nil
	}

	// --- setup: throwaway base unit + floor drop-in (mirrors the arm path) ---
	if err := os.WriteFile(filepath.Join(sysDir, unit),
		[]byte("[Unit]\nDescription=xhelix egress live-validation (throwaway)\n[Service]\nExecStart=/bin/sleep infinity\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	dropInDir := filepath.Join(sysDir, unit+".d")
	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dropInDir, "50-floor.conf"),
		[]byte("[Service]\nIPAddressAllow=localhost link-local\nIPAddressDeny=any\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sc("daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if err := sc("start", unit); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sc("stop", unit)
		_ = os.RemoveAll(dropInDir)
		_ = os.Remove(filepath.Join(sysDir, unit))
		_ = sc("daemon-reload")
		_ = sc("reset-failed", unit)
	})

	mainPID := func() string {
		out, _ := exec.Command("systemctl", "show", "-p", "MainPID", "--value", unit).Output()
		return strings.TrimSpace(string(out))
	}
	effectiveAllow := func() string {
		out, _ := exec.Command("systemctl", "show", "-p", "IPAddressAllow", "--value", unit).Output()
		return string(out)
	}
	fileHas := func(want string) bool {
		b, _ := os.ReadFile(filepath.Join(dropInDir, "51-xhelix-egress-dynamic.conf"))
		return strings.Contains(string(b), want)
	}
	fileExists := func() bool {
		_, err := os.Stat(filepath.Join(dropInDir, "51-xhelix-egress-dynamic.conf"))
		return err == nil
	}

	pid0 := mainPID()

	// --- wire the REAL production components ---
	arm := &contractarm.Armorer{SystemdDir: sysDir, Runner: sc}
	applier := newLiveEgressApplier(arm)
	res := &scriptedResolver{}
	src := oneUnitSource{u: egressrefresh.Unit{Name: unit, FQDNs: []string{"dyn.validate.local"}}}
	r := egressrefresh.New(src, res, applier, 10*time.Minute)
	ctx := context.Background()
	t0 := time.Now()

	ipA, ipB := "203.0.113.10/32", "203.0.113.20/32"

	// Tick 1 — cold start, resolve FAILS. Must NOT write a lockout file.
	res.ips = nil
	r.RefreshOnce(ctx, t0)
	if fileExists() {
		t.Fatalf("COLD-START LOCKOUT: 51- file written when resolve failed (must be a no-op)")
	}

	// Tick 2 — resolves to A. 51- written; effective allow includes A; no restart.
	res.ips = []net.IP{net.ParseIP("203.0.113.10")}
	r.RefreshOnce(ctx, t0.Add(1*time.Minute))
	if !fileHas("203.0.113.10/32") {
		t.Fatalf("grow: 51- missing %s", ipA)
	}
	if !strings.Contains(effectiveAllow(), "203.0.113.10/32") {
		t.Fatalf("grow: systemd effective IPAddressAllow missing %s; got %q", ipA, effectiveAllow())
	}

	// Tick 3 — FQDN ROTATES to B. Within grace, A retained + B added.
	res.ips = []net.IP{net.ParseIP("203.0.113.20")}
	r.RefreshOnce(ctx, t0.Add(2*time.Minute))
	ea := effectiveAllow()
	if !strings.Contains(ea, "203.0.113.10/32") || !strings.Contains(ea, "203.0.113.20/32") {
		t.Fatalf("rotation/grace: expected BOTH %s and %s within grace; got %q", ipA, ipB, ea)
	}

	// Tick 4 — well past the 10m grace, still resolving to B. A must be gone.
	r.RefreshOnce(ctx, t0.Add(15*time.Minute))
	ea = effectiveAllow()
	if strings.Contains(ea, "203.0.113.10/32") {
		t.Fatalf("shrink: %s should have expired past grace; got %q", ipA, ea)
	}
	if !strings.Contains(ea, "203.0.113.20/32") {
		t.Fatalf("shrink: %s must remain; got %q", ipB, ea)
	}

	if mainPID() != pid0 {
		t.Fatalf("unit RESTARTED during live update (MainPID %s -> %s); must stay live", pid0, mainPID())
	}
	t.Logf("live validation OK: cold-start no-op, grow, rotation+grace, shrink — all live (MainPID %s stable)", pid0)
}
