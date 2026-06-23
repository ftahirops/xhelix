# SP-1b.2b.2 — Live-Validation of the Egress Refresh Wiring (Runbook + gated test)

> **Validation, not a feature.** Output is a go/no-go on enabling
> `hardening.egress_refresh_enforce` on a real host. It ships ONE artifact —
> a committed, CI-skipped, root-gated integration test — and a runbook to
> run it on the dev box against a throwaway unit.

**Goal:** Prove the *wiring* of SP-1b.2b.2 end-to-end on a real systemd unit: the production `egressrefresh.Refresher` + `liveEgressApplier`, driven with a scripted resolver, must (1) NOT lock out a unit on a cold-start resolve failure, (2) write the `51-` drop-in and have systemd's effective `IPAddressAllow` reflect the resolved IPs after `daemon-reload`, (3) track an FQDN **rotation** through the grace window (old IP retained for `grace`, then dropped; new IP added immediately), all with the unit's MainPID unchanged (no restart).

**What this adds over the earlier spike:** the spike (`…spike-RESULTS.md`) proved the *mechanism* (drop-in rewrite + `daemon-reload` updates a running cgroup's filter live, incl. shrink). This proves the *Go code path* — resolve → `Tracker.WithinGrace` → `liveEgressApplier.Apply`/`Commit` → file + reload → systemd effective config — has no integration gap. Kernel enforcement itself is already spike-proven, so this asserts at the **systemd-effective-config** layer (`systemctl show -p IPAddressAllow`), which is deterministic and parse-clean.

## ⚠️ Safety
- **Dev box ONLY** (`135.181.79.27`). **Never prod** (`65.108.246.67`).
- **Throwaway unit ONLY** — `xhelix-egress-validate.service`, a `sleep infinity` the test creates and destroys (`t.Cleanup`). Never `xhelix.service`, `sshd`, redis-server, or any real service.
- The test is **gated**: it `t.Skip`s unless `XHELIX_LIVE_VALIDATE=1`, and fails fast if not root. In CI / normal `make test` it is a skip — zero effect.
- Running it is a **hard stop** (writes `/etc/systemd/system/`, runs `systemctl`). Only on an explicit "run the validation" in the current turn.

---

## Deliverable: `cmd/xhelix/egress_live_validate_test.go` (committed, gated)

```go
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
// AND running as root on a dev box.
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
	// 50- floor: localhost/link-local always allowed + deny-any. The dynamic
	// 51- file (written by the applier under test) carries the FQDN IPs.
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
```

**Why each assertion matters:**
- Tick 1 = the **cold-start lockout** guard, proven live (not just unit-tested).
- Tick 2 = the resolve→applier→drop-in→`daemon-reload`→systemd-effective wiring.
- Tick 3 = the **grace window** holds the rotated-out IP so in-flight connections survive.
- Tick 4 = the IP is **shrunk** out of the running unit after grace — the make-or-break.
- MainPID stable across all = no restart, the whole point.

---

## Run it (hard-stop — dev box only, explicit authorization)

```bash
cd /home/rctop/xhelix
sudo XHELIX_LIVE_VALIDATE=1 go test -count=1 -run TestLiveEgressValidation -v ./cmd/xhelix/
```

(`go test` builds the binary itself; running as root lets it write the throwaway unit + run `systemctl`. The test self-cleans via `t.Cleanup`.)

**If it crashes/leaves residue, manual cleanup:**
```bash
sudo systemctl stop xhelix-egress-validate.service 2>/dev/null
sudo rm -rf /etc/systemd/system/xhelix-egress-validate.service.d /etc/systemd/system/xhelix-egress-validate.service
sudo systemctl daemon-reload; sudo systemctl reset-failed xhelix-egress-validate.service 2>/dev/null
```

---

## Decision

- **PASS (all four ticks green, MainPID stable):** the live wiring is sound. `hardening.egress_refresh_enforce` is safe to enable on a *vetted* single-app host — after the operator has reviewed that host's shadow `51-` allow-sets (the LogApplier logs them) and confirmed every legitimate destination is covered. Keep the rollout staged: enable on one host, watch for blocked-egress alerts, then widen.
- **FAIL (any tick):** do NOT enable enforce anywhere. Record which tick failed:
  - Tick 1 fail (lockout file written) → the empty-set guard regressed → fix before anything.
  - Tick 2/3/4 fail but `systemctl show` is correct → an enforcement/kernel gap on this host (re-check cgroup v2 / systemd version vs the spike's findings).
  - MainPID changed → something triggered a restart (a drop-in field that requires restart slipped in) → investigate the rendered drop-in.

Record the result in `…spike-RESULTS.md` or a `…live-validation-RESULTS.md`.

## Notes
- The test is `//go:build linux` + env-gated, so it never runs in CI or `make test` (skips). It is committed so it can be re-run on every new host class before that host is promoted to enforce.
- It does NOT depend on the running `xhelix.service`, the app registry, or the arm/web flow — it wires the components directly. A fuller end-to-end (declare an app with `EgressLive`, arm it through `xhelixctl`, run a second xhelix instance with the enforce knob) is a heavier optional follow-on; this slice validates the genuinely-new code path with minimal surface.
```
