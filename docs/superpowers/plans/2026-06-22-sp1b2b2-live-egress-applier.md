# SP-1b.2b.2 — Live Egress Applier (drop-in rewrite + daemon-reload) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Promote the SP-1b.2b.1 shadow re-resolver from logging to **actually enforcing** a live, grace-windowed FQDN egress allowlist on a running unit — using the mechanism the spike proved works (**rewrite a dynamic drop-in + `systemctl daemon-reload`**, which updates a running unit's `IPAddressAllow` cgroup filter live, including *shrink*, with no restart). Opt-in per service, **config-gated and default-off**.

**Architecture (decided by `docs/superpowers/plans/2026-06-22-sp1b2b2-spike-RESULTS.md`):**
A live-mode service splits its egress across two drop-ins so the refresher can shrink freely (systemd *combines* `IPAddressAllow` lists across drop-ins, so the dynamic IPs must live in a file the refresher solely owns):
- **`50-…` (arm-time, contractarm):** the **floor only** — `IPAddressAllow=localhost link-local` + `IPAddressDeny=any`. No dynamic IPs.
- **`51-xhelix-egress-dynamic.conf` (refresher-owned):** `IPAddressAllow=<static CIDRs + within-grace resolved FQDN IPs>`. No deny, no localhost (those are in the floor). The refresher rewrites this file and `daemon-reload`s once per tick.

Combine → `localhost + link-local + dynamic-allows + deny-any`. Removing an IP from `51-` + reload removes it from the running filter (proven by the spike) because it appears in no other drop-in. `set-property` is **not** used (the spike found it rejects `localhost`/`link-local` tokens and its reset wipes the combined list).

**Tech Stack:** Go 1.23 (CI on 1.22), `CGO_ENABLED=0`, std `testing`. Builds on `pkg/egressrefresh` (SP-1b.2b.1), `pkg/contractarm` (`Armorer.Runner`, `SystemdDir`, `EgressDirectives`), `pkg/appregistry`, `pkg/contractcompiler`.

## Global Constraints

- `CGO_ENABLED=0`; statically linked. Module path `github.com/xhelix/xhelix`; avoid Go 1.23-only stdlib (CI 1.22).
- Tests use std `testing` only; **zero** real systemd/DNS — the applier's systemd interaction goes through an injected `Runner func(args ...string) error` and a temp `SystemdDir`; resolution stays behind the `egressresolve.Resolver` interface.
- Full gate: `make vet && make test`; `make static-check`.
- **FP-safety (this slice can sever a service's network — treat as the write-zone class):**
  - **Config-gated, default-off.** Live enforcement only runs when an operator sets the promotion knob AND a service sets `EgressLive=true`. With the knob off, behaviour is identical to SP-1b.2b.1 (shadow `LogApplier`).
  - **Empty-set guard (the lock-out path).** The applier MUST NOT write an empty `51-` allow-set (which, combined with the floor's `IPAddressDeny=any`, is a total external lockdown) **unless that unit previously had a non-empty applied set** — i.e. never lock a service out from a cold start where DNS hasn't resolved yet. An all-FQDN-fail first tick is a no-op, not a lockdown.
  - **Never-shrink-on-failure** is already guaranteed by the SP-1b.2b.1 `Tracker` grace window — preserved here.
  - **`Forget` evicts `lastSet`.** When a unit stops being live, clear both the tracker and the refresher's change-detection state, or a re-opt-in skips its first apply.
- **Scope:** this is the systemd live applier + promotion only. nftables-per-cgroup / cgroup-BPF (SP-1b.3) remain unrelated and unneeded for this capability (the spike confirmed systemd suffices on this host).

---

### Task 1: `EgressLive` opt-in flag

**Files:**
- Modify: `pkg/appregistry/appregistry.go` (Service egress block), `pkg/contractcompiler/types.go` (CompiledService egress block), `pkg/contractcompiler/compiler.go` (compileService copy)
- Test: `pkg/appregistry/egress_test.go` + `pkg/contractcompiler/egress_test.go` (extend)

**Interfaces:**
- Produces: `appregistry.Service.EgressLive bool` and `CompiledService.EgressLive bool` (copied verbatim). Semantics: when true (and `EgressDefaultDeny` true), this service's egress is managed *live* by the refresher rather than frozen at arm time.

- [ ] **Step 1: Failing tests** — append to `pkg/appregistry/egress_test.go`:

```go
func TestServiceEgressLiveDefaultsOff(t *testing.T) {
	var s Service
	if s.EgressLive {
		t.Error("EgressLive must default false (opt-in)")
	}
	s.EgressLive = true
	if !s.EgressLive {
		t.Error("EgressLive not settable")
	}
}
```

And append to `pkg/contractcompiler/egress_test.go`:

```go
func TestCompileCarriesEgressLive(t *testing.T) {
	app := appregistry.App{Name: "shop", Services: []appregistry.Service{{
		Name: "nginx", UnitName: "nginx.service", EgressDefaultDeny: true, EgressLive: true,
	}}}
	if !Compile(app, redzones.Default()).Services[0].EgressLive {
		t.Error("EgressLive not carried to CompiledService")
	}
}
```

- [ ] **Step 2: Run — confirm FAIL** (`EgressLive undefined`):
`go test ./pkg/appregistry/ ./pkg/contractcompiler/ -run EgressLive`

- [ ] **Step 3: Implement** — in `pkg/appregistry/appregistry.go`, add after `EgressAllowFQDNs`:

```go
	// EgressLive opts this service's egress into LIVE refresh (SP-1b.2b.2):
	// the egressrefresh loop keeps the systemd IPAddressAllow set current as
	// FQDN IPs rotate, with a grace window. Requires EgressDefaultDeny. When
	// false, egress (if any) is the arm-time snapshot (SP-1b.2a). Live
	// enforcement is additionally gated by the daemon's promotion knob
	// (default off).
	EgressLive bool `json:"egress_live,omitempty"`
```

In `pkg/contractcompiler/types.go` add to the egress block: `EgressLive bool \`json:"egress_live,omitempty"\``. In `compileService` add `EgressLive: svc.EgressLive,` to the `cs` initializer.

- [ ] **Step 4: Run — PASS:** `go test ./pkg/appregistry/ ./pkg/contractcompiler/`
- [ ] **Step 5: Commit:** `feat(egress): EgressLive opt-in flag for live-managed egress`

---

### Task 2: Arm writes the FLOOR only for live-mode services

**Files:**
- Modify: `cmd/xhelix/web_setup.go` (`specsFor`)
- Test: `cmd/xhelix/web_setup_egress_test.go` (extend)

**Interfaces:**
- Consumes: `CompiledService.EgressLive` (Task 1); `contractarm.EgressDirectives` (existing).
- Behaviour: for a service with `EgressDefaultDeny && EgressLive`, `specsFor` sets `EgressDirective = contractarm.EgressDirectives(nil)` — i.e. `IPAddressAllow=localhost link-local` + `IPAddressDeny=any`, the **floor**, with NO static/dynamic IPs (the refresher's `51-` file owns those). The static-mode path (`EgressDefaultDeny && !EgressLive`) is unchanged.

- [ ] **Step 1: Failing test** — append to `cmd/xhelix/web_setup_egress_test.go`:

```go
func TestSpecsForLiveServiceGetsFloorOnly(t *testing.T) {
	cc := &contractcompiler.CompiledContract{App: "shop", Services: []contractcompiler.CompiledService{{
		Unit: "nginx.service", EgressDefaultDeny: true, EgressLive: true,
		EgressAllowCIDRs: []string{"10.0.0.0/8"}, // must NOT appear in the arm drop-in
	}}}
	specs := specsFor(cc)
	d := specs[0].EgressDirective
	if !strings.Contains(d, "IPAddressDeny=any") || !strings.Contains(d, "localhost") {
		t.Fatalf("live service should still get the floor: %q", d)
	}
	if strings.Contains(d, "10.0.0.0/8") {
		t.Errorf("live service arm drop-in must NOT carry dynamic/static IPs (refresher owns them): %q", d)
	}
}
```

(Add `"strings"` to the test imports if not present.)

- [ ] **Step 2: Run — FAIL** (static CIDR currently leaks into the arm directive).

- [ ] **Step 3: Implement** — in `cmd/xhelix/web_setup.go` `specsFor`, replace the egress block:

```go
		// SP-1b.1/2a: arm-time egress. SP-1b.2b.2: for EgressLive services the
		// arm drop-in carries only the FLOOR (localhost/link-local + deny);
		// the egressrefresh loop owns the dynamic allow-set in its own 51-
		// drop-in, so it can shrink it (systemd combines IPAddressAllow lists).
		if cs.EgressDefaultDeny {
			if cs.EgressLive {
				spec.EgressDirective = contractarm.EgressDirectives(nil)
			} else {
				spec.EgressDirective = contractarm.EgressDirectives(cs.EgressAllowCIDRs)
			}
		}
```

- [ ] **Step 4: Run — PASS** (all `cmd/xhelix` egress tests).
- [ ] **Step 5: Commit:** `feat(arm): live-egress services get the floor drop-in only`

---

### Task 3: `Applier.Commit()` — batch one reload per tick

**Files:**
- Modify: `pkg/egressrefresh/refresher.go` (Applier interface, LogApplier, RefreshOnce)
- Test: `pkg/egressrefresh/refresher_test.go` (extend)

**Interfaces:**
- Adds `Commit() error` to `Applier`. `LogApplier.Commit()` is a no-op (returns nil). `RefreshOnce` calls `r.applier.Commit()` once after the per-unit loop. This lets the live applier write N drop-ins then `daemon-reload` once.

- [ ] **Step 1: Failing test** — append to `pkg/egressrefresh/refresher_test.go`:

```go
type commitCounter struct{ applies, commits int }

func (c *commitCounter) Apply(string, []string) error { c.applies++; return nil }
func (c *commitCounter) Commit() error                { c.commits++; return nil }

func TestRefreshCommitsOncePerPass(t *testing.T) {
	src := fakeSource{units: []Unit{
		{Name: "a", StaticCIDRs: []string{"10.0.0.0/8"}},
		{Name: "b", StaticCIDRs: []string{"10.0.0.0/8"}},
	}}
	cc := &commitCounter{}
	New(src, fakeResolver{}, cc, time.Hour).RefreshOnce(context.Background(), t0)
	if cc.applies != 2 || cc.commits != 1 {
		t.Errorf("applies=%d commits=%d; want 2 applies, 1 commit", cc.applies, cc.commits)
	}
}
```

- [ ] **Step 2: Run — FAIL** (`Commit` undefined on Applier; `cc` doesn't satisfy `Applier` yet → actually fails to compile against the interface once Commit is added; first it fails because RefreshOnce doesn't call Commit).

- [ ] **Step 3: Implement** — in `pkg/egressrefresh/refresher.go`:
  - Add to the `Applier` interface: `Commit() error`.
  - Add to `LogApplier`: `func (l LogApplier) Commit() error { return nil }`.
  - In `RefreshOnce`, after the `for _, u := range r.src.Units()` loop closes, add:

```go
	if err := r.applier.Commit(); err != nil {
		slog.Default().Warn("egress refresh commit failed", "err", err)
	}
```

- [ ] **Step 4: Run — PASS** (`go test -race ./pkg/egressrefresh/`; existing tests' inline appliers also need `Commit()` — add a no-op `Commit() error { return nil }` to `recApplier` and `countApplier` in the test file).
- [ ] **Step 5: Commit:** `feat(egressrefresh): Applier.Commit() for batched per-tick reload`

---

### Task 4: The live systemd applier (write `51-` drop-in + reload)

**Files:**
- Create: `cmd/xhelix/egress_live_applier.go`
- Test: `cmd/xhelix/egress_live_applier_test.go`

**Interfaces:**
- Consumes: `egressrefresh.Applier` shape; `contractarm.Armorer` (`Runner func(args ...string) error`, `SystemdDir string`).
- Produces: `liveEgressApplier` implementing `egressrefresh.Applier`:
  - `Apply(unit string, allowCIDRs []string) error` — writes `<SystemdDir>/<unit>.d/51-xhelix-egress-dynamic.conf` containing `[Service]\nIPAddressAllow=<space-joined cidrs>\n` (NO deny, NO localhost — those are in the floor). **Empty-set guard:** if `allowCIDRs` is empty AND this unit has never had a non-empty set applied, skip (do not write a lockout file); record that a write happened so Commit reloads.
  - `Commit() error` — if any unit's file changed this cycle, run `Runner("daemon-reload")` once.
  - A `Forget(unit)` helper that deletes the unit's `51-` file + clears its "had-non-empty" memory (wired to the refresher's Forget in a later step / SP-1b.2b.1 carry-forward; for this task expose the method + test it).

- [ ] **Step 1: Failing test** — `cmd/xhelix/egress_live_applier_test.go`:

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/contractarm"
)

func newTestApplier(t *testing.T) (*liveEgressApplier, *[]string, string) {
	t.Helper()
	dir := t.TempDir()
	var ran []string
	arm := &contractarm.Armorer{SystemdDir: dir, Runner: func(a ...string) error { ran = append(ran, strings.Join(a, " ")); return nil }}
	return newLiveEgressApplier(arm), &ran, dir
}

func TestLiveApplierWritesDropInAndReloadsOnce(t *testing.T) {
	a, ran, dir := newTestApplier(t)
	if err := a.Apply("nginx.service", []string{"1.1.1.1/32", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf"))
	if err != nil {
		t.Fatalf("drop-in not written: %v", err)
	}
	if !strings.Contains(string(b), "IPAddressAllow=1.1.1.1/32 10.0.0.0/8") {
		t.Errorf("bad drop-in content:\n%s", string(b))
	}
	if strings.Contains(string(b), "IPAddressDeny") || strings.Contains(string(b), "localhost") {
		t.Errorf("dynamic file must not carry deny/localhost (floor owns them):\n%s", string(b))
	}
	if len(*ran) != 1 || (*ran)[0] != "daemon-reload" {
		t.Errorf("expected exactly one daemon-reload, got %v", *ran)
	}
}

func TestLiveApplierEmptySetGuardColdStart(t *testing.T) {
	a, ran, dir := newTestApplier(t)
	// First-ever apply with an empty set must NOT write a lockout file.
	if err := a.Apply("nginx.service", nil); err != nil {
		t.Fatal(err)
	}
	a.Commit()
	if _, err := os.Stat(filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf")); !os.IsNotExist(err) {
		t.Error("empty set on cold start must NOT create a lockout drop-in")
	}
	if len(*ran) != 0 {
		t.Errorf("no change -> no reload; got %v", *ran)
	}
}

func TestLiveApplierEmptyAfterNonEmptyIsLockdown(t *testing.T) {
	a, _, dir := newTestApplier(t)
	a.Apply("nginx.service", []string{"1.1.1.1/32"}) // non-empty first
	a.Commit()
	a.Apply("nginx.service", nil) // now empty -> intentional lockdown allowed
	a.Commit()
	b, _ := os.ReadFile(filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf"))
	if !strings.Contains(string(b), "IPAddressAllow=\n") && !strings.HasSuffix(strings.TrimRight(string(b), "\n"), "IPAddressAllow=") {
		t.Errorf("empty set after a non-empty set should write an empty allow (lockdown):\n%s", string(b))
	}
}

func TestLiveApplierForgetRemovesDropIn(t *testing.T) {
	a, _, dir := newTestApplier(t)
	a.Apply("nginx.service", []string{"1.1.1.1/32"}); a.Commit()
	p := filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf")
	if _, err := os.Stat(p); err != nil {
		t.Fatal("setup: drop-in missing")
	}
	a.Forget("nginx.service"); a.Commit()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("Forget should delete the unit's dynamic drop-in")
	}
}
```

- [ ] **Step 2: Run — FAIL** (`newLiveEgressApplier` undefined).

- [ ] **Step 3: Implement** — `cmd/xhelix/egress_live_applier.go`:

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xhelix/xhelix/pkg/contractarm"
)

const liveEgressDropIn = "51-xhelix-egress-dynamic.conf"

// liveEgressApplier implements egressrefresh.Applier (SP-1b.2b.2). It writes
// each live unit's dynamic allow-set to its own 51- drop-in and batches a
// single `systemctl daemon-reload` per Commit. The drop-in carries ONLY the
// IPAddressAllow list; the deny floor + localhost/link-local live in the
// arm-time floor drop-in, so removing an IP here genuinely shrinks the
// running filter (proven by the SP-1b.2b.2 spike). Mechanism: drop-in
// rewrite + daemon-reload (NOT set-property).
type liveEgressApplier struct {
	arm *contractarm.Armorer

	mu        sync.Mutex
	hadNonEmpty map[string]bool // unit -> has ever had a non-empty set applied
	dirty       bool            // a file changed this cycle -> reload on Commit
}

func newLiveEgressApplier(arm *contractarm.Armorer) *liveEgressApplier {
	return &liveEgressApplier{arm: arm, hadNonEmpty: map[string]bool{}}
}

func (a *liveEgressApplier) dropInPath(unit string) string {
	return filepath.Join(a.arm.SystemdDir, unit+".d", liveEgressDropIn)
}

func (a *liveEgressApplier) Apply(unit string, allowCIDRs []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Empty-set guard: a cold-start empty set (no IP has ever resolved) must
	// NOT write a lockout. An empty set AFTER a non-empty one is an
	// intentional lockdown and is honoured.
	if len(allowCIDRs) == 0 && !a.hadNonEmpty[unit] {
		return nil
	}
	dir := filepath.Join(a.arm.SystemdDir, unit+".d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("live egress: mkdir %s: %w", dir, err)
	}
	content := "# Managed by xhelix egressrefresh (SP-1b.2b.2). Do not edit by hand.\n" +
		"[Service]\nIPAddressAllow=" + strings.Join(allowCIDRs, " ") + "\n"
	if err := os.WriteFile(a.dropInPath(unit), []byte(content), 0o644); err != nil {
		return fmt.Errorf("live egress: write %s: %w", a.dropInPath(unit), err)
	}
	if len(allowCIDRs) > 0 {
		a.hadNonEmpty[unit] = true
	}
	a.dirty = true
	return nil
}

// Forget removes a unit's dynamic drop-in and its history (called when a unit
// stops being live). Carry-forward from the SP-1b.2b.1 review.
func (a *liveEgressApplier) Forget(unit string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.Remove(a.dropInPath(unit)); err == nil {
		a.dirty = true
	}
	delete(a.hadNonEmpty, unit)
}

func (a *liveEgressApplier) Commit() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.dirty {
		return nil
	}
	a.dirty = false
	return a.arm.Runner("daemon-reload")
}
```

- [ ] **Step 4: Run — PASS:** `go test -race ./cmd/xhelix/ -run TestLiveApplier`
- [ ] **Step 5: Commit:** `feat(egress): live systemd applier (51- drop-in + daemon-reload, empty-set guarded)`

---

### Task 5: Config-gated promotion shadow → live (CHECKPOINT — daemon change)

**Files:**
- Modify: `pkg/config/config.go` (add the promotion knob), `cmd/xhelix/egress_refresh.go` (UnitSource includes live units + carries `EgressLive`), `cmd/xhelix/run.go` (choose applier by the knob)
- Test: `cmd/xhelix/egress_refresh_test.go` (extend — filter includes EgressLive)

**Interfaces:**
- Adds `cfg.Hardening.EgressRefresh.Enforce bool` (or nearest existing hardening sub-struct) — default **false**. When false, the refresher uses `egressrefresh.LogApplier` (shadow, SP-1b.2b.1 behaviour). When true, it uses `newLiveEgressApplier(foundation.Armorer)`.
- `unitsFromApps` includes a service when `EgressDefaultDeny && len(EgressAllowFQDNs)>0` **OR** `EgressLive` (a live service with only static CIDRs still needs its `51-` file written/maintained).

> **Only this task changes enforcement behaviour, and only when the operator
> sets the knob true.** Knob default-false = unchanged shadow behaviour. Even
> true, only services that set `EgressLive=true` are affected, and the
> empty-set guard prevents cold-start lockout. Stop here for review.

- [ ] **Step 1: Failing test** — extend `unitsFromApps` coverage in `cmd/xhelix/egress_refresh_test.go`:

```go
func TestUnitsFromAppsIncludesLiveStaticOnly(t *testing.T) {
	apps := []appregistry.App{{Name: "shop", Services: []appregistry.Service{
		{UnitName: "live.service", EgressDefaultDeny: true, EgressLive: true, EgressAllowCIDRs: []string{"10.0.0.0/8"}},
	}}}
	u := unitsFromApps(apps)
	if len(u) != 1 || u[0].Name != "live.service" {
		t.Fatalf("a live service (static-only) must be tracked: %+v", u)
	}
}
```

- [ ] **Step 2: Run — FAIL** (current filter requires FQDNs).

- [ ] **Step 3: Implement** — in `cmd/xhelix/egress_refresh.go`, change the filter in `unitsFromApps`:

```go
			if !svc.EgressDefaultDeny {
				continue
			}
			if len(svc.EgressAllowFQDNs) == 0 && !svc.EgressLive {
				continue // static-CIDR-only non-live services need no refresh
			}
```

(keep the rest of the mapping the same.)

In `pkg/config/config.go`, add to the egress/hardening config a `EgressRefreshEnforce bool \`yaml:"egress_refresh_enforce,omitempty"\`` (default false), and pre-declare its key in `predeclaredAuditKeys` + witness it.

In `cmd/xhelix/run.go`, replace the SP-1b.2b.1 spawn block's applier choice:

```go
	if foundation.AppRegistry != nil {
		var applier egressrefresh.Applier = egressrefresh.LogApplier{Log: log}
		if cfg.Hardening.EgressRefreshEnforce && foundation.Armorer != nil {
			applier = newLiveEgressApplier(foundation.Armorer)
			log.Warn("egress refresh ENFORCE mode — live IPAddressAllow updates are ON")
		}
		refresher := egressrefresh.New(
			registryUnitSource{reg: foundation.AppRegistry},
			egressresolve.Default(), applier, 10*time.Minute,
		)
		go refresher.Start(ctx, 5*time.Minute)
	}
```

- [ ] **Step 4: Build + full gate:**
`go build ./cmd/xhelix/ && go vet ./cmd/xhelix/ && make vet && go test -race ./pkg/appregistry/ ./pkg/contractcompiler/ ./pkg/contractarm/ ./pkg/egressrefresh/ ./cmd/xhelix/ && make build && make static-check`
- [ ] **Step 5: Commit:** `feat(egress): config-gated promotion of egress refresh from shadow to live`

---

## Self-Review

- **Spec coverage:** Tasks 1-2 = declaration + floor-split (shrink-capable); Task 3 = batched reload; Task 4 = the Mechanism-B applier with the empty-set guard + Forget; Task 5 = default-off promotion. Matches the spike RESULTS design constraints. ✓
- **Placeholders:** complete code in every step; the two prose edits (config sub-struct name, witness key) name the exact file. ✓ The implementer must confirm the exact `cfg.Hardening` egress sub-struct field path when adding the knob — flagged in Task 5.
- **FP-safety:** default-off (Task 5), empty-set cold-start guard (Task 4 + `TestLiveApplierEmptySetGuardColdStart`), floor/deny separation so shrink works, never-shrink-on-failure inherited from the grace tracker. ✓

## Deferred

- **Wire `Refresher.Forget` → `liveEgressApplier.Forget`** when a unit drops out of the UnitSource between ticks (so its `51-` file is removed). The applier method exists + is tested here; the refresher-side eviction is a small follow-on once opt-out UX exists.
- **Pre-promotion preview** (`xhelixctl`): show each unit's current shadow `51-` set + the destinations the egress ledger says would newly block, before flipping `egress_refresh_enforce` on.
- **SP-1b.2c** — passive DNS-observation pinning + SNI (unchanged deferral).
- **Live-validate on a real unit** once built: the spike proved the mechanism; a post-implementation check should arm a throwaway live service, let the refresher write `51-`, and confirm a real FQDN's rotation is tracked — using the same throwaway-unit discipline as the spike (never a real service).
