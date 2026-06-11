# xhelix Behavioral Compiler — Full Implementation Plan

**Document authority:** This is the single source of truth for the behavioral compiler
build. All phases, file paths, dates, and UI deliverables are defined here.

**Start date:** 2026-06-10  
**Target completion:** 2026-12-15 (27 weeks)  
**Branch:** verdict-foundation → merge to main at Phase 4 completion

---

## What This Builds

xhelix today is a detection engine. This plan turns it into a **behavioral compiler
with kernel enforcement** — a system that makes attacks physically impossible rather
than merely detectable, managed entirely through a web UI.

When complete:
- An operator installs xhelix on a VPS
- Opens the web UI, clicks "Add App", selects running services
- xhelix observes for 7 days, then presents a visual contract review
- Operator approves/rejects each learned behavior from the UI
- xhelix compiles the contract into kernel enforcement (seccomp, AppArmor, execguard, cgroup BPF)
- Live dashboard shows real-time activity, denies, health per app
- When a new version deploys, a behavioral diff appears in the UI for approval

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│  DECLARATION PLANE (UI-driven)                              │
│  /apps/new wizard → app contract YAML                       │
│  Learning review → operator approves/rejects per behavior   │
│  /apps/:name/contract → view/edit enforcement policy        │
└──────────────────────────┬──────────────────────────────────┘
                           │ compiles
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  COMPILER  (pkg/contractcompiler)                           │
│  App Contract → seccomp + AppArmor + execguard rules        │
│              + cgroup BPF egress + credbroker + FIM policy  │
└──┬───────────┬────────────┬─────────────┬───────────────────┘
   ▼           ▼            ▼             ▼
seccomp    AppArmor    execguard    cgroup BPF egress
(kernel)   (kernel)    (kernel)     (kernel, pre-SYN)
└──────────────────────────┴─────────────────────────────────┘
                           │ observed by
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  RUNTIME OBSERVATION (eBPF sensors already built)           │
│  Events → pipeline → causal chain tagging                   │
│  → per-app attribution → learning accumulation              │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  CONTRACT HEALTH  (pkg/contracthealth)                      │
│  Deny ledger + circuit breaker + auto-rollback              │
│  → UI: health badges, deny review, re-lock flow             │
└─────────────────────────────────────────────────────────────┘
```

---

## Enforcement Modes (per app)

| Mode | Behavior | Promoted to by |
|---|---|---|
| `observe` | Record only. Zero blocks. | Default on new app declaration |
| `shadow` | Log would-blocks. No actual enforcement. | Operator after observation window |
| `guarded` | Red zones blocked. Drift alerted. | Operator after contract review |
| `locked` | All undeclared behavior blocked. Circuit breaker active. | Operator manually |
| `sealed` | All unsigned drift blocked. No auto-downgrade. Break-glass only. | Operator, critical infra only |

---

## Phase Timeline

| Phase | Name | Start | End | Duration |
|---|---|---|---|---|
| **P1** | Red Zone Hard Blocks | 2026-06-03 | 2026-06-10 | **DONE** |
| **P2** | Maintenance Chains | 2026-06-10 | 2026-07-01 | 3 weeks |
| **P3** | Egress Prevention | 2026-07-01 | 2026-07-22 | 3 weeks |
| **P4** | Contract Health + Circuit Breaker | 2026-07-22 | 2026-08-11 | 3 weeks |
| **P-UI** | App Management + Learning Dashboard | 2026-08-11 | 2026-09-08 | 4 weeks |
| **P5a** | Contract Compiler (service-level) | 2026-09-08 | 2026-10-06 | 4 weeks |
| **P5b** | OTel Integration | 2026-10-06 | 2026-10-27 | 3 weeks |
| **P6** | Causal Chain Engine | 2026-10-27 | 2026-11-24 | 4 weeks |
| **P7** | CI/CD Integration | 2026-11-24 | 2026-12-15 | 3 weeks |

---

## Phase 1 — Red Zone Hard Blocks
**Status: COMPLETE (2026-06-10)**

### What was built
- `pkg/redzones/redzones.go` — Policy type, Default() with 24 exec paths / 14 write zones / 15 syscalls
- `pkg/redzones/redzones_test.go` — 9 tests
- `ruleset/core/redzones.yaml` — 6 CEL rules for file/read red zones
- `cmd/xhelix/run.go` — execguard now loads red zone exec rules at startup

### Protection delivered
- execve of /bin/sh, bash, curl, wget, python*, node, php, perl, nc → kernel DENY
- Write to /etc/sudoers, /root/, /lib/*.so, /etc/systemd/ → alert (CEL)
- Read of /etc/shadow, /root/.ssh/*, /root/.aws/ → alert (CEL)

### What remains for full P1
- Per-cgroup web-worker targeting (currently global — fires for ALL processes)
- Syscall-level blocking via seccomp (DenySyscalls list exists, not yet compiled + applied)

---

## Phase 2 — Maintenance Chains
**Start: 2026-06-10 | End: 2026-07-01**

Maintenance chains make the red zone blocks operationally safe. Without them,
Phase 1 breaks legitimate deploys, package updates, and backups. With them,
those operations get a time-boxed, signed, scoped capability grant.

### Files to create

```
pkg/maintenancechain/
  chain.go          — Grant type, mint, validate, scope checks
  store.go          — SQLite-backed grant store (CRUD + expiry sweep)
  store_test.go     — store tests
  chain_test.go     — mint/validate/scope tests
```

### Files to modify

```
cmd/xhelix/foundation.go       — add MaintenanceChains *maintenancechain.Store
cmd/xhelix/run.go              — check active grants before red-zone blocks in
                                 execguard callback; add sweep goroutine
cmd/xhelix/web_setup.go        — register /maintenance routes
ui/web/maintenance.go          — NEW: handler for /maintenance page + API endpoints
ui/web/templates.go            — add maintenance chain templates
```

### Data model

```go
// Grant is a signed, time-boxed capability grant for a cgroup.
type Grant struct {
    ID          string        // ulid
    AppName     string        // "billing-api"
    CgroupMatch string        // prefix match, e.g. "/system.slice/php-fpm.service"
    Scope       GrantScope    // deploy | update | backup | custom
    AllowExec   []string      // specific exec paths unlocked (empty = none)
    AllowWrite  []string      // specific write paths unlocked (empty = none)
    Reason      string        // human-readable "deploying v1.4.2"
    CreatedBy   string        // operator identity from session
    CreatedAt   time.Time
    ExpiresAt   time.Time
    SignedBy    string        // signing key name ("ops" | "ci-prod")
    Signature   []byte        // Ed25519 over canonical JSON
}

type GrantScope string
const (
    ScopeDeploy  GrantScope = "deploy"   // unlocks shell + write in deploy cgroup
    ScopeUpdate  GrantScope = "update"   // unlocks package manager + network
    ScopeBackup  GrantScope = "backup"   // unlocks read of sensitive paths
    ScopeCustom  GrantScope = "custom"   // operator-defined allow/deny
)
```

### UI: /maintenance page

```
┌─────────────────────────────────────────────────────────┐
│ Maintenance Windows                    [+ New Window]    │
├─────────────────────────────────────────────────────────┤
│ billing-api | deploy | 23:47 remaining | by: admin      │
│   Scope: /system.slice/php-fpm.service                  │
│   Reason: "deploying v1.4.2"                 [Revoke]   │
├─────────────────────────────────────────────────────────┤
│ wordpress   | update | EXPIRED 4m ago | by: ci-prod     │
│   Scope: /system.slice/php-fpm.service                  │
│   Reason: "apt-get upgrade wordpress"                   │
└─────────────────────────────────────────────────────────┘
```

### UI: New maintenance window modal (no YAML)

```
┌─────────────────────────────────────────────────────────┐
│ New Maintenance Window                                   │
│                                                         │
│ App:      [billing-api       ▼]                         │
│ Type:     ( ) Deploy  ( ) Package Update                │
│           ( ) Backup  (●) Custom                        │
│ Duration: [30 minutes ▼]  (15m / 30m / 1h / 4h / 8h)  │
│ Reason:   [deploying v1.4.2            ]                │
│                                                         │
│ Unlocks:  ☑ Shell execution in deploy cgroup            │
│           ☑ Write to /srv/billing-api/**                │
│           ☐ Read sensitive paths                        │
│                                                         │
│              [Cancel]  [Start Window]                   │
└─────────────────────────────────────────────────────────┘
```

### API endpoints

```
POST /api/maintenance/create   — create + sign a new grant
GET  /api/maintenance/list     — list active + recent expired grants
POST /api/maintenance/revoke   — revoke by ID
GET  /api/maintenance/check    — check if a cgroup has an active grant (for pipeline)
```

### Integration: red zone check sequence

```
execguard fires Deny callback
  → check pkg/maintenancechain.Store.ActiveFor(cgroupID)
  → if valid grant covers this exec path: allow + log "maintenance chain bypass"
  → if no grant: enforce Deny, emit alert
```

### Tests required

- Grant mint produces valid Ed25519 signature over canonical JSON
- Grant validates correctly (expiry, scope, cgroup match)
- Grant with wrong signature rejects
- Expired grant rejects
- Store sweep removes expired grants
- Cgroup prefix matching works (partial path matches)

---

## Phase 3 — Egress Prevention
**Start: 2026-07-01 | End: 2026-07-22**

This is the phase where xhelix transitions from detection-only egress to actual
packet-level prevention. A webshell connecting to C2 is blocked before the SYN
leaves the host.

### Files to create

```
pkg/egressguard/cgroupbpf/
  cgroupbpf_linux.go     — cgroup BPF connect hook, policy map per cgroup
  cgroupbpf_stub.go      — //go:build !linux stub
  cgroupbpf_test.go      — unit tests
  policy_map.go          — per-cgroup allow-set: (ip, port) pairs + FQDNs

pkg/egressguard/
  dnstracker.go          — resolves FQDNs in allow-sets, refreshes on DNS events
  dnstracker_test.go
```

### Files to modify

```
pkg/egressguard/nft.go         — extend existing partial nftables code to named
                                 sets per app, installed at contract activation
cmd/xhelix/foundation.go       — add DNSTracker, CgroupBPFGuard fields
cmd/xhelix/run.go              — wire cgroupbpf guard; subscribe DNS events to tracker
cmd/xhelix/web_setup.go        — register /apps/:name/egress routes
ui/web/egress_app.go           — NEW: per-app egress management handler
ui/web/templates.go            — add egress app templates
```

### Enforcement hierarchy (in priority order)

1. **cgroup BPF connect hook** — best: pre-SYN, no packet leaves, kernel space
2. **systemd IPAddressDeny/Allow** — good: in-kernel via cgroup v2, no BPF needed
3. **nftables named sets** — fallback: works on kernels without BPF connect hook

All three are wired; the highest available is used. On modern kernels (≥5.15, which
is the xhelix minimum) cgroup BPF is always available.

### UI: per-app egress management (/apps/:name/egress)

```
┌─────────────────────────────────────────────────────────┐
│ billing-api — Egress Policy           [Mode: locked ▼]  │
├─────────────────────────────────────────────────────────┤
│ Allowed destinations                   [+ Add manually] │
│                                                         │
│  api.stripe.com:443   ●external  34 connects/day  [✕]  │
│  mysql.internal:3306  ●internal  88k connects/day [✕]  │
│  redis.internal:6379  ●internal  4k connects/day  [✕]  │
├─────────────────────────────────────────────────────────┤
│ Shadow mode queue — approve or block                    │
│  8.8.8.8:443          ●raw-ip  2 attempts  [✓ Add] [✗] │
│  ntfy.sh:443          ●messaging  1 attempt [✓ Add] [✗]│
└─────────────────────────────────────────────────────────┘
```

Shadow mode queue: every "would-block" outbound connection appears here in real
time via SSE. Operator clicks Approve (adds to contract) or Block (hardens deny).
No YAML editing required.

### API endpoints

```
GET  /api/apps/:name/egress/policy      — current allow-set
POST /api/apps/:name/egress/approve     — add destination to allow-set
POST /api/apps/:name/egress/deny        — explicitly deny a destination
GET  /api/apps/:name/egress/shadow      — stream would-block events (SSE)
POST /api/apps/:name/egress/mode        — change enforcement mode
```

---

## Phase 4 — Contract Health + Circuit Breaker
**Start: 2026-07-22 | End: 2026-08-11**

Makes P1–P3 production-safe. Without this phase, the first false-positive in
locked mode causes operators to disable xhelix globally. With it, failures are
narrow, recoverable, and leave an audit trail.

### Files to create

```
pkg/contracthealth/
  health.go          — deny ledger, health state machine, circuit breaker logic
  health_test.go     — state machine tests
  ledger.go          — SQLite-backed deny event log
  ledger_test.go
```

### Files to modify

```
cmd/xhelix/foundation.go       — add ContractHealth *contracthealth.Monitor
cmd/xhelix/run.go              — publish deny events to health monitor;
                                 subscribe to mode-change events (locked→guarded)
cmd/xhelix/web_setup.go        — register /apps/:name/health routes
ui/web/health.go               — NEW: health dashboard handler
ui/web/templates.go            — health templates
```

### Circuit breaker logic

```
Per-app deny ledger:
  - Record every block: timestamp, app, cgroup, type (exec/file/egress/syscall), path, reason
  - Rolling 5-minute window counter
  - Red zone violations → NEVER trigger rollback; always page immediately

Circuit breaker thresholds (configurable per app):
  guarded mode:   >50 denies/5min AND >20% are non-red-zone → alert + human review required
  locked mode:    >20 denies/5min AND >5 are non-red-zone → auto-downgrade to guarded + alert
  sealed mode:    ANY non-red-zone deny → alert + human review; NO auto-downgrade

Recovery path (UI-driven):
  Operator reviews deny ledger items one by one
  Per item: "Approve this behavior" (adds to contract) or "Keep blocking"
  After all items reviewed → "Re-lock" button re-promotes to locked
```

### UI: /apps/:name/health

```
┌─────────────────────────────────────────────────────────┐
│ billing-api — Contract Health          ● Healthy        │
├────────────────────────┬────────────────────────────────┤
│ Mode: LOCKED           │ Denies (24h): 0                │
│ Circuit: CLOSED        │ Red-zone violations: 0          │
│ Last review: 3 days ago│ Last mode change: 12 days ago   │
├─────────────────────────────────────────────────────────┤
│ Deny ledger (last 100)                      [Export CSV] │
│                                                         │
│ 2026-06-15 14:23:01 | exec | /bin/sh | pid:4821        │
│   comm: php-fpm  cgroup: /system.slice/php-fpm.service  │
│   verdict: RED ZONE BLOCK  [View lineage]               │
└─────────────────────────────────────────────────────────┘
```

Circuit breaker state shown as badge on every app card on the `/apps` dashboard.

### API endpoints

```
GET  /api/apps/:name/health          — current health state + stats
GET  /api/apps/:name/health/ledger   — paginated deny ledger
POST /api/apps/:name/health/approve  — approve a deny ledger item (adds to contract)
POST /api/apps/:name/health/relock   — re-promote to locked after review
GET  /api/apps/:name/health/stream   — SSE: real-time deny events
```

---

## Phase UI — App Management + Learning Dashboard
**Start: 2026-08-11 | End: 2026-09-08**

The primary operator interface. Everything an operator does to declare, observe,
review, and manage apps happens here. No CLI required for any of this.

### Files to create

```
ui/web/apps.go              — app registry, app detail, mode controls
ui/web/apps_learn.go        — learning review (approve/reject per behavior)
ui/web/apps_live.go         — real-time activity feed handler + SSE
ui/web/apps_wizard.go       — new app declaration wizard (service discovery)
ui/web/static/apps/
  apps.css                  — app management styles
  apps.js                   — app registry + live activity JS
  learn.js                  — contract review interactive JS
  wizard.js                 — service discovery + wizard JS
  charts.js                 — uPlot wrapper for time-series charts (embedded)
```

### Files to modify

```
cmd/xhelix/web_setup.go        — register all /apps/* routes
cmd/xhelix/foundation.go       — add AppRegistry *appregistry.Registry
cmd/xhelix/run.go              — attribute events to apps via cgroup matching
pkg/appregistry/               — NEW: pkg to store declared app stacks
  registry.go                  — CRUD for declared apps + stacks
  registry_test.go
  store.go                     — SQLite backing (apps.db)
ui/web/templates.go            — all new page templates
```

### Page inventory

```
GET  /apps                      — app registry (card grid)
GET  /apps/new                  — wizard: step 1 discover, step 2 configure, step 3 start
GET  /apps/:name                — app detail (mode, health badge, mini-charts)
GET  /apps/:name/live           — real-time activity feed
GET  /apps/:name/learn          — learning review (post-observation)
GET  /apps/:name/contract       — full contract view + edit
GET  /apps/:name/health         — deny ledger + circuit breaker (from P4)
GET  /apps/:name/egress         — egress management (from P3)
GET  /apps/:name/maintenance    — maintenance windows for this app (from P2)
```

### Service discovery (wizard step 1)

xhelix scans running systemd units via `/run/systemd/private/` and `/proc/*/cgroup`,
returns a list of running services with:
- Unit name
- Binary path + SHA
- Running since
- Current cgroup
- Detected service type (nginx/php-fpm/mysql/redis/node/python/custom)

The UI shows these as selectable tiles. Operator clicks the services that form their app.

### App registry API

```
GET    /api/apps                 — list all declared apps with health summary
POST   /api/apps                 — declare new app (from wizard)
GET    /api/apps/:name           — app detail
PATCH  /api/apps/:name/mode      — change enforcement mode
DELETE /api/apps/:name           — remove app declaration
GET    /api/apps/:name/services  — list services in this app's stack
GET    /api/apps/discover        — scan system for running services (for wizard)
```

### Learning review API

```
GET  /api/apps/:name/learn/summary    — overview of what was observed
GET  /api/apps/:name/learn/items      — paginated list of behaviors for review
POST /api/apps/:name/learn/approve    — approve a behavior (adds to contract draft)
POST /api/apps/:name/learn/reject     — reject a behavior
POST /api/apps/:name/learn/generate   — generate contract from approved items
POST /api/apps/:name/learn/activate   — activate generated contract in shadow mode
```

### Live activity API

```
GET  /api/apps/:name/live/stream   — SSE: real-time events for this app
GET  /api/apps/:name/live/stats    — rolling 60s stats (events/s by type)
GET  /api/apps/:name/live/egress   — current active connections with bytes
GET  /api/apps/:name/live/proctree — current process tree snapshot
```

### uPlot chart library

Embed uPlot 1.6.31 (~15KB minified) in `ui/web/static/apps/uplot.min.js`.
Used for: events-per-second timeline, egress bytes timeline, deny rate chart.
Self-hosted — no CDN. License: MIT.

---

## Phase 5a — Contract Compiler (Service-Level)
**Start: 2026-09-08 | End: 2026-10-06**

Ties the declaration plane to kernel enforcement. The existing type vocabulary
(`pkg/protectedsvc/`, `pkg/profiles/contracts/`, `pkg/prevent/seccomp/`,
`pkg/prevent/apparmor/`) provides the foundation. This phase builds the compiler
that wires them all together from a YAML contract file.

### Files to create

```
pkg/contractcompiler/
  compiler.go          — AppContract → CompiledContract
  compiler_test.go
  types.go             — AppContract, CompiledContract, RouteContract structs
  loader.go            — load + validate contract YAML from /etc/xhelix/apps.d/
  loader_test.go

/etc/xhelix/apps.d/    — operator-managed app contracts (created by UI)
```

### Contract file format

```yaml
# /etc/xhelix/apps.d/billing-api.yaml
app: billing-api
version: "1.0"
artifact_sha256: ""   # set by xhelixctl app sign

services:
  - unit: nginx.service
    kind: nginx
    role: reverse_proxy
    contract:
      listen_ports: [80, 443]
      upstream_cidrs: ["127.0.0.1/32"]   # php-fpm socket only
      deny_exec_paths: []                 # inherits NeverLearnableExec

  - unit: php-fpm.service
    kind: php_fpm
    role: fastcgi
    contract:
      write_roots:
        - /var/www/html/wp-content/cache/**
        - /var/www/html/wp-content/uploads/**
        - /tmp/php-*
      upstream_cidrs:
        - "127.0.0.1/32"   # mysql
        - "127.0.0.1/32"   # redis
      upstream_fqdns:
        - api.stripe.com:443
      deny_exec_paths: []   # inherits NeverLearnableExec

egress:
  mode: locked
  default: deny

maintenance_keys:
  - name: ops
    public_key: "base64-ed25519-pub"
  - name: ci-prod
    public_key: "base64-ed25519-pub"
```

### CompiledContract output

```go
type CompiledContract struct {
    App          string
    Services     []CompiledService
    CompiledAt   time.Time
    ArtifactSHA  string
}

type CompiledService struct {
    Unit           string
    SeccompProfile seccomp.Profile        // cBPF instructions
    AppArmorProfile apparmor.Profile      // AA rules text
    ExecguardRules  []execguard.Rule      // fanotify deny rules
    EgressPolicy    egressguard.Policy    // cgroup BPF allow-set
    FIMPolicy       fim.WatchPolicy       // paths to watch + alert thresholds
}
```

### UI additions

```
GET  /apps/:name/contract        — view compiled contract as human-readable YAML
POST /api/apps/:name/contract/recompile   — trigger recompile from current approved behaviors
GET  /api/apps/:name/contract/download    — download contract YAML
POST /api/apps/:name/contract/upload      — upload signed contract (from CI)
```

---

### P5a — AS BUILT (first cut, 2026-06-10)

The original plan above was YAML-file-driven (`/etc/xhelix/apps.d/`). P-UI moved
the source of truth to the SQLite **app registry** ("everything managed by UI"),
so the compiler is driven from the registry, not contract files. Two operator
decisions narrowed the first cut:

- **Enforcement:** compiler core + the **no-restart** enforcer only. App.Mode now
  drives live per-app exec allowlisting via an execguard policy hook. Seccomp /
  AppArmor profiles are **generated and written to `/etc/xhelix/compiled/<app>/`
  for review, but NOT armed** — arming needs a service restart → deferred to P5a.2.
- **Input:** declaration + red zones (deterministic, zero-FP). Baseline-driven
  refinement is the documented next step; it needs a baseline query layer that
  does not exist yet, so it is not wired.

**Shipped:**
- `pkg/contractcompiler/` — `Compile(app, redzones) → CompiledContract`;
  `Manager` caches contracts, writes staged artifacts, and answers the exec hook.
- `pkg/execguard` — `SetPolicyHook` (tighten-only: Allow→Deny for locked/sealed
  undeclared exec, scoped to the app cgroup; red-zone floor never weakened;
  maintenance grants still lift via the existing AllowOverride).
- Mode → live behavior: `observe`/`guarded` → floor only; `shadow` → log+tally
  would-blocks, deny nothing; `locked`/`sealed` → deny exec ∉ declared binaries
  in-cgroup + stage seccomp/AppArmor to disk.
- UI: `GET /api/apps/:name/policy`, `POST /api/apps/:name/recompile`, and a
  "Compiled Profile" panel on the app detail page (staged artifacts labeled
  "NOT enforced").
- Recompile triggers on app create / mode-change / delete.

**Deferred (needs new layers):** baseline-driven allowlist refinement; per-app
egress blocking (needs the eBPF cgroup/connect backend — egress stays per-host).

**Honest limits:** `locked` allowlists *exec only*, live — not syscalls/writes
(those are staged until armed, see P5a.2). Exec allowlisting can FP on legit
undeclared helpers; mitigations are per-app opt-in, `shadow`-first preview, and
maintenance grants.

### P5a.2 — AS BUILT (arming, 2026-06-11)

Arms the staged seccomp/AppArmor profiles via **native systemd directives** in a
unit drop-in — no wrapper binary, no ExecStart rewriting.

**Shipped:**
- `pkg/contractarm/` — `RenderDropIn` (pure: emits `SystemCallFilter=~…` +
  `SystemCallErrorNumber=EPERM` + optional `AppArmorProfile=`); `Armorer` with
  `Arm` / `Disarm` / `Restart` / `Status`. systemctl runs through an injected
  Runner (unit-testable; never invoked against real services during dev).
- **Non-disruptive arm:** `Arm` writes the drop-in to
  `/etc/systemd/system/<unit>.d/50-xhelix-<app>.conf`, loads AppArmor
  (best-effort, only when `apparmor.Available()`), and runs `daemon-reload` —
  it does **not** restart. Enforcement applies on next start; a separate explicit
  **Restart** (`systemctl try-restart`) applies it now.
- **`sealed` gate:** arming a sealed app requires an active maintenance-chain
  grant on one of its service cgroups (break-glass). `locked` needs only
  operator confirmation. Arm is rejected for observe/shadow/guarded.
- `CompiledService` carries `SeccompSystemdDirective` + `AppArmorProfileName`.
- UI: `GET /api/apps/:name/arm-status`, `POST .../arm|disarm|restart`, and
  Arm / Disarm / Restart-services controls on the Compiled Profile panel with
  armed/staged/restart-pending state per service.
- 9 contractarm tests (drop-in render, arm writes + single daemon-reload,
  skip-empty-service, disarm removes, status reflects state, restart issues
  try-restart).

**Honest limits:** seccomp arming uses systemd's `SystemCallFilter` (syscall
*names*, deny-list) — slightly coarser than the raw cBPF profile, but native and
auditable. AppArmor arming is best-effort (skipped when the host lacks AppArmor).
Restart is genuinely disruptive — gated behind an explicit, separate operator
action with a confirm dialog. The daemon shells out to `systemctl` as root;
this is the operator's action through the product, not an automatic behavior.

---

## Phase 5b — OpenTelemetry Integration
**Start: 2026-10-06 | End: 2026-10-27**

Optional but high-value layer. When an app emits OTel traces, xhelix gains
per-route behavioral visibility — far higher fidelity than eBPF alone.

### Files to create

```
pkg/otelreceiver/
  receiver.go        — OTLP gRPC receiver (listens on 127.0.0.1:4317)
  receiver_test.go
  correlator.go      — correlate spans with eBPF events by pid+timestamp
  correlator_test.go
  routemap.go        — build per-route capability maps from correlated events
```

### Files to modify

```
cmd/xhelix/foundation.go   — add OTelReceiver *otelreceiver.Receiver (opt-in)
cmd/xhelix/run.go          — start receiver if cfg.OTel.Enabled; wire span events
                             into pipeline as synthetic events tagged otel.span
pkg/contractcompiler/      — accept route-level maps from OTel when available
ui/web/apps.go             — add /apps/:name/traces page
```

### What OTel enables

Without OTel: contract says "php-fpm connects to stripe.com"  
With OTel: contract says "POST /checkout connects to stripe.com; GET /healthz does not"

This closes the SSRF detection gap: if GET /healthz connects to stripe.com, that's
unexpected per the route contract — alert fires even though stripe.com is in the
service-level allow list.

### OTel trace page (/apps/:name/traces)

```
┌─────────────────────────────────────────────────────────┐
│ billing-api — Route Activity (last 5 min)               │
├─────────────────────────────────────────────────────────┤
│ POST /checkout   234 req/min  avg 45ms                  │
│   → mysql:3306  (SELECT+INSERT)  avg 12ms               │
│   → redis:6379  (GET)            avg 1ms                │
│   → api.stripe.com:443           avg 31ms               │
│                                                         │
│ GET /healthz     12 req/min   avg 2ms                   │
│   → mysql:3306  (SELECT 1)  avg 1ms                     │
│   [no egress]                                           │
└─────────────────────────────────────────────────────────┘
```

---

## Phase 6 — Causal Chain Engine
**Start: 2026-10-27 | End: 2026-11-24**

Every event gets a `chain_id`. Every enforcement decision has full causal context.
With OTel done in 5b, the chain_id IS the OTel trace ID for instrumented apps.
For non-instrumented apps, the chain engine reconstructs causality from OS signals.

### Files to create

```
pkg/workflowchain/
  chain.go          — chain_id assignment, parent-child graph
  chain_test.go
  correlator.go     — correlate events into chains by: pid lineage, socket inode,
                      fd, file inode, DNS name, TLS SNI, HTTP route, OTel trace ID
  correlator_test.go
```

### Files to modify

```
pkg/pipeline/pipeline.go    — stamp chain_id on every event
cmd/xhelix/run.go           — start chain correlator; subscribe to OTel spans
                              to seed chain_ids for instrumented apps
ui/web/apps_live.go         — expose chain_id in live feed; allow expand-to-chain
```

### UI: chain expansion

Any event in the deny ledger or live feed shows a "View chain" link. Clicking it
expands the full causal chain:

```
chain_id: 01J4X7... (POST /checkout at 14:23:01.482)
  ├─ [ACCEPT] tcp accept nginx:80 ← 203.0.113.5:42891
  ├─ [ALLOW]  unix connect nginx → php-fpm.sock
  ├─ [ALLOW]  file read /var/www/html/checkout.php
  ├─ [ALLOW]  tcp connect php-fpm → mysql:3306
  ├─ [ALLOW]  tcp connect php-fpm → api.stripe.com:443
  └─ [BLOCK]  exec php-fpm → /bin/bash  ← RED ZONE VIOLATION
               reason: no maintenance chain active
               action: SIGKILL sent to pid 4821
```

---

## Phase 7 — CI/CD Integration
**Start: 2026-11-24 | End: 2026-12-15**

Every deploy produces a behavioral diff. Security team reviews the diff in the UI.
No YAML editing, no CLI required for the operator.

### Files to create

```
pkg/contractdiff/
  diff.go           — compute behavioral diff between two contracts
  diff_test.go
  renderer.go       — render diff as HTML (for UI) and JSON (for CI webhook)
```

### Files to modify

```
cmd/xhelix/run.go           — accept incoming contract via webhook endpoint
cmd/xhelix/web_setup.go     — register /api/deploys/* routes
ui/web/deploys.go           — NEW: deploy history + pending approval UI
ui/web/templates.go         — deploy diff templates
```

### CI pipeline integration (no xhelixctl needed from CI)

```
# In CI (GitHub Actions, GitLab CI, etc.)
# Step 1: build binary
# Step 2: record test suite
XHELIX_RECORD=1 XHELIX_APP=billing-api ./run-tests.sh

# Step 3: push recorded contract to xhelix
curl -X POST https://xhelix-host/api/deploys/propose \
  -H "Authorization: Bearer $CI_TOKEN" \
  -d '{"app":"billing-api","artifact_sha":"abc123","recorded_contract":"..."}'

# xhelix shows diff in UI, operator approves, CI is notified
```

### Deploy history UI (/apps/:name/deploys)

```
┌─────────────────────────────────────────────────────────┐
│ billing-api — Deploy History                            │
├─────────────────────────────────────────────────────────┤
│ v1.4.3  git:a4bc71f  2026-12-01  ● Active              │
│ v1.4.2  git:91fd2c8  2026-11-14  ○ Previous            │
│ v1.4.1  git:7de3a91  2026-11-01  ○ Previous            │
├─────────────────────────────────────────────────────────┤
│ Pending approval: v1.4.4  git:b2c983e  pushed 2m ago   │
│                                                         │
│ Behavioral diff from v1.4.3:                            │
│  + egress: api.sendgrid.com:443  (new email feature)    │
│  - egress: legacy-smtp.internal:25  (removed)           │
│  + write: /var/www/html/exports/**  (CSV export)        │
│  (47 other behaviors: unchanged)                        │
│                                          [Approve] [Reject]│
└─────────────────────────────────────────────────────────┘
```

### API endpoints

```
POST /api/deploys/propose          — CI pushes recorded contract
GET  /api/deploys/:app             — list deploys for an app
GET  /api/deploys/:app/:id/diff    — get behavioral diff as JSON or HTML
POST /api/deploys/:app/:id/approve — operator approves from UI
POST /api/deploys/:app/:id/reject  — operator rejects
GET  /api/deploys/:app/:id/status  — CI polls for approval status
```

---

## Complete File Creation/Modification Index

### New packages (in creation order)

| Package | Phase | Path |
|---|---|---|
| `pkg/maintenancechain` | P2 | `pkg/maintenancechain/` |
| `pkg/appregistry` | P-UI | `pkg/appregistry/` |
| `pkg/egressguard/cgroupbpf` | P3 | `pkg/egressguard/cgroupbpf/` |
| `pkg/contracthealth` | P4 | `pkg/contracthealth/` |
| `pkg/contractcompiler` | P5a | `pkg/contractcompiler/` |
| `pkg/otelreceiver` | P5b | `pkg/otelreceiver/` |
| `pkg/workflowchain` | P6 | `pkg/workflowchain/` |
| `pkg/contractdiff` | P7 | `pkg/contractdiff/` |

### New UI files (in creation order)

| File | Phase | Purpose |
|---|---|---|
| `ui/web/maintenance.go` | P2 | Maintenance chains page + API |
| `ui/web/egress_app.go` | P3 | Per-app egress management |
| `ui/web/health.go` | P4 | Contract health + deny ledger |
| `ui/web/apps.go` | P-UI | App registry + detail |
| `ui/web/apps_learn.go` | P-UI | Learning review |
| `ui/web/apps_live.go` | P-UI | Real-time activity feed |
| `ui/web/apps_wizard.go` | P-UI | Service discovery wizard |
| `ui/web/static/apps/apps.css` | P-UI | App management styles |
| `ui/web/static/apps/apps.js` | P-UI | App registry + live JS |
| `ui/web/static/apps/learn.js` | P-UI | Contract review JS |
| `ui/web/static/apps/wizard.js` | P-UI | Discovery wizard JS |
| `ui/web/static/apps/uplot.min.js` | P-UI | Embedded chart library |
| `ui/web/apps_otel.go` | P5b | OTel route trace view |
| `ui/web/deploys.go` | P7 | Deploy history + diff approval |

### Modified files (cumulative across all phases)

| File | Phases |
|---|---|
| `cmd/xhelix/foundation.go` | P2, P3, P4, P-UI, P5b |
| `cmd/xhelix/run.go` | P2, P3, P4, P5b, P6 |
| `cmd/xhelix/web_setup.go` | P2, P3, P4, P-UI, P5b, P7 |
| `ui/web/templates.go` | P2, P3, P4, P-UI, P6, P7 |
| `pkg/pipeline/pipeline.go` | P6 |
| `pkg/egressguard/nft.go` | P3 |

---

## What the Operator Does From the UI (No CLI Required)

| Task | UI location |
|---|---|
| Install xhelix + first app setup | /apps/new wizard |
| Start observation on a new app | /apps/new → step 3 |
| See real-time app activity | /apps/:name/live |
| Review learned behaviors after observation | /apps/:name/learn |
| Approve or reject individual behaviors | /apps/:name/learn (per-item buttons) |
| Generate + activate contract | /apps/:name/learn → "Generate Contract" |
| Promote enforcement mode | /apps/:name → mode slider |
| Start maintenance window for a deploy | /apps/:name/maintenance → "New Window" |
| Approve a new egress destination | /apps/:name/egress → shadow queue |
| Review deny ledger after a block | /apps/:name/health |
| Re-lock after circuit breaker trips | /apps/:name/health → "Re-lock" |
| Review + approve a CI/CD behavioral diff | /apps/:name/deploys → pending |
| View full causal chain for any event | Any event → "View chain" |
| See per-route activity (OTel) | /apps/:name/traces |

---

## Quality Gates (per phase)

Each phase must pass before the next begins:

- **P2 gate:** Maintenance chain created from UI, active grant shows in `/maintenance`,
  execguard bypass confirmed in test, red zone re-engages after expiry
- **P3 gate:** cgroup BPF attach confirmed (`bpftool cgroup show`), outbound SYN
  to non-allowlisted IP dropped before leaving host, shadow queue populates in UI
- **P4 gate:** Circuit breaker trips at configured threshold in test, auto-downgrade
  fires, deny ledger populated in UI, re-lock flow completes without CLI
- **P-UI gate:** All /apps/* pages render with real data, live feed streams events,
  contract review workflow completes end-to-end from browser
- **P5a gate:** Contract YAML round-trips through compiler, seccomp profile installs
  and denies target syscall in test, contract activation shows in UI
- **P5b gate:** xhelix receives OTel span, span correlated with eBPF event by pid,
  /apps/:name/traces shows per-route breakdown
- **P6 gate:** chain_id present on all events in deny ledger, "View chain" link
  expands to full causal graph in UI
- **P7 gate:** CI webhook pushes contract, diff appears in UI within 5s,
  approval/reject cycle completes, CI poll returns result

### Safety layer + reconciler — AS BUILT (2026-06-11)

Built ahead of P5b because the maturity review flagged the missing P4 safety
layer as the top blocker to shipping enforcement.

**Decision (security-driven):** the deny-storm breaker is ALERT-ONLY — it never
auto-disables enforcement, because deny volume is attacker-controllable (a flood
of denies must not become an off-switch for the EDR). The only thing that
auto-reverts is an unambiguous availability failure: a service that won't restart
after arming.

**Shipped:**
- `pkg/contracthealth` — `Breaker` (rolling-window per-app deny counter; latches a
  one-shot alert at threshold; sticky until operator Reset) + `Reconciler`
  (converges on-disk armed drop-ins with declared intent: auto-disarms orphans
  from deleted/downgraded apps, alerts on missing-arm drift; never auto-arms).
- `contractarm.Arm` is now **transactional** — a mid-loop failure rolls back every
  drop-in written in that call before returning.
- `contractarm.RestartAndVerify` — restarts, polls `systemctl is-active`, and
  AUTO-ROLLS-BACK any service that fails to come up (removes drop-in, daemon-reload,
  restarts unconstrained) so a bad policy can't brick a service.
- `contractarm.ScanArmed` / `DisarmUnits` — filesystem source-of-truth for the
  reconciler.
- Wired: breaker fed from the execguard deny callback (compiled-policy denies
  only); breaker trip + reconcile drift publish alerts on the bus; reconciler runs
  every 1m; UI shows a breaker banner with Acknowledge, and Restart surfaces any
  auto-rolled-back services.
- Tests: breaker (trip-once, window expiry, reset, concurrent `-race`), reconciler
  (orphan disarm, drift), transactional arm rollback, health-check auto-rollback.

**Still deferred:** policy signing/versioning, RBAC-on-arm, persistent audit trail,
kernel-in-the-loop e2e proving a real syscall is denied.

### Audit trail + RBAC-on-arm — AS BUILT (2026-06-11)

Closes the two remaining production-blockers from the maturity review:
no change-audit trail, and any authenticated session could arm prod.

**Audit trail — `pkg/contractaudit`:**
- Append-only, SHA-256 **hash-chained** SQLite log (hash = sha256(prev_hash |
  canonical(record))). `Verify()` walks the chain and names the first broken
  seq, so a deleted or edited row is detectable. Tip recovered across reopen.
- Records every control action — create / mode_change / arm / disarm / restart /
  delete / recompile / breaker_reset — with actor (role + credential + source IP),
  target, detail, and outcome (ok / error).
- Surfaced per-app at GET /api/apps/:name/audit + a "Recent Activity" panel.
- Tests: chain link, tamper detection (edit), deletion detection, reopen, per-app.

**RBAC-on-arm — role-scoped tokens (backward compatible):**
- Three roles: viewer < operator < admin. The existing single token is always
  ADMIN, so current deployments are unchanged. Optional viewer/operator tokens via
  `ui.role_tokens: {viewer: <file>, operator: <file>}`.
- AuthGuard resolves the presented token → role, attaches an Identity (role +
  credential + IP) to the request context; NoAuth/single-token → admin.
- Gates: GET = viewer; create / mode_change / arm(locked) / disarm / recompile /
  breaker_reset = operator; restart / delete / arm(sealed) / promote-to-sealed =
  admin. 403 on insufficient role.
- Tests: role ordering, ParseRole, default-admin identity, requireRole 403 matrix.

**Still deferred:** policy signing/versioning (overlaps P7 CI/CD); per-person (vs
per-credential) identity; kernel-in-the-loop e2e proving an armed syscall denies.

### P7 (started) — policy signing + versioning — AS BUILT (2026-06-11)

The highest-value, self-contained slice of P7, and the one that closes the last
maturity gap (no policy signing/versioning). The full CI webhook / behavioral
diff / deploy-history UI remain the P7 continuation.

**Shipped:**
- `CompiledContract.ArtifactSHA` — deterministic SHA-256 over the policy-relevant
  content (services, exec allow/deny, syscalls, write-deny). Content-addressed
  VERSION. Excludes Mode + CompiledAt, so a mode flip or plain recompile keeps the
  same hash (a signature survives), while any declaration drift changes it.
- `pkg/contractsign` — Ed25519 Sign/Verify over a domain-separated message
  (`xhelix-contract-sig-v1|app|hash`, so a sig can't be replayed across apps) +
  a signature store that verifies against the trust root before storing and
  RE-verifies on read (a revoked key's old signature stops counting).
- Sealed-mode arm gate is now **signature-based**: arming a sealed app requires a
  valid trusted signature over the CURRENT ArtifactSHA, OR an active maintenance
  grant (documented break-glass). Unsigned drift → blocked until re-signed.
- Trust root = the BRP `trusted-keys.d` (CI signs with a key whose public half is
  there); the daemon UI key is also registered as signer "ui" for in-UI self-sign.
- API (admin-gated, audited): POST /api/apps/:name/sign (self-sign current version),
  POST /api/apps/:name/signature (accept external CI signature). Policy view +
  panel show the version hash + signed/✗-unsigned status + a Sign button.
- Tests: sign/verify round-trip + cross-app/cross-hash/untrusted rejection;
  store rejects untrusted, drops revoked-key sigs on read, blocks drift; hash
  stable across mode-flip but changes on drift.

**P7 continuation (not yet built):** CI propose endpoint + behavioral diff
(`pkg/contractdiff`) + deploy-history/approval UI (`ui/web/deploys.go`).

### P7 (continued) — behavioral diff + version history — AS BUILT (2026-06-11)

Adapts the documented "CI pushes contract → diff → approve" flow to the
registry-driven, signing-based model: the diff is current-compiled vs
last-signed, and "approve" = sign the new version.

**Shipped:**
- `pkg/contractdiff` — pure behavioral diff of two compiled contracts:
  service add/remove + per-service set diffs (exec_allow / exec_deny /
  deny_syscalls / write_deny) → added/removed changes + unchanged count.
  Deterministic ordering.
- `contractsign` now snapshots the signed contract's JSON content
  (AddWithSnapshot / SnapshotJSON) and exposes LatestSigned — so a diff has
  an approved baseline to compare against, surviving restart.
- API (viewer): GET /api/apps/:name/diff (current vs last-signed),
  GET /api/apps/:name/versions (signed history, active flag).
- UI: "Pending Changes" panel shows drift (+/− per behavior) with a clear
  "review then Sign to approve" prompt; "Version History" lists signed
  versions with the active one marked. Sign refreshes the diff.
- Integration test: compile→sign→snapshot, drift the declaration, confirm
  the drifted version reads unsigned (sealed-arm blocked) AND the diff vs
  the JSON-reloaded baseline shows the exact binary add/remove.

**P7 remaining (optional):** a CI *propose* webhook that POSTs a new
declaration (vs. editing via UI) + a polled approval-status endpoint for CI
to block on. The signing/diff/version substrate it would use is now built.

### P7 (complete) — CI propose webhook — AS BUILT (2026-06-11)

The final P7 piece: CI proposes a declaration change, an admin reviews the diff
and approves/rejects, CI polls status. Adapted to the registry model — a
"deploy" proposes a new declaration for an EXISTING app.

**Shipped:**
- `pkg/contractpropose` — proposal store (pending/approved/rejected), app-scoped
  IDs, decide-once semantics (a decided proposal can't be re-decided).
- `appregistry.Update` — replace an existing app's declaration + services in one
  transaction, rebuilding the cgroup index (needed to apply an approved proposal).
- API:
  - POST /api/apps/:name/propose            (operator) — CI submits a declaration;
    xhelix compiles it for the target hash, stores pending. Audited.
  - GET  /api/apps/:name/proposals          (viewer)
  - GET  /api/apps/:name/proposals/:id/diff (viewer)  — proposed vs live diff
  - GET  /api/apps/:name/proposals/:id[/status] (viewer) — CI polls
  - POST /api/apps/:name/proposals/:id/approve (admin) — applies declaration +
    recompiles + marks approved. Audited.
  - POST /api/apps/:name/proposals/:id/reject  (admin). Audited.
- Approve applies the declaration but does NOT auto-sign — signing stays a
  separate attestation, so a sealed app's new version still needs a Sign to arm.
- UI: "Pending Deploys" panel lists pending proposals with their behavioral diff
  inline + Approve/Reject buttons.
- Integration test: declare → propose drift → diff non-empty → approve applies +
  recompiles → registry reflects new declaration, version == target, cgroup index
  intact; decide-once enforced.

**P7 is now functionally complete.** CI flow: GET /policy (read artifact_sha) →
sign after tests, or POST /propose → poll /status → (admin approves in UI) →
POST /signature to attest the approved version.

### P6 (started) — hot causal graph wired live — AS BUILT (2026-06-11)

First cut of the causal chain engine. The substrate (lineage, incidentgraph,
correlator with retained constituent events, proctree) was already wired; the
one missing piece was pkg/hotgraph — fully built and queryable but populated by
nothing (Insert called nowhere → empty in production).

Approach chosen: substrate-based on-demand assembly, NOT the doc's universal
chain_id stamping (which overlaps deferred P5b/OTel and needs a much larger
correlator). This first cut just makes the graph live.

**Shipped:**
- pipeline.populateHotGraph: on proc spawn, resolve the PID + parent to canonical
  (PID,StartTicks) keys via the ProcKey cache, build a ProcessNode, and Insert.
  Lineage + origin IP are inherited from the parent's existing graph node, so a
  root anchor (SSH login, web request) propagates to every descendant.
- MarkExit on proc exit (cache-only key lookup; no /proc read on a dead pid).
- Wired Pipeline.HotGraph + Pipeline.ProcKeys (foundation.HotGraph /
  foundation.ProcCache) through dispatch. Single-goroutine, consistent with the
  correlator's determinism requirement. Nil-safe.
- Effect: the already-exposed LocalAPI handlers — graph.ancestors / descendants /
  by_lineage / by_origin / by_cgroup — now return LIVE data (were empty before).
- Test: spawn inherits parent lineage+origin, parent edge set, Ancestors walks to
  the root, ByLineage/ByOriginIP resolve the whole tree.

**P6 continuation (deferred):** pkg/causalengine (CausalChain(alertID) → ordered
root-cause story from alert EvidenceIDs → hotgraph ancestors → lineage Origins)
and the UI "View chain" expansion. The graph they consume is now live.
