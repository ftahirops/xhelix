# xhelix Behavioral Compiler Architecture

**Status:** Design document — active build target  
**Branch:** verdict-foundation  
**Date:** 2026-06-10

---

## What This Document Is

This is the full engineering specification for xhelix's next architectural layer: a **behavioral compiler** that turns application intent into kernel-level enforcement.

Current xhelix is a strong detection engine. This architecture makes it a **prevention engine** — one that does not merely alert when nginx spawns a shell, but makes it physically impossible for nginx to spawn a shell, exfiltrate data, or write persistence, at the kernel level, before the packet or syscall completes.

---

## The Core Insight

Every Linux service has a finite, knowable behavioral envelope. nginx serving static HTML will never legitimately:
- Spawn `/bin/sh`
- Connect to `82.221.101.203:8443`
- Write to `/root/` or `/etc/cron.d/`
- Read `~/.ssh/id_rsa`
- Send a POST request to `ntfy.sh`

The OS does not enforce this. The kernel allows any process to attempt any syscall it has permission for. The job of this architecture is to close that gap: **compile what an app is allowed to do into kernel enforcement before the app starts, not after an attack is detected.**

The unit of policy is not a process. It is a **causal workflow chain**: the complete graph of OS-level actions that a valid user request or background job is allowed to produce, from first network accept to final log write.

---

## The Three-Contract Model

Every application in xhelix's protection scope has three contracts:

### 1. Code Contract
*What the deployed artifact claims it can do.*

Derived from static analysis, SBOM, routes, declared dependencies, env vars, DB migration names, cron definitions, OpenAPI hash, commit SHA, artifact hash. This is the **declared capability ceiling**. The app cannot claim capabilities at runtime that it did not declare at deploy time.

### 2. Causal Runtime Contract
*What actually happens when a valid workflow executes.*

Recorded by running e2e tests or observing production traffic through xhelix's recorder. Captures the full event graph: inbound request → file reads → DB calls → DNS → TLS → egress → log writes → response. This is the **observed behavioral truth** for each known workflow.

### 3. Enforcement Contract
*What xhelix compiles into kernel and userland controls.*

The compiler takes contracts 1 and 2, validates consistency, and emits: seccomp profile, AppArmor profile, execguard allowlist, cgroup BPF egress policy, credbroker app contract, FIM watch policy, BRP invariants, correlator chain rules. This is what actually runs.

**The enforcement contract is the compiled output. You never edit it directly. You change the code contract or runtime contract and recompile.**

---

## Red Zones — Never Learnable

These behaviors are categorically forbidden for web application services. No learning window, no maintenance grant (unless explicitly scoped), no operator approval can normalize them:

```yaml
red_zones:
  exec:
    - /bin/sh
    - /bin/bash
    - /bin/dash
    - /usr/bin/curl
    - /usr/bin/wget
    - /usr/bin/python*
    - /usr/bin/node        # unless app IS node
    - /usr/bin/php         # unless app IS php-fpm
    - /usr/bin/perl
    - /usr/bin/ruby
    - /usr/bin/nc
    - /usr/bin/ncat
    - /usr/bin/socat

  write:
    - /root/**
    - /etc/cron*
    - /var/spool/cron/**
    - /etc/systemd/system/**
    - /etc/systemd/user/**
    - /home/*/.config/systemd/user/**
    - /home/*/.ssh/**
    - /etc/ssh/**
    - /etc/ld.so.preload
    - /etc/modprobe.d/**
    - /proc/*/mem
    - /proc/sysrq-trigger

  read:
    - /root/**
    - /home/*/.ssh/**
    - /home/*/.aws/**
    - /home/*/.kube/config
    - "**/.env"
    - "**/id_rsa"
    - "**/id_ed25519"

  network:
    - raw_ip_without_sni
    - unknown_domain_tls
    - messaging_platform_from_web_worker  # ntfy.sh, Telegram, Discord
    - high_volume_encrypted_post_to_new_dest

  syscalls:
    - ptrace
    - bpf
    - userfaultfd
    - mount
    - unshare
    - setns
    - process_vm_writev
    - process_vm_readv
    - kcmp
    - open_by_handle_at
```

Red zones are **hard-denied at the kernel level** for all web application cgroups. They can only be temporarily unlocked inside a signed **Maintenance Chain** with explicit scope.

---

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  DECLARATION PLANE                                              │
│  App Contract File (/etc/xhelix/apps.d/<app>.yaml)             │
│  Code Contract Builder (xhelixctl app contract build)          │
│  Red Zone Registry (global + per-app overrides)                │
│  "What this app version is allowed to be capable of"           │
└──────────────────────────┬──────────────────────────────────────┘
                           │ compiles
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  COMPILER  (pkg/contractcompiler)                               │
│  App Contract → CompiledContract                               │
│  Outputs: seccomp + AppArmor + execguard + cgroup BPF egress   │
│           + credbroker policy + FIM policy + BRP invariants    │
└──┬──────────┬──────────┬──────────┬──────────┬─────────────────┘
   │          │          │          │          │
   ▼          ▼          ▼          ▼          ▼
seccomp    AppArmor  execguard  cgroup BPF  credbroker
(kernel)   (kernel)  (kernel)   (kernel)    (userland)
   │          │          │          │          │
   └──────────┴──────────┴──────────┴──────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  RUNTIME OBSERVATION PLANE                                      │
│  eBPF sensors → pipeline → proctree + source attribution       │
│  → causal chain engine (pkg/workflowchain)                     │
│  → every event tagged: chain_id, app, route, maintenance_id    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  CONTRACT ENFORCEMENT PLANE                                     │
│  BRP runtime + maintenance chain checker + correlator          │
│  "Does this runtime event match its declared contract?"        │
│  "Is there a valid maintenance grant for this red-zone action?"│
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  CONTRACT HEALTH PLANE  (pkg/contracthealth)                    │
│  Drift classifier + deny ledger + circuit breaker + rollback   │
│  "Is the contract still correct? How do we recover safely?"    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Enforcement Modes

Every app moves through these modes:

| Mode | What it does | When to use |
|---|---|---|
| `observe` | Record only. No blocks. | First 7 days on new host |
| `shadow` | Would-block events logged. No actual blocks. | Validating a new contract |
| `guarded` | Red zones blocked. Drift alerted. Non-red-zone events allowed. | Default for most services |
| `locked` | All contract drift blocked. Auto-rollback on health failure. | Stable, well-tested services |
| `sealed` | All unsigned drift blocked. No auto-downgrade. Break-glass only. | Critical infrastructure |

---

## Maintenance Chains

Maintenance chains are the mechanism that makes `locked` and `sealed` modes operational. They are **signed, time-boxed, cgroup-scoped capability grants** that temporarily unlock specific red-zone behaviors for a known-good operation.

```yaml
maintenance_chains:
  - id: deploy_billing_api
    app: billing-api
    trigger:
      type: signed_release
      signer: ci-prod
      artifact_sha256: "abc123..."
    scope:
      systemd_unit: billing-api-deploy.service
      user: deploy
      cgroup: /system.slice/billing-api-deploy.service
    max_duration: 300s
    allowed_red_zones:
      exec:
        - /bin/sh
        - /usr/bin/npm
        - /usr/bin/node
      write:
        - /srv/billing-api/**
        - /etc/systemd/system/billing-api.service.d/**
      network:
        - registry.npmjs.org:443
        - github.com:443
    post_checks:
      - app_contract_hash_matches
      - service_restarted
      - no_remaining_child_processes
      - no_new_persistence_outside_scope
```

**How it works:**
1. Operator runs: `xhelixctl maint run deploy_billing_api -- ./deploy.sh`
2. xhelix mints a maintenance token bound to: `(maintenance_id, cgroup_id, pid_start_time, artifact_hash, signer, expiry)`
3. Every kernel event in that lineage is tagged `maintenance_id=deploy_billing_api`
4. BRP hard-deny path checks: is there a valid maintenance grant for this event's cgroup + action + timestamp?
5. If `/bin/sh` is spawned by **nginx** — not in maintenance cgroup — still hard-blocked
6. After expiry: post-checks run, grant invalidated, all red-zones re-locked

No permanent exceptions. No "apt is trusted globally." Every deviation from contract must be explicitly scoped.

---

## Egress Enforcement Design

Egress enforcement must be **prevention, not detection**. The credential exfil POST to a C2 server completes in under 100ms. An alert after the fact does not prevent the breach.

### Three backends in enforcement order:

**Backend 1 — cgroup BPF connect hook** (best, use for `locked`/`sealed`):
- Attached to service cgroup at contract activation
- Blocks `connect()` before the SYN packet leaves the host
- Policy map: `(cgroup_id, dst_ip, dst_port) → allow/deny`
- Updated on DNS resolution events (TTL-aware)
- Zero userspace roundtrip

**Backend 2 — systemd IPAddressDeny/IPAddressAllow** (practical, use for `guarded`):
- Compiled allow CIDRs into unit drop-in at service start
- Kernel-enforced, no userspace overhead
- Limitation: CIDR-level only, no SNI awareness

**Backend 3 — nftables named sets** (fallback):
- Named set per app with resolved IPs + TTL tracking
- Persistent table installed at contract activation
- Not NFQUEUE — named sets with `drop` verdict

**NFQUEUE is not used for `locked`/`sealed` modes.** `pkg/enforce/nfqueue/` is intentionally fail-open on timeout. Acceptable for diagnostics, not for prevention.

**DNS/SNI binding:** xhelix resolves FQDNs at contract activation and on DNS events, updates IP sets with TTL. Raw IP without SNI matching a declared FQDN is blocked even if the IP resolves correctly — prevents SNI stripping attacks.

---

## Contract Health and Circuit Breaker

Contracts will sometimes be wrong. One missed e2e test scenario, one undocumented background job — and the app breaks in production. The circuit breaker makes this recoverable without disabling protection.

```yaml
health_guard:
  rollback_to_previous_on:
    approved_denies_per_hour: 3
    blocked_5xx_rate: ">2%"
    healthcheck_failures: 2
    denied_requests: 10
  never_rollback_for:
    - shell_spawn
    - credential_read
    - persistence_write
    - unknown_raw_ip_egress
    - red_zone_violation
  rollback_target: previous_signed_contract
  downgrade_mode: guarded
```

**What this means in practice:**
- Contract blocks a legitimate file read → 3 operators approve it → auto-downgrade to `guarded`, page on-call
- Contract blocks nginx spawning `/bin/sh` → **no rollback, stays blocked, page immediately**
- Rollback restores previous signed contract and keeps all red zones active

Operator workflow for legitimate drift:
```bash
xhelixctl app approve-drift deny_01 --ttl 2h --reason "new payment provider rollout"
# creates signed temporary grant, not a permanent contract change
```

---

## Phase Build Plan

---

### Phase 1 — Red Zone Hard Blocks
**2–3 weeks. Zero contract machinery needed.**

**What gets built:**
- `pkg/redzones/redzones.go` — global hard-deny policy loaded at daemon start
- Wired into existing execguard + BRP + BPF LSM
- Per-cgroup policy: web worker cgroups get the full red zone set
- Static config: `/etc/xhelix/redzones.yaml`

**What it enforces:**
- `execve(/bin/sh, /bin/bash, /usr/bin/curl, ...)` from web worker cgroup → SIGKILL
- Write to `/etc/cron*`, `/root/`, `~/.ssh/` → kernel deny
- Read of `~/.ssh/id_rsa`, `~/.aws/credentials`, `**/.env` → kernel deny
- `ptrace`, `bpf`, `userfaultfd`, `mount` from userland service → kernel deny

**Protection level at Phase 1 completion:**

| Attack | Before | After Phase 1 |
|---|---|---|
| Webshell spawns bash | Detected (alert) | **Blocked at execve — process killed** |
| Webshell writes cron | Detected (FIM alert) | **Blocked at kernel write** |
| Webshell reads SSH keys | Detected (credbroker observe) | **Blocked at kernel open()** |
| Supply chain postinstall → bash | Detected (npm rules) | **Blocked at execve** |
| ptrace-based exploit | Partially detected | **Blocked at syscall** |
| Webshell egress to C2 | Detected (tls_no_sni) | **No change — egress still detection-only** |
| SQLi, SSRF | Partially detected | **No change — semantic attacks unaffected** |

**Honest coverage: 55–65% of real attacks blocked outright. The rest still detected.**

This is the highest-value-per-effort phase. Existing execguard and BPF LSM hooks make most of this possible with configuration, not new kernel code.

---

### Phase 2 — Maintenance Chains
**3–4 weeks. Required before anything can be locked.**

**What gets built:**
- `pkg/maintenancechain` — signed grant mint, token validation, lineage binding, post-checks
- `xhelixctl maint run <chain_id> -- <command>` — operator CLI
- Integration into BRP hard-deny path: check maintenance grant before denying red-zone action
- Grant store in hot store (SQLite), indexed by `(cgroup_id, expiry)`

**What it enables:**
- Deploy scripts can spawn shells — but only in the deploy cgroup, only for 300 seconds, only when signed by `ci-prod`
- Package updates can contact npm/GitHub — but only during the signed update window
- DB migrations can write schema files — but only the migration service, only for the declared duration
- Everything outside a maintenance chain: still hard-blocked

**Protection level at Phase 1+2 completion:**

Now Phase 1 hard blocks can be safely applied to production systems. Without maintenance chains, Phase 1 breaks deploys. With maintenance chains, Phase 1 is operationally safe.

| Scenario | Coverage |
|---|---|
| Attacker tries to run bash via webshell | Blocked (Phase 1) |
| Attacker tries during deploy window | Blocked — deploy maintenance chain only unlocks deploy cgroup |
| Legitimate deploy runs bash | Allowed — maintenance chain scopes it |
| apt-get runs during maintenance window | Allowed — scoped to update chain |
| Attacker triggers apt install outside window | Blocked (Phase 1 hard block) |

**Honest coverage: 60–70% of attacks blocked. Operational safety achieved.**

---

### Phase 3 — Pre-Start Egress Prevention
**3–4 weeks.**

**What gets built:**
- `pkg/egressguard/cgroupbpf/` — cgroup BPF connect hook, policy map per cgroup
- systemd drop-in generator: `IPAddressAllow`/`IPAddressDeny` compiled from app contract
- nftables fallback: named sets per app, installed at contract activation
- DNS/IP set tracker: resolves FQDNs at activation, refreshes on DNS events
- SNI binding: raw IP without matching SNI → blocked even if IP is in allow set

**What it prevents:**
- Webshell connecting to C2 server → packet never leaves host
- Malware phoning home after exploit → cgroup has no outbound route
- Credential POST to ntfy.sh, Telegram, Discord → messaging platform in egress deny
- Data exfil via raw IP → blocked (no SNI, not in allow set)

For static nginx specifically: `egress allow: []` — nginx **cannot make any outbound connection**. Zero.

**Protection level at Phase 1+2+3 completion:**

| Attack | Coverage |
|---|---|
| Webshell → bash | Blocked (P1) |
| Webshell → cron persistence | Blocked (P1) |
| Webshell → credential read | Blocked (P1) |
| Webshell → C2 egress | **Blocked (P3) — packet never leaves** |
| Exploit → data exfil POST | **Blocked (P3)** |
| Supply chain RAT → ntfy.sh | **Blocked (P3)** |
| Supply chain RAT → raw IP C2 | **Blocked (P3)** |
| Malware → DNS exfil | Detected (dnsexfil) — not yet packet-blocked |
| SQLi, SSRF | Detected, secondary effects blocked |

**Honest coverage: 75–85% of real attacks fully contained. Exfil path mostly closed.**

This is the phase where xhelix transitions from "good EDR" to "genuine prevention system."

---

### Phase 4 — Contract Health + Circuit Breaker
**2–3 weeks.**

**What gets built:**
- `pkg/contracthealth` — deny ledger, approved-deny counter, health monitor, auto-downgrade
- `xhelixctl app approve-drift` — operator approval workflow, temporary signed grants
- Auto-rollback: locked → guarded on threshold breach, never for red zone violations
- Previous contract store: keeps last N signed contracts for rollback

**What it enables:**
- Operators can deploy `locked` mode to production without fear of catastrophic false positives
- Wrong contracts degrade gracefully to `guarded` mode, not to "xhelix disabled"
- Red zone violations never trigger rollback — they page immediately
- Audit trail: every block, every approval, every rollback is logged and signed

**Why this matters operationally:** Without Phase 4, the first time a locked contract blocks a legitimate request in production, the operator disables xhelix globally. Phase 4 makes the failure mode narrow and recoverable. **This is what makes the rest of the architecture deployable in the real world.**

**Protection level at Phase 1+2+3+4 completion:**

Same attack coverage as P1–P3, but now it is **production-safe**. Operators will leave it on. That is the actual win of Phase 4.

---

### Phase 5 — App Contract + Compiler
**4–6 weeks.**

**What gets built:**
- App contract file format: `/etc/xhelix/apps.d/<app>.yaml`
- `pkg/contractcompiler` — takes app contract, emits `CompiledContract{seccomp, AppArmor, execguard, egressguard, credbroker, FIM, BRP}`
- Contract loader: compiled contracts stored in hot store, loaded by daemon at service start
- `xhelixctl app enforce <app>` — compile + activate
- `xhelixctl app contract build` — static analysis for Go/Rust/compiled languages (best-effort for PHP/Python)

**App contract format:**
```yaml
app: billing-api
version: git:91fd2c8
artifact_sha256: "abc123..."
kind: web
unit: billing-api.service
root: /srv/billing-api

routes:
  - method: GET
    path: /healthz
    allows:
      files_read: []
      db: []
      egress: []

  - method: POST
    path: /checkout
    allows:
      secrets: [stripe_api_key]
      egress: [api.stripe.com:443]
      db_fingerprints: [insert_order_v3, select_customer_v2]

children:
  allow: []
files:
  write: [/srv/billing-api/storage/**, /var/log/billing-api/**]
secrets:
  allow: [/etc/xhelix/secrets/billing/stripe.key]
egress:
  allow: [api.stripe.com:443, smtp.provider.com:587]
  mode: locked
  default: deny
```

**What it enables:**
- `GET /healthz` cannot reach `api.stripe.com` even though `POST /checkout` can — route-level enforcement
- Secrets are scoped to specific routes and jobs — `stripe_api_key` only readable during checkout
- Any code path not declared in the contract → blocked

**Protection level at Phase 1–5 completion:**

| Attack class | Coverage |
|---|---|
| Infrastructure exploit (nginx, redis) | **95–99% prevention** — fully specifiable, fully compiled |
| Web app exploit → secondary effects | **85–95% prevention** — secondary effects (shell, cred read, egress) blocked |
| Supply chain (npm, pip, gem) | **90–95% prevention** — install-script cgroup fully locked |
| Privilege escalation via SUID | **80–90%** — syscall restrictions + execguard |
| Lateral movement via SSH key abuse | **85–95%** — key read blocked, outbound SSH locked per-app |
| Semantic attacks (SQLi payload, SSRF) | **60–75%** — secondary effects blocked, payload itself not inspectable |
| Browser / dev workstation | **40–60%** — much wider legitimate behavior surface |

---

### Phase 6 — Causal Chain Engine
**4–5 weeks.**

**What gets built:**
- `pkg/workflowchain` — causal chain graph from root event to completion
- Every event tagged: `chain_id`, `root_action`, `app`, `route`, `maintenance_id`
- Correlation keys: cgroup, pid lineage, socket inode, fd, file inode, DNS name, TLS SNI, HTTP route
- Integration: pipeline stamps `chain_id` on every event
- Correlator rules can reference `chain_id` for cross-event decisions

**What it enables:**
- "This egress connect has no valid parent chain" — currently impossible with per-event rules
- "GET /healthz triggered a DB write" — contract violation visible as a chain
- "This shell spawn happened 200ms after a POST /upload" — attack chain reconstructed automatically
- Forensic replay: full attack chain from first request to last persistence event, reconstructed

**Protection level at Phase 1–6 completion:**

Same attack coverage as P1–P5, but now every block decision has full causal context. False positive rate drops significantly because the chain provides enough context to distinguish legitimate behavior from attack. The circuit breaker in Phase 4 becomes much more precise.

---

### Phase 7 — Full CLI + CI Integration
**2–3 weeks.**

**What gets built:**
```bash
xhelixctl app contract build --repo . --out contract.yaml
xhelixctl app record <app> -- ./tests/e2e.sh
xhelixctl app diff --old prod.contract --new recorded.contract
xhelixctl app sign --key ops.key recorded.contract
xhelixctl app install --mode shadow signed.contract
xhelixctl app enforce <app>
xhelixctl maint run <chain_id> -- <command>
xhelixctl app approve-drift <deny_id> --ttl 2h
xhelixctl app status <app>
xhelixctl app health <app>
xhelixctl app rollback <app>
```

**CI/CD integration:**
- Every release: `app contract build` + `app sign` with `ci-prod` key
- Production only accepts contracts signed by registered keys
- Unsigned behavioral drift → blocked
- Contract diff in CI output: security team reviews behavioral changes before deploy

---

## Final State: Full Architecture Complete

When all seven phases are complete, xhelix is no longer an EDR. It is a **behavioral compiler with kernel enforcement**.

The system enforces three guarantees:

1. **No app can exceed its declared capabilities.** A billing API that declared it talks to Stripe cannot talk to anything else, at the kernel level, before the packet leaves.

2. **No runtime chain can perform undeclared red-zone behavior.** Shell spawn, credential read, persistence write, raw IP egress — these are kernel-level impossible for web application processes outside a signed maintenance window.

3. **Wrong contracts fail safely.** A missed test scenario degrades the app to `guarded` mode, not to "security disabled." Red zone violations never trigger rollback.

### Protection by app class at full completion:

| App class | Realistic protection ceiling | Limiting factor |
|---|---|---|
| Static file server (nginx HTML) | **98–99.5%** | Near-total — fully specifiable |
| Reverse proxy (nginx → upstream) | **95–98%** | Upstream behavior adds complexity |
| API server with known dependencies | **90–97%** | Depends on test coverage quality |
| PHP/Node app with known plugins | **80–95%** | Dynamic language limits static analysis |
| WordPress with third-party plugins | **70–90%** | Plugins change behavior unpredictably |
| Background worker / queue consumer | **85–95%** | Queue semantics must carry correlation IDs |
| Developer workstation | **50–70%** | Legitimate behavior surface is too wide |
| npm/pip install environment | **90–95%** | Install-script cgroup locked by P1+P3 |

### What this architecture cannot prevent:

- **Pure semantic attacks** — SQL injection that reads data using the app's own DB connection. The chain is valid, the egress is allowed, the data goes out via a legitimate response. xhelix cannot inspect encrypted DB query content or HTTP response payloads.
- **Logic abuse** — An attacker who understands the app's declared contract and stays within it (no new files, no new network, no red zones) while abusing business logic.
- **Supply chain in declared dependencies** — If `axios@1.2.3` ships malicious code and the app legitimately calls it, and the malicious code stays within the app's declared behavioral contract, it is invisible to xhelix.
- **Zero-days that stay inside the process** — An in-process memory corruption exploit that reads data and exfiltrates it via an already-allowed egress channel.

These remaining gaps require app-layer semantics (WAF + input validation + query analysis), not kernel-layer enforcement.

---

## What Already Exists in xhelix

The foundation is largely built. The architecture above is an integration layer, not a greenfield build.

| Component | Package | Status |
|---|---|---|
| eBPF sensors (all event types) | `sensors/ebpf/` | Complete |
| Process tree + source attribution | `pkg/proctree/`, `pkg/source/` | Complete |
| BRP invariant runtime | `pkg/brp/runtime.go` | Complete |
| Credential broker + enforcement | `pkg/credbroker/` | Complete |
| App identity | `pkg/appident/` | Complete |
| Request contracts | `pkg/reqcontract/` | Complete |
| Correlator + lineage scorer | `pkg/correlator/`, `pkg/lineagescore/` | Complete |
| File integrity monitoring | `sensors/fim/` | Complete |
| Alert bus + verdict engine | `pkg/alert/`, verdict pipeline | Complete |
| seccomp profile structs | `pkg/prevent/seccomp/` | Structs exist, not auto-compiled |
| AppArmor profile structs | `pkg/prevent/apparmor/` | Structs exist, not auto-compiled |
| execguard | `pkg/execguard/` | Complete |
| npm lifecycle tagger | `pkg/pkglifecycle/` | Complete |
| Egress ledger + observer | `pkg/egressledger/`, `pkg/egressmon/` | Complete (detection) |
| nftables integration | `pkg/egressguard/nft.go` | Partial (reactive) |
| Service contracts | `pkg/profiles/contracts/` | Partial |

**What must be built:** `pkg/redzones`, `pkg/maintenancechain`, `pkg/contractcompiler`, `pkg/workflowchain`, `pkg/contracthealth`, cgroup BPF egress prevention, and the `xhelixctl` command surface.

---

## Total Build Timeline

| Phase | What | Weeks | Cumulative |
|---|---|---|---|
| Phase 1 | Red zone hard blocks | 2–3 | 2–3 weeks |
| Phase 2 | Maintenance chains | 3–4 | 5–7 weeks |
| Phase 3 | Pre-start egress prevention | 3–4 | 8–11 weeks |
| Phase 4 | Contract health + circuit breaker | 2–3 | 10–14 weeks |
| Phase 5 | App contract + compiler | 4–6 | 14–20 weeks |
| Phase 6 | Causal chain engine | 4–5 | 18–25 weeks |
| Phase 7 | CLI + CI integration | 2–3 | 20–28 weeks |

**Phase 1 alone** closes the most exploited attack paths in 2–3 weeks.  
**Phases 1–4** (10–14 weeks) deliver a production-safe prevention system that outperforms most commercial EDR products for Linux service workloads.  
**Full completion** (20–28 weeks) delivers something that does not exist in the commercial market: a behavioral compiler that turns application intent into kernel enforcement.

---

*This document is the design authority for the xhelix behavioral compiler build. Phases 1–4 are the immediate roadmap. Phases 5–7 are the product moat.*
