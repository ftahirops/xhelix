# xhelix — App-Causal BRP Guardian: Locked Scope

| | |
|---|---|
| **Status** | **SCOPE LOCKED** |
| **Date locked** | 2026-06-21 |
| **Branch** | verdict-foundation |
| **Supersedes framing of** | "generic Linux EDR" |
| **Companion design docs** | `docs/BEHAVIORAL_COMPILER_ARCHITECTURE.md`, `docs/LOW_FALSE_POSITIVE_ARCHITECTURE_2026-05-21.md`, `docs/v2-brp-progress.md`, `docs/MATURITY_GATE_DROPPER.md` |

This document is the **authoritative scope reference**. Later work cites it as
the locked definition of what xhelix is and what it must observe, attribute,
learn, and enforce. Implementation proceeds by decomposing this into
sub-projects (see §12), each with its own spec → plan → build cycle.

---

## 1. Product definition (the one line)

> **xhelix is a per-application causal behavior compiler for Linux servers,
> with service-level hard invariants and kernel-level egress isolation.**

Not "an EDR." EDR-style detections remain as *supporting signals*. The
primary object xhelix produces and enforces is an **app contract** derived
from the observed, attributed, causal behavior of one application.

---

## 2. Verified current state (code-grounded, 2026-06-21)

Established by direct inspection of the repo, correcting earlier narrative:

**Built:**
- `pkg/reqcontract/contract.go` — per-request HMAC capability-token carrier (real, well-designed).
- `pkg/causalengine/engine.go` — **on-demand** process-ancestry tracer (ssh/web/cron origin). Stitches parent-process edges *when queried*; stamps nothing per-event; no request/fd/socket/file/DB edges.
- `pkg/contractcompiler/` — compiles a **declared** `appregistry.App` + red zones → kernel artifacts (exec allowlist live; seccomp/AppArmor generated/staged, not armed by default).
- `pkg/redzones/`, `pkg/maintenancechain/`, `pkg/contracthealth/`, `pkg/contractarm/` — red-zone floor, signed time-boxed grants, circuit breaker, armorer.
- `pkg/contractpropose/` — CI **deploy-proposal review store** for human-authored declarations (NOT a synthesizer).
- `pkg/egressguard/backend.go` — backend interface (eBPF / nftables / observe). nftables functional but **global per-host deny**; eBPF backend **scaffold-only**.
- `pkg/appregistry/` — per-app service/cgroup declarations (shallow: no vhost/route/DB-user/schema/Redis-prefix/queue/tenant model).

**Missing (the world-class center):**
- `pkg/workflowchain` — per-event chain stamping & data-flow stitching. **Does not exist.**
- Observation→contract **synthesizer**. **Does not exist.**
- Server-side **L7 root emitters** (`cmd/xhelix-bridge` is a browser native-messaging bridge, *not* an nginx/Envoy/server emitter; no socket-cookie binding).
- **DB/Redis semantic adapters** (table/verb/key truth). **Do not exist.**
- **Per-cgroup, pre-start egress allowlist** compilation.

Summary: enforcement substrate *partial*; request-token carrier *built*; per-app
declaration model *built but shallow*; **recorder, synthesizer, L7 emitters, DB
semantic visibility, per-cgroup pre-start egress = missing.**

---

## 3. The five enforcement layers

Deterministic (low-FP, no learning) → learned (envelope, soak-gated):

1. **Global red zones** — categorically forbidden everywhere; hard-denied at kernel level unless a signed maintenance chain unlocks. Never learnable.
2. **Service-role contracts** — per-service invariants independent of any app BRP. `nginx → /bin/sh` is blocked even with zero app profile. Low-FP because these are *role invariants*, not anomalies.
3. **Per-app causal BRP** — the learned workflow envelope for one application; multi-app per host with attribution splitting.
4. **Egress isolation** — a **separate privileged enforcement plane**; allowlist-first, pre-installed *before* the app starts.
5. **Maintenance chains** — signed, time-boxed, cgroup-scoped unlocks of red-zone actions for known-good operations (deploy, migration, cert renewal, package update).

The app BRP is the brain; layers 1–2 and 4 are the bones. Without the
deterministic layers the system is smart but not hard.

---

## 4. The three-decision-per-event rule (never collapsed)

Every observed event gets three independent determinations:

1. **Boundary** — where did this happen? (is it app-scoped?)
2. **Causality** — what root caused it? (is it chain-scoped?)
3. **Learnability** — may this become "normal"?

```
event_in_scope    = observed by a sensor on the host
event_app_scoped  = matches an app boundary
                    (cgroup, unit, container, vhost, php-fpm pool,
                     DB user/schema, Redis prefix, queue, owned path)
event_chain_scoped= reachable from a root
                    (inbound_request, background_job, queue_message,
                     startup, reload, deploy, maintenance)
event_learnable   = app_scoped
                    AND chain_scoped
                    AND clean_window
                    AND NOT red_zone
                    AND NOT admin_noise
                    AND NOT compromise_window
```

**Worked example — admin noise (must NOT poison the BRP):**
admin shell runs `df -h` → recorded, tagged `root_type: admin_shell`,
`learnable: false`. Never enters the app BRP.

**Worked example — learnable workflow:**
`POST /checkout` → php-fpm → mysql → stripe.com → recorded as
`app_id: shop`, `root_type: inbound_request`, `route: POST /checkout`,
`chain_id: …`, `learnable: true`. Eligible for the BRP after operator review.

Unattributable-in-boundary activity is retained as
`unattributed-shared` / suspicious — **never promoted into the BRP**.

---

## 5. Attribution & boundary model

**Boundary dimensions** (what makes an event "this app's"):
systemd units, cgroups, containers, binaries, php-fpm pools, nginx vhosts,
DB users/schemas, Redis DB/key-prefix, queue/topic, listen ports, unix
sockets, cron/timers, owned paths, secret scopes.

**Shared-service tenant attribution** (must split, never flatten):
`nginx SNI/Host/route → app`, `php-fpm pool/socket → app`,
`DB user/schema → app`, `Redis DB/key-prefix → app`, `queue/topic → app`,
`systemd unit/cgroup → app`. On attribution failure →
`shared-infra` / `unattributed-shared`, `learnable=false`.

**Chain roots:** inbound HTTP/TCP request, background job, queue message,
startup, reload, cron/timer, signed deploy/maintenance, package lifecycle.

---

## 6. Fidelity tiers (the honest kernel-limit boundary)

The kernel alone CANNOT provide SQL table names, app function names, or
decrypted payloads. Every event and every contract dimension therefore
carries a **fidelity** tag so precision is never silently faked:

| Dimension | Coarse (kernel-only) | Precise (adapter-backed) |
|---|---|---|
| DB | connect to `:3306`, bytes | DB user, schema, table, verb, row-shape |
| HTTP egress | dst IP:port, SNI | route, method, host |
| Redis | connect, bytes | DB index, key-prefix, command |
| Files | path, mode, op | (kernel is already precise here) |

A contract whose DB dimension is coarse MUST be marked as such; it does not
claim table-level enforcement it cannot back.

---

## 7. Service-role contracts (deterministic layer)

Per-service, role-based, **not learned**. Example nginx reverse-proxy:

```yaml
service: nginx
role: reverse_proxy
hard_deny:
  exec:   [/bin/sh, /bin/bash, /usr/bin/curl, /usr/bin/wget, /usr/bin/python*, /usr/bin/node]
  write:  [/root/**, /etc/cron*, /etc/systemd/**, /home/*/.ssh/**]
  kernel: [ptrace, bpf, mount, unshare]
  egress: { default: deny }
```

Covers nginx, sshd, mysql, postgres, redis, cron, systemd-resolved, etc.

---

## 8. Per-app BRP (boundary-rich declaration)

```yaml
app: wordpress-site-a
boundaries:
  units:    [nginx.service, php-fpm@site-a.service]
  vhosts:   [site-a.com]
  php_pools:[site-a]
  db:       { mysql_users: [wp_site_a], schemas: [wp_site_a] }
  paths:
    code:    /var/www/site-a/**
    uploads: /var/www/site-a/wp-content/uploads/**
    logs:    /var/log/site-a/**
```

Each app maintains its own BRP, mode, deny ledger, maintenance chains,
egress policy, file policy, child-process policy, DB policy, and causal graph.

---

## 9. Egress isolation plane

Separate privileged plane. **Locked egress is allowlist-first, pre-installed
before app start** (not reactive deny-after-connect — credential exfil
completes before a userspace alert is processed).

```yaml
app: node-api
egress:
  default: deny
  allow:
    - { dns: api.stripe.com, port: 443 }
    - { dns: smtp.provider.com, port: 587 }
    - { cidr: 10.0.0.0/8, port: 5432 }
  deny: [raw_ip_without_sni, unknown_external, secret_tainted_lineage]
```

Enforcement order: cgroup-BPF connect hook → nftables per-cgroup → systemd
IPAddressDeny/Allow. DNS/SNI binding with TTL; raw IP not matching a declared
SNI is blocked even if the IP resolves correctly.

**State locations (trusted enforcement is NOT under a home dir):**
- `/etc/xhelix/egress.d/` — signed policies
- `/var/lib/xhelix/egress/` — compiled state/maps
- `/run/xhelix/egress.sock` — local control socket
- `/var/log/xhelix/egress.log` — audit
- `/home/xhelix-egress` — desktop UI/profile workspace ONLY, never trusted policy

---

## 10. Modes & lowest-FP enforcement rule

**Mode ladder:** `observe → shadow → guarded → locked → sealed`.
Red zones blocked from `guarded` onward; the full learned envelope enforces
only after soak.

**Auto-block ONLY deterministic facts:**
red-zone violation · service-invariant violation · locked-app-contract
violation · secret access outside contract · egress outside allowlist ·
unexpected child binary · persistence write outside a signed maintenance chain.

**Never auto-block soft novelty.** ML/novelty may *rank and cluster*, never
*decide* enforcement.

---

## 11. Clean-window precondition (locked assumption)

The learnability rule excludes `compromise_window`, but xhelix cannot
self-certify that a record window was clean without the very detector it is
building. Therefore, **locked assumption:**

> Record-mode assumes a **trusted clean window** — preferably a
> freshly-provisioned or staging instance under synthetic/e2e traffic. If
> recording on a live host, **layers 1–2 (red zones + service invariants)
> MUST be enforcing during the window** so it is guarded while learning.

A learned BRP is only as trustworthy as the cleanliness of its input window.

---

## 12. Build order & decomposition into sub-projects

This is a **program**, not one implementation plan. Build deterministic
protection FIRST (it is FP-safe, partly built, ships value now, and is the
precondition for safely recording everything else), then the learning system.

**Components, in dependency order:**
1. App Registry v2 — boundaries beyond cgroup (vhost, route, DB user/schema, Redis prefix, queue, path ownership, secret scopes)
2. Root Emitters — server-side L7 roots (nginx/Envoy module or sidecar, app middleware, queue hook, systemd startup root, signed maintenance root)
3. Workflow Chain Engine (`pkg/workflowchain`) — stamp every event: `app_id, chain_id, root_id, root_type, request_id/job_id, phase, learnable, fidelity`
4. Semantic Adapters — MySQL/Postgres/Redis (table/verb/key truth)
5. Recorder — store chain **shapes** (dedup by workflow shape; no infinite raw events); coverage metric
6. Synthesizer — clean observed chain graphs → candidate contract (**hardest component; core R&D**)
7. Compiler — contract → execguard, AppArmor, seccomp/systemd filters, cgroup egress BPF/nftables, FIM, secret policy, DB policy
8. Modes — observe → shadow → guarded → locked → sealed

**Sub-project sequencing:**

| # | Sub-project | Contents | State |
|---|---|---|---|
| **SP-1a** | **Deterministic protection layer (core)** | red-zone wiring + per-cgroup application, service-role contracts (nginx/sshd/mysql/redis invariants), exec-deny, maintenance-chain triggers (deploy/migration/cert/pkg) | mostly wiring + completing; **first to ship** |
| **SP-1b** | **Per-cgroup pre-start egress allowlist** | compile per-app egress allowlist into cgroup-BPF (`egressguard` eBPF backend) + nftables per-cgroup fallback + systemd IPAddressAllow/Deny; DNS/SNI-bound, installed *before* app start | **hardest SP-1 piece; partly missing** (nft is global-deny, eBPF backend scaffold-only) |
| SP-2 | Attribution & chain spine | App Registry v2, L7 root emitters, Workflow Chain Engine | greenfield core |
| SP-3 | Semantic adapters | MySQL/PG/Redis table/verb/key visibility | greenfield, per-engine |
| SP-4 | Recorder + Synthesizer | clean-window record, shape dedup, coverage, contract synthesis | greenfield; the R&D |
| SP-5 | Compiler completion + mode rollout | full compile + shadow→locked promotion + circuit breaker | extends existing |

**SP-1a is the first implementation target.** SP-1b (per-cgroup pre-start
egress) follows as its own cycle — split out because it is the one genuinely
hard, partly-missing piece, so the wiring-heavy SP-1a can land independently.

### Status — 2026-06-24

**SP-1b: DONE.** SP-1b.1 (static CIDR drop-in) + SP-1b.2a (FQDN-at-arm) +
SP-1b.2b.1/.2 (shadow→live grace-windowed refresher) all landed + spike +
live-validated. The eBPF/nftables-per-cgroup path the original SP-1b line item
named is **not needed** — the spike proved systemd drop-in + `daemon-reload`
updates a running cgroup's `IPAddressAllow` live (incl. shrink) on this host.

**SP-1a enforcement: effectively COMPLETE** (a re-grounding, 2026-06-24,
corrected the original "mostly wiring" estimate):
- *exec-deny* — done (SP-1a.1: red-zone exec floor + service-role classifier →
  execguard PolicyHook, scoped per service cgroup).
- *protected-path WRITES* — done via the Tier-2 verify-tier (`pkg/verify`
  PathClassifier + context domains; the 2026-05-23 FP-storm demotion). Adding
  a naive hard write-deny is explicitly the wrong move.
- *protected-path READS* — done via **credbroker** + `ruleset/core/redzones.yaml`
  CEL rules. The BRP runtime *deliberately* excludes reads (`runtime.go:360`:
  "reads of protected paths are handled by credbroker, not BRP"). The unused
  `redzones.ReadZonePrefixes()` Go helper is **dead code**, not a coverage gap
  — wiring it into BRP would duplicate credbroker.

**SP-1a remaining = operability only:** the `xhelixctl maint` CLI (mint/list/
revoke maintenance grants) — grants today are creatable only via the web UI /
Go API. Being built as the SP-1a closing slice (own plan), with grant delivery
via the existing `sweepMaintenanceChains` tick (operator drops a signed grant
file; daemon ingests it ≤1 min). **Deferred** (logged, not building now):
auto-mint triggers (pkg-mgr/deploy → grant; greenfield + privilege surface) and
AppArmor explicit WriteZone-deny (FP-risky, redundant with the verify-tier).

---

## 13. Honest limits (no overstatement)

- Kernel alone cannot know SQL tables or app function names.
- Per-request tracing requires a deployed L7 emitter + reliable socket/request correlation.
- Multi-app shared-service attribution depends on L7/DB adapters.
- Plugin-heavy apps (WordPress) top out at `guarded`; single-purpose apps (static nginx, Go API) reach `locked`/`sealed`.
- The synthesizer (generalization + completeness) is the core, never-fully-finished R&D problem.
- Pure semantic attacks (SQLi via the app's own DB conn), logic abuse within contract, malicious code inside a *declared* dependency, and in-process zero-days over *allowed* channels are **out of kernel-enforcement scope** — they need app-layer semantics (WAF/input validation/query analysis).

**Lock-ceiling per app class:** static nginx 98–99.5% · reverse proxy 95–98% ·
API w/ known deps 90–97% · PHP/Node w/ known plugins 80–95% · WordPress + 3rd-party
plugins 70–90% · dev workstation 50–70%.

---

*Scope locked 2026-06-21. Implementation begins with SP-1a (deterministic
protection layer core); SP-1b (per-cgroup pre-start egress) is its own cycle.
Each sub-project gets its own spec → plan → build cycle.*
