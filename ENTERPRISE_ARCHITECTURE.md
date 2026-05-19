# xhelix — Enterprise Architecture (Revised)

> Revised architecture incorporating the critique of the original
> enterprise design. Adds Control Plane / Data Plane split, promotes
> the flight recorder to a core component, requires curated plugin
> exception library, formalises mode-transition security, and
> specifies the operator workflow as first-class.
>
> Companions: [ARCHITECTURE.md](ARCHITECTURE.md),
> [ROADMAP.md](ROADMAP.md), [DEFENSE_PRIORITIES.md](DEFENSE_PRIORITIES.md),
> [ZERO_DAY_GUARDIAN.md](ZERO_DAY_GUARDIAN.md),
> [SUPPLY_CHAIN_DEFENSE.md](SUPPLY_CHAIN_DEFENSE.md).

---

## Contents

1. Design law (one-line summary)
2. Revised topology — Control Plane + Data Plane
3. Flight recorder as core architecture
4. Plugin exception library (curated profiles)
5. Per-API protection-level auto-categorisation
6. Mode-transition security
7. DB integration levels (L0–L5)
8. Response contract levels (cheap vs expensive)
9. Trust Boundary Map
10. Failure modes — explicit behaviour
11. Day-1 bootstrap problem
12. Operator workflow as first-class
13. Multi-tenant / multi-app
14. Contract diff workflow
15. Honest naming of intelligence in the pipeline
16. Revised product strategy
17. Mapping back to ARCHITECTURE.md and ROADMAP.md

---

## 1. Design law

> **Facts are cheap. Alerts are expensive. Blocking is sacred.**

| Tier | Meaning |
|---|---|
| Fact | Something happened |
| Candidate | Maybe risky; investigate later |
| Alert | Verified contract violation |
| Block | Clearly forbidden or high-confidence dangerous |

Never: high-load → alert. Never: new-behavior → block. Never:
ML-suspicion → kill. The blocking decision is always:

> forbidden actor + forbidden action + sensitive target + wrong mode +
> complete causal proof = enforcement

## 2. Revised topology — Control Plane + Data Plane

```
xhelix Control Plane
  ├─ contract learning engine
  ├─ human review workflow
  ├─ plugin exception library
  ├─ policy compiler
  ├─ signed policy store
  ├─ mode manager
  ├─ contract diff viewer
  └─ exception ledger

xhelix Data Plane (per host)
  ├─ WAF / request sensor
  ├─ app SDK / plugin
  ├─ OS / eBPF / AppArmor / seccomp sensor + enforcer
  ├─ DB sensor / proxy
  ├─ response checker
  ├─ local contract engine
  ├─ local flight recorder
  └─ local safe enforcement engine
```

**Rule**: local enforcement must continue without the control plane.
Control plane delivers signed policies; data plane caches them and
operates standalone on the cached set until the next signed update.

## 3. Flight recorder as core architecture

Promoted to top-level component. Every alert must carry:

- Previous 30–120 seconds of high-resolution context
- Request context (route, user, role, mode, request_id)
- Process lineage from root (origin → child)
- File / network / SQL events in the window
- Mode state at time of event
- Policy version active when event occurred
- Why the rule fired or why it was suppressed

Implementation: bounded in-memory ring buffer per host, sized to the
agent's memory budget. On a verified violation, flushed to the
audit chain. Otherwise overwritten in place.

This is what makes the system feel trustworthy. Without the flight
recorder, an alert is a fact in isolation; with it, an alert is a
self-contained story.

## 4. Plugin exception library (curated profiles)

Required for WordPress and similar plugin-heavy apps. xhelix ships
with a library of profiles for popular plugins. Operators pick which
to enable.

Example profile:

```yaml
plugin: updraftplus
category: backup
allowed_mode: backup
allowed_reads:
  - wp-content/**
  - database_dump
allowed_network:
  - approved_backup_destinations
denied:
  - unknown_shell
  - unknown_destination
  - persistence_write
requires:
  - operator_backup_mode
  - time_limit
```

Required catalog at v1 launch (~30 profiles):

| Category | Plugins covered |
|---|---|
| Backup | UpdraftPlus, BackupBuddy, BackWPup, Duplicator |
| Security | Wordfence, Sucuri, iThemes |
| SEO | Yoast, Rank Math, AIO SEO |
| Cache | WP Rocket, WP Super Cache, W3 Total Cache |
| Image | Smush, ShortPixel, EWWW |
| Forms | WPForms, Contact Form 7, Gravity Forms |
| E-commerce | WooCommerce + key extensions |
| Membership | MemberPress, Restrict Content Pro |
| Page builders | Elementor, Beaver, Divi |
| Migration | All-in-One WP Migration, WP Migrate |

Plugins not in the curated library run in observation mode by default.
The operator either accepts the auto-derived contract after a review
window or remains in observation indefinitely.

## 5. Per-API protection-level auto-categorisation

Manual L0–L5 tagging of 200+ WordPress routes is impractical. Use
pattern-based defaults; operators override exceptions only.

| Pattern | Default level |
|---|---|
| `/wp-admin/*` | L3–L4 |
| `/wp-login.php` | L4 |
| `/wp-json/wp/v2/users*` | L3–L4 |
| `/wp-json/wp/v2/settings*` | L4 |
| `/wp-json/wc/*/orders*` | L3–L4 |
| `/wp-json/wc/*/customers*` | L3–L4 |
| `/wp-json/*` other (public read) | L1–L2 |
| `/wp-content/uploads/*` | L2 |
| `/?p=*` and other public pages | L1 |
| `admin-ajax.php` action unknown | L2–L3 until classified |
| Plugin update / install routes | special update mode |

Defaults must be excellent. Operators touch them rarely.

## 6. Mode-transition security

Mode entries disable enforcement rules. They must be treated like
privileged actions.

**Update-mode entry requirements**:

- Explicit operator action through the local API
- `SO_PEERCRED` uid match against an authorised set
- Signed audit-chain entry recording who, why, when, scope
- Visible UI banner while active
- Hard TTL cap (default 10–15 minutes)
- No auto-extension; expiry returns to enforcement
- Exact scope: site / plugin / service
- Reason text required
- All file changes during the window recorded

Example operator command:

```
xhelix mode enter update \
  --site example.com \
  --plugin woocommerce \
  --ttl 10m \
  --reason "approved plugin update"
```

Every suppressed alert during the window must annotate "allowed only
because update mode was active for scope X." Operators can audit later.

## 7. DB integration levels (L0–L5)

Do not start with "full business DB intelligence." Use levels.

| Level | What it does | Feasibility |
|---|---|---|
| **DB-L0** | No DB integration | Easy |
| **DB-L1** | Query digest / table / row-count summary | Medium |
| **DB-L2** | Route → query-shape mapping | Medium-hard |
| **DB-L3** | Table / field allow-lists per endpoint | Hard |
| **DB-L4** | Object ownership / user-row rules | Very hard |
| **DB-L5** | Transaction / business invariants | App-specific |

**v1 commitment**: DB-L1 + DB-L2 for critical endpoints only. L3+
deferred to post-v1 when operators ask.

## 8. Response contract levels (cheap vs expensive)

Response inspection cost varies massively. Split into two tiers.

**Cheap, always-on for every response**:

| Check | Cost |
|---|---|
| Status code | Low |
| Content-type | Low |
| Response size | Low |
| Route response class (e.g. JSON vs HTML expected) | Low |
| Secret-pattern regex (PRIVATE KEY, API_TOKEN, …) | Medium |
| JSON schema for critical APIs | Medium |

**Expensive, only for high-risk endpoints**:

| Check | Cost |
|---|---|
| PII classification (names, emails, SSNs, payment numbers) | High |
| Object ownership in response | High |
| HTML semantic correctness | Very high |
| Full body scanning for every route | Too expensive |

**Routing**:
- Public page → size + content-type only
- Login / auth → schema + secret regex
- Admin / export → strict response contract
- Checkout / payment → schema + value rules

## 9. Trust Boundary Map

| Component | Runs as | Trust level |
|---|---|---|
| nginx / WAF module | nginx user (root at startup) | Medium |
| PHP / WordPress plugin | `www-data` | Low |
| xhelix agent | Root / privileged service unit | High |
| eBPF loader | Root / `CAP_BPF` | High |
| Policy compiler | Control plane | High |
| Local enforcer | Root | High |
| UI / dashboard | Separate user / service | Medium |
| Kafka / ClickHouse | Separate server / network segment | Medium |
| Signing key (chain + policy) | Offline or hardened control plane | Highest |

**Rule**: the WordPress / PHP plugin may *provide* context to enrich
events, but must not be trusted as *authority*. If PHP is compromised
it can lie. Enforcement decisions must be verifiable from OS facts.
App context biases enrichment; it does not bypass OS evidence.

## 10. Failure modes — explicit behaviour

| Failure | Correct behaviour |
|---|---|
| Control plane unreachable | Continue with last signed policy |
| Kafka / downstream down | Local enforcement continues; local spool buffers |
| Spool full | Drop low-value facts; keep violations |
| DB proxy crashes | Fail-open or bypass per configured level |
| Agent OOM | Watchdog restart; AppArmor / seccomp / nft rules stay active |
| Policy update broken | Rollback to last known-good signed policy |
| Plugin update changes many routes | Auto shadow-mode + contract diff |
| eBPF event loss | Mark telemetry degraded; never silently overclaim |
| Clock skew across cores | Use lineage / order; do not trust timestamps alone |
| Audit-chain signing key unavailable | Refuse to write new chain entries; alert loudly |

All of the above must be documented operator-facing behaviour, not
implementation detail.

## 11. Day-1 bootstrap problem

A fresh install has no baseline. The system must not be "allow all"
or "block all" on day one.

**Day-1 hybrid mode**:

Universal hard blocks enabled immediately:
- No shell from PHP
- No PHP execution in uploads
- No writes to persistence paths
- No reads of root secrets
- No dangerous syscalls

App-specific behaviour in learning mode for 7 days:
- DB query shapes
- Response shapes
- Plugin behaviour
- Route categories
- Outbound destinations beyond the universal allow-list

Day 1 protects against the worst attacks before any baseline exists.
Day 8+ adds the app-specific contracts once they're stable.

## 12. Operator workflow as first-class

The violation screen is where operators will live. Design it as
carefully as the kernel layer.

**Required UI elements per violation**:

```
What happened:
  php-fpm tried to execute /bin/sh

Why it was blocked:
  WordPress runtime policy forbids child shell spawn

Causal chain:
  POST /wp-admin/admin-ajax.php?action=do_thing
  user: admin (uid 1001, ssh from 1.2.3.4)
  php-fpm pid 8821, started 14:22:01
  attempted exec /bin/sh

Context (previous 60 seconds):
  changed files: /var/www/uploads/img.jpg
  outbound attempts: none
  SQL queries: SELECT wp_users WHERE login=...
  mode state: normal

Options:
  [ keep blocked ]
  [ approve once (single event, no rule change) ]
  [ approve for this plugin for 10 minutes ]
  [ create scoped exception (reviewed) ]
  [ enter update mode (if applicable) ]
```

**Forbidden UI patterns**:
- "Allow forever" button
- "Approve for all routes" button
- "Ignore this rule" without scope

**Required UI patterns**:
- Every approval names exactly which actor, action, target, mode,
  destination is being allowed
- Every approval has a TTL with operator-set duration (default short)
- Every approval becomes a ledger entry in the signed audit chain

## 13. Multi-tenant / multi-app

If one host runs three WordPress sites under different cgroups,
contracts must be per-site, not only per-host.

Identity hierarchy:

```
tenant_id
site_id
service_id
cgroup_id
document_root
php_fpm_pool
unix_user
policy_version
```

Site A's `php-fpm` pool may write `/var/www/siteA/uploads`. Site B's
pool may write `/var/www/siteB/uploads`. Site A must never read
Site B's files, even though both run on the same host.

This is a significant selling point for hosting providers and
container hosts.

## 14. Contract diff workflow

After every plugin update, operator must see what changed:

```
Plugin: woocommerce
Old version: 9.4.2
New version: 9.5.0

Behavioural delta:
+ plugin now connects api.newvendor.com
+ plugin writes wp-content/cache/newdir
+ plugin adds admin-ajax action `wc_new_handler`
+ plugin queries `wp_users` (new in this version)
- plugin no longer reads `wp-content/old-config.php`

Accept into contract?
  [ accept for this version only ]
  [ accept for 24 hours ]
  [ shadow-mode for 7 days then auto-accept stable ]
  [ block / revert to old version ]
```

Without this workflow, operators stop reviewing and start
auto-approving. With it, the work scales: 5 minutes per plugin update,
operator only reviews the diff, not the full contract.

## 15. Honest naming of intelligence in the pipeline

> Deterministic rules at the enforcement boundary; intelligence
> everywhere before it.

| Layer | Nature | Acceptable to use ML / heuristics? |
|---|---|---|
| Contract suggestion engine | Rule induction over observed behaviour | Yes — supervised classification + heuristics |
| Contract diff review | Pattern matching over deltas | Yes |
| Anomaly scoring (display only) | Heuristic / statistical | Yes — display only, never gate |
| Policy compiler | Symbol transformation | No — fully deterministic |
| Rule evaluator | Predicate matching | No — fully deterministic |
| Enforcement decision | Hash-table lookup against compiled rules | No — fully deterministic |

Product positioning:

> xhelix uses machine learning to understand your application's normal
> behaviour, then converts that into deterministic rules that are
> enforced without further model evaluation. The blocking decision is
> always a hash-table lookup, never a model inference.

This is honest. It is defensible. It is also accurate.

## 16. Revised product strategy

Do not build "all apps, all layers, full intelligence" first.

**v1 — xhelix WordPress Runtime Guardian**:

| Feature | Reason |
|---|---|
| PHP no-shell / no-exec | Highest value |
| Upload PHP blocker | Highest value |
| Read-only code / update mode | High value |
| Sensitive file guard | High value |
| Outbound allowlist | High value |
| Local flight recorder | Trust / RCA |
| Plugin profile library (30 profiles) | Adoption |
| Contract diff after updates | Usability |
| Local SQLite event store | Lightweight |
| AppArmor / systemd / nftables generator | Native enforcement |

**v2 — Extensions**:
- Route categories with auto-defaults
- DB query shape contracts (DB-L1 + L2)
- Response contracts (cheap tier)
- Remote control plane
- Multi-tenant support

**v3 — Distributed**:
- Docker container contracts
- Kubernetes DaemonSet + CRDs
- Distributed trace correlation
- Cross-host fleet view

## 17. Mapping back to ARCHITECTURE.md and ROADMAP.md

| New section here | Adjustment to existing doc |
|---|---|
| §2 (Control / Data Plane split) | Update ARCHITECTURE.md §4 diagram |
| §3 (Flight recorder as core) | Promote in ARCHITECTURE.md §5; add as first-class component |
| §4 (Plugin library) | New ROADMAP.md phase 5.5 (Curation Workstream) |
| §5 (Auto-categorisation) | Update DEFENSE_PRIORITIES.md §6 (the L0–L5 ladder) |
| §6 (Mode-transition security) | Add to ARCHITECTURE.md §5.13 |
| §7 (DB levels) | Replace single "DB integration" item in ROADMAP.md P8 with five sub-tasks (L0–L5) |
| §8 (Response levels) | New section in ARCHITECTURE.md §5; same split |
| §9 (Trust map) | New section in ARCHITECTURE.md §8 (threat model) |
| §10 (Failure modes) | New section in ARCHITECTURE.md §8 |
| §11 (Day-1 hybrid) | New section in ROADMAP.md P9 (operator workflow) |
| §12 (Operator workflow) | Refine ROADMAP.md P5 with explicit violation-screen design |
| §13 (Multi-tenant) | New section in ARCHITECTURE.md §5; add to ROADMAP.md P7 |
| §14 (Contract diff) | New ROADMAP.md task in P9 (operator workflow) |
| §15 (Intelligence naming) | Update product-positioning section across all docs |
| §16 (v1 / v2 / v3 strategy) | Replace generic "phases" with explicit product-version mapping |

These adjustments extend the locked architecture without changing
its design laws or the canonical data model.

## 18. Final verdict

The architecture is enterprise-grade if and only if:

- Contract lifecycle is designed as a real system (proposal → review → approval → version → rollback)
- Plugin exceptions are a curated library, not operator burden
- Mode security is first-class with hard caps
- Trust boundaries are explicit
- Failure modes are documented
- Operator workflow is designed with the same rigor as the kernel layer
- Intelligence is honestly labelled where it lives

The most important correction is in product positioning:

> Sell "xhelix learns behavior, proposes contracts, and enforces
> approved deterministic rules" — not "AI blocks attacks."

That is realistic, defensible, low-noise, and safer.
