# Data Leak Containment Fabric (DLCF)

xhelix subsystem for preventing and containing data exfiltration without
firehose recording. Replaces "log everything, detect leaks later" with
**ownership + sensitivity + movement + permission** as first-class
concepts.

> Status: design locked. Implementation tracked in
> `ROADMAP.md` → Phase 7 (DLCF).

## Companion documents

- `ARCHITECTURE.md` — base evidence fabric (events, lineage, chain).
- `ENTERPRISE_ARCHITECTURE.md` — Control Plane / Data Plane split.
- `SUPPLY_CHAIN_DEFENSE.md` — supply-chain attack containment.
- `POST_COMPROMISE_DEFENSE.md` — post-compromise playbook.
- `ZERO_DAY_GUARDIAN.md` — unknown-exploit containment.

DLCF builds on top of the lineage chain delivered in Phase 1 (`pkg/lineage`).

---

## 0. Core rule

> Sensitive data may be read only for a known purpose,
> by a known route/user/service,
> within a known budget,
> and may leave only through an approved valve.

Everything else in this document is mechanism for that rule.

---

## 1. Primitives

| Primitive | Layer | Owns |
|---|---|---|
| **Data Catalog** | control plane | classifies tables/files/columns/secrets and assigns sensitivity points |
| **Route-to-Data Map** | control plane | which API may touch which data |
| **Coarse Taint Ledger** | data plane | which lineage touched which data classes |
| **Sensitivity Budget** | data plane | cumulative points per (lineage / session / user / IP / token / route) |
| **Data Passport** | control plane | signed short-TTL permission to move specific data |
| **Egress Valve** | data plane | destination policy keyed on lineage taint |
| **Export Broker** | service | sole approved path for bulk exports |
| **Canary Rows/Secrets** | data plane | high-confidence detection via planted bait |
| **Watermarking** | broker only | identifies leaker post-hoc |
| **Response Valve** | sidecar (optional) | enforces schema/size/forbidden-field on HTTP responses |

Coarse, not byte-level. Taint is per-lineage, not per-buffer.

---

## 2. Database observation: non-proxy stack

**Do NOT use a full SQL proxy in v1.** Latency-sensitive, ops-heavy,
fragile, per-engine protocol burden.

Instead, four layers:

| Layer | Method | Invasive? | Perf | Gives |
|---|---|---|---|---|
| **A. App DB tap** | wrap framework DB driver (e.g. WordPress `wpdb` drop-in) | low | very low | route, user, query shape, row count |
| **B. DB-native digest** | MySQL `events_statements_summary_by_digest`, PostgreSQL `pg_stat_statements` | none | low | normalized query fingerprints + counts |
| **C. eBPF DB watcher** | observe process → DB socket bytes, no SQL parsing | very low | very low | which process talked to DB, volume, timing |
| **D. Selective audit plugin** | DB engine audit, **only** for sensitive tables/users | medium | medium | accountability for risky access |

Layer C uses an existing socket+process eBPF probe (already on the
roadmap for Phase 3); only labels DB endpoints from config.

Layer A is the killer: the application already knows the route, user,
plugin, action, and result row count. Capturing those four fields at
the app DB-call site is cheaper and more useful than reconstructing
them from wire traffic.

### What to capture in the app DB tap

| Field | Example |
|---|---|
| `request_id` | `req_abc123` |
| `route` | `/wp-json/wc/v3/orders` |
| `user_id` | `8821` |
| `role` | `admin` |
| `plugin/action` | `woocommerce_checkout` |
| `query_shape_hash` | sha1 of normalized SQL |
| `tables` | `wp_users`, `wp_posts` |
| `operation` | `SELECT` |
| `rows_returned` | `1 / 20 / 10000` |
| `duration_ms` | `12` |
| `sensitivity_score` | derived from catalog |

Store the **shape** (`SELECT * FROM wp_users WHERE id = ?`), never
the bound values. Values are PII risk and storage burden.

### What eBPF should NOT do

| Task | Why not |
|---|---|
| full SQL parsing | fragile |
| prepared-statement reconstruction | hard |
| TLS DB traffic parsing | not visible |
| business-ownership rules | needs app context |
| row semantics | needs DB + app layer |

eBPF answers **"who talked to the DB and how much"**; the app tap
answers **"what did they ask for and what came back"**.

### Coverage without SQL proxy

| Attack | App tap | DB digest | eBPF | Protection |
|---|:-:|:-:|:-:|---:|
| `php-fpm → mysqldump` | maybe | no | **yes** | 95%+ |
| webshell connects DB | maybe | yes | **yes** | 90–98% |
| SQLi broad dump | **yes** | **yes** | yes | 75–90% |
| route reads forbidden table | **yes** | yes | no | 75–90% |
| huge result from sensitive table | **yes** | partial | yes | 70–90% |
| slow low-volume DB leak | yes | yes | partial | 50–75% |
| IDOR same shape wrong object | partial | no | no | 30–60% (needs app ownership) |
| business logic leak | partial | no | no | 20–50% (needs semantics) |

The last two rows are honest gaps; SQL proxy wouldn't close them
either without app cooperation.

---

## 3. The Coarse Taint Ledger

Reuses the lineage chain delivered in P1.4. Each `lineage.Origin`
gains a `TaintSet` field — the set of data classes the lineage has
touched.

```go
// pkg/lineage/taint.go  (P7.2)
type DataClass string
const (
    ClassPII           DataClass = "pii"
    ClassCredentials   DataClass = "credentials"
    ClassPaymentToken  DataClass = "payment_token"
    ClassCustomerOrder DataClass = "customer_order"
    ClassAPIKey        DataClass = "api_key"
    ClassSourceCode    DataClass = "source_code"
    ClassBackup        DataClass = "backup"
    ClassCanary        DataClass = "canary" // highest priority
)

type TaintSet uint64 // bitset, ~64 classes max
```

Propagation: when an admitted event tagged with a sensitive data class
flows through the dispatch loop, OR its `TaintSet` into the originating
lineage's record. Propagation is **append-only** — taint never clears
inside a lineage's lifetime.

Cost: one atomic-OR per sensitive event, ~50 ns.

---

## 4. Sensitivity Budget

Per-bucket cumulative counter. Buckets are short-lived (default
1 h sliding window, 24 h hard cap).

```yaml
# config: ruleset/dlcf/budgets.yaml
budgets:
  - key: "user_id:{user_id}+route_group:customer_data"
    max_sensitive_points_per_hour: 500
    max_sensitive_points_per_day: 2000
  - key: "lineage:{lineage_root}"
    max_sensitive_points_per_hour: 1000
  - key: "route:{route}"
    max_sensitive_points_per_request: 100
```

Points table is part of the Data Catalog:

| Data touched | Points |
|---|---:|
| public post title | 1 |
| product info | 2 |
| user email | 20 |
| phone/address | 40 |
| password hash | 100 |
| payment token | 300 |
| API key / secret | 1000 |
| canary | ∞ (always alert) |

Slow-exfil that flies under per-request limits hits the per-hour
cumulative.

---

## 5. Data Passport

A signed, short-TTL capability token issued by the Control Plane.

```yaml
data_passport:
  id: export_2026_001
  issued_at: 2026-05-19T14:00:00Z
  expires_at: 2026-05-19T14:10:00Z   # hard 15-min cap
  actor: admin_user_91
  route: /admin/export/orders
  data_class: [customer_order, customer_email]
  max_rows: 5000
  max_bytes: 50MB
  destination: browser_download
  reason: "monthly finance export"
  approved_by: operator_id_12
  signature: ed25519:...
```

xhelix verifies the signature against the Control Plane's pubkey (same
key infra used by the chain in P0/P1) and enforces every field at the
Egress Valve and Export Broker. **No passport → no bulk movement.**

---

## 6. Egress Valve

Extends `pkg/netban`. Becomes taint-aware:

```text
on outbound connect:
  lineage_taint = lookup(lineage_id)
  if lineage_taint != ∅:
    require: destination matches passport for that taint set
    else: block + alert
```

Free at runtime — already on the netban hot path.

---

## 7. Export Broker (separate daemon)

`cmd/xhelix-exportd/` — a small daemon, Unix-socket IPC, that is the
**only** process permitted to:
- run `SELECT` queries against bulk tables,
- read backup files,
- create archives of source/data,
- upload to approved destinations.

Every export requires:
- valid Data Passport
- approval ticket
- short TTL (≤ 15 min)
- row/byte limits enforced inline
- output watermarked (CSV row order, unique whitespace, manifest sig)
- signed audit entry in the chain

Other processes (php-fpm, nginx, node) are denied these paths by
policy + LSM hooks.

---

## 8. Canary Rows / Secrets

Plant fake data that must never be read:
- canary customer (`xhelix-canary-user@example.com`)
- canary API key (recognisable prefix `xc-canary-…`)
- canary file (`/var/lib/xhelix/canary/.do-not-touch`)
- canary backup (`/srv/backups/canary-2024.tar.gz.fake`)

A rule fires the moment a canary appears in:
- DB result (via app tap → `tables.row_contains_canary`)
- file read (via eBPF file_open)
- outbound bytes (via netflow → string match)
- archive contents (via export broker)

Near-zero false-positive rate. This is the cheapest, highest-confidence
detection in the entire fabric.

---

## 9. Response Valve (optional, sidecar)

Only viable inside `xhelix-bridge` (the existing HTTP-tier
companion). For critical endpoints:

```yaml
/api/user/profile:
  max_objects: 1
  allowed_fields: [id, name, email]
  forbidden_fields: [password_hash, api_key]
  max_bytes: 32KB
```

Out of scope for non-bridge deployments.

---

## 10. Architecture diagram

```text
                 ┌──────────────────────┐
                 │ Data Catalog          │
                 │ tables/files/secrets  │
                 │ + sensitivity points  │
                 └──────────┬───────────┘
                            │
HTTP/API → App DB Tap ──────┤
                            ▼
┌──────────────┐    ┌───────────────────┐    ┌──────────────────┐
│ eBPF DB flow │ →  │ Coarse Taint      │ ←  │ DB native digest │
│ pid/bytes    │    │ Ledger (lineage)  │    │ perf_schema/pgss │
└──────────────┘    └─────────┬─────────┘    └──────────────────┘
                              ▼
              ┌─────────────────────────────┐
              │ Sensitivity Budget counters │
              │ + Data Leak Rules engine    │
              └─────────────────────────────┘
                              ▼
        ┌──────────────┬──────┴───────┬──────────────────┐
        ▼              ▼              ▼                  ▼
  Response Valve  Egress Valve  Export Broker     Alert / Audit
  (xhelix-bridge) (netban+taint) (passport gate)   (signed chain)
```

---

## 11. Performance budget (steady state)

| Component | Cost per event |
|---|---|
| Catalog lookup (hash) | ~50 ns |
| Taint propagation (atomic-OR) | ~100 ns |
| Sensitivity counter (atomic-add into bucket) | ~200 ns |
| Egress Valve taint check | ~1 µs (already on netban path) |
| Canary rule (CEL match) | sub-µs |
| Export Broker | only on export, not steady state |
| Response Valve | 10–50 µs/response (sidecar only) |

Total kernel/event-tier cost: **< 500 ns per event**. The expensive
parts (DB proxy, Response Valve) are deferred or scoped to a sidecar.

---

## 12. Implementation phases

See `ROADMAP.md` → Phase 7. Summary:

**P7 v1 — cheap tier (~5 weeks):**
1. Data Catalog (YAML schema + loader)
2. Coarse Taint Ledger (extend `pkg/lineage`)
3. Sensitivity Budget counters + LocalAPI surfacing
4. Canary rules pack (~10 detectors)
5. Egress Valve taint-aware extension to `pkg/netban`
6. Data Passport issuance + ed25519 verification

**P7 v2 — DB observation (~3 weeks):**
7. eBPF DB socket watcher (label endpoints from catalog)
8. MySQL/Postgres native digest poller
9. WordPress `wpdb` drop-in tap (reference implementation)
10. App DB tap protocol (route/user/query-shape/rows over Unix socket)

**P7 v3 — broker tier (~3 weeks):**
11. `cmd/xhelix-exportd/` daemon
12. Watermarking
13. DB role posture lint (advisory)
14. Selective DB audit plugin integration

**Deferred / opt-in:**
- Response Valve (only if `xhelix-bridge` is in path)
- Full SQL proxy (NOT planned)

---

## 13. What v1 deliberately does NOT do

- Full SQL parsing in the kernel.
- Full HTTP response inspection without bridge.
- Byte-level memory taint tracking.
- Per-row capture (we keep shape + count, never values).
- Always-on DB audit of every statement.
- IDOR ownership without app-supplied object IDs.
- Business-logic leak detection without semantics.

These are honest gaps. The fabric still raises attacker time-to-success
by orders of magnitude against the realistic exfil patterns
(`mysqldump`, archive + outbound, slow drip, webshell DB read, broad
`SELECT *`, backup theft).

---

## 14. Trust boundaries

| Boundary | Trust |
|---|---|
| App DB tap → xhelix | medium — app process can lie; xhelix corroborates with eBPF + DB digest |
| eBPF DB watcher | high — kernel-side, attacker-resistant |
| DB native digest | high — read-only DB introspection |
| Data Catalog | operator-authored, signed |
| Data Passport | strong — ed25519, short TTL, single use |
| Egress Valve | high — kernel hook (LSM/netfilter) |
| Export Broker | strong — separate uid, separate cgroup, separate creds |

The app DB tap is deliberately the **least** trusted layer. If the app
is compromised it may suppress or falsify tap events, which is exactly
why eBPF and DB digest exist as corroboration. Disagreement between
the three is itself a signal.

---

## 15. Open questions

1. Catalog format: YAML only, or auto-discovery via DB introspection +
   operator confirmation?
2. Budget storage: in-memory ring + periodic SQLite snapshot, or
   straight to SQLite with prepared statements?
3. Passport issuance UX: CLI-only in v1, or web UI in xhelix-bridge?
4. Watermark scheme: deterministic per-export (forensic) or
   non-deterministic (harder to strip)?
5. Canary placement: per-database operator workflow, or shipped
   migration helpers?

Decide before P7 v2.
