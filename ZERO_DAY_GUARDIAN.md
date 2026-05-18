# xhelix — Zero-Day Guardian Analysis

> Working analysis of the "full-chain causal guardian" thesis for
> application-level zero-day containment, plus external critical
> review and reconciled position.
>
> Companions: [ARCHITECTURE.md](ARCHITECTURE.md),
> [ROADMAP.md](ROADMAP.md), [DEFENSE_PRIORITIES.md](DEFENSE_PRIORITIES.md).

---

## Contents

1. The thesis — "kills the core" position
2. External critical review — verbatim summary
3. Analysis of the review (what's right, what's refined, what's missing)
4. Refined numbers and position
5. Implementation realities the review didn't surface
6. Concrete adjustments to ARCHITECTURE.md and ROADMAP.md
7. Final consolidated position
8. OpenTelemetry as the correlation spine

---

## 1. The thesis — "kills the core" position

### 1.1 What "killing zero-day core" actually means

Two distinct outcomes get conflated under "zero-day kill":

| Type | Meaning | Reality |
|---|---|---|
| Stop the exploit trigger | Prevent the unknown bug from firing | **Not reliably possible** |
| Stop the exploit being useful | Allow the bug to fire; block valuable follow-up | **Very possible** |

The xhelix design targets the second. Every monetisable zero-day
outcome requires one of a small number of follow-up actions. Block
those, and the exploit succeeds technically but yields nothing.

### 1.2 The original "seven outcomes" framing

Every useful zero-day must do at least one of:

1. Read a file the application normally wouldn't touch
2. Spawn a child process
3. Make a network connection to an unexpected destination
4. Issue a SQL query in an unexpected shape
5. Modify application code or persistence
6. Return data the route doesn't normally return
7. Affect another user's data via the same app function

(Revised in §3.2 below — three additional outcomes added.)

### 1.3 The contract-layer mapping

| Useful outcome | Layer that catches it |
|---|---|
| Read unexpected file | OS / eBPF sensitive-file contract |
| Spawn child process | OS / eBPF process-lineage contract |
| Network to unexpected destination | OS / eBPF egress contract |
| Unexpected SQL shape | SQL / query-AST contract |
| Modify app code / persistence | OS / eBPF + integrity contract |
| Unexpected response shape | Response contract |
| Cross-user data access | App-semantic + DB row-ownership contract |

### 1.4 Original aggregate claims

- Most damaging outcomes (RCE, credential theft, persistence, C2):
  ~90-97% contained
- Data-access (SQLi, IDOR, BOLA): ~50-85% depending on app integration
- Business-logic: ~30-60% — needs app cooperation
- Pure compute / response-only: ~20-40% — hardest class

Aggregate: **80-90% of zero-day useful damage contained**.

### 1.5 Why the model is structurally different

- WAFs see request bytes; not what the app did
- EDRs see process events; not which request caused them
- DB firewalls see SQL; not which route / user generated it
- RASPs see app calls; not the OS / DB side effects

Each in isolation: ~30-50% containment because attackers route around
the single layer that's watching.

xhelix binds all layers by `request_id`. Every event carries a causal
anchor. "This SQL ran because of HTTP POST /checkout from user 8821
in request `abc`." That's the chain. Without the chain, every layer
is guessing.

### 1.6 What still escapes (original honest list)

1. **Allowed-behaviour exploitation** — attacker stays inside the
   envelope (e.g. legitimate `/checkout` route, but writes fake order)
2. **Business-logic zero-days** — coupon stacking, refund race
   conditions; chain looks legitimate at every layer
3. **Read-only response leaks** — route returns sensitive data when
   called with correct credentials but by the wrong user

These three classes require *application semantic understanding*,
not OS observation.

---

## 2. External critical review — verbatim summary

The full review was provided by the operator. Key points (preserved
without paraphrase distortion):

### 2.1 Critical verdict (review's own table)

| Question | Honest answer |
|---|---|
| Is the architecture valid? | Yes. Very strong concept. |
| Is it buildable? | Yes, in phases. |
| Is it unique? | The full chain is uncommon. Pieces exist; not unified. |
| Is it performant? | Yes if local enforcement is minimal and off-host analysis is async. No if you inspect everything synchronously. |
| Can it help extremely high-security systems? | Yes, strongly. Especially narrow workloads. |
| Can it become distributed / Kubernetes / Docker aware? | Yes, but a second product phase. |
| Can it stop all zero-days? | No. It makes most damaging post-exploitation actions fail. |
| Biggest difficulty | App semantic integration + DB query/object contracts + policy maintenance. |

### 2.2 Where review agrees with the thesis

- Two-meanings split (trigger vs usefulness) is correct
- `request_id` causal binding is the killer feature
- The seven outcomes model is mostly right (three additions needed)
- For controlled WordPress with strict contracts, the model can reach
  the high-90s on RCE / shell / webshell / persistence / egress / SSRF
- The business-logic and allowed-behaviour gaps are real

### 2.3 Where review pushes back

1. **The percentages are too clean.** The 98% / 95% numbers apply
   only under ideal conditions: perfect route contracts, strict app
   instrumentation, strict DB query contracts, strict egress allowlists,
   no broad admin/update modes, no loose WordPress plugins, low
   dynamic behaviour. General real-world apps reduce all numbers.

2. **DB integration is harder than "parse SQL and done."** Production
   DB behaviour requires:
   - route → query templates
   - role → table access
   - object ownership
   - row count limits
   - write fields
   - transaction state
   - query source
   - prepared statement parameters
   
   A DB proxy can inspect SQL but cannot know business meaning unless
   the app tells it (`this query is for user_id=8821`).

3. **Response contracts are expensive.** Some checks are cheap (size,
   content-type, JSON schema). Others (PII classification, semantic
   correctness, ownership-in-response) are costly and app-specific.

4. **Per-function tracing cannot be always-on at full depth.** Use mode-
   based tracing: training mode = deep, shadow mode = sampled, enforce
   mode = checkpoints, incident mode = temporary deep.

5. **Three more useful exploit outcomes** the original missed:
   - Abuse allowed external API (exfil via email/S3/payment/webhook)
   - Change business state incorrectly (refund/coupon/order/role abuse)
   - Resource exhaustion (CPU/RAM/DB/file upload DoS)

6. **Marketing-heavy claims to tone down**:
   - "Every monetizable zero-day falls into seven buckets" — close
     but incomplete (now ten)
   - "80-90% of zero-days contained" — true only for strict,
     instrumented, narrow workloads
   - "5-10x improvement" — only after measured benchmarks + red team
   - "Strongest publicly designed posture" — too marketing-heavy
   - "No current tool combines this" — mostly true as one product,
     but pieces exist across RASP, WAF, eBPF runtime security,
     DB firewall, service mesh, APM

### 2.4 Performance architecture (the review's clearest contribution)

The review splits the system cleanly:

**Local fast path (synchronous, sub-millisecond):**
- eBPF / WAF / app SDK
- Local event admission
- Local contract cache
- Immediate hard deny only
- Compact event stream
- Local WAL spool
- Forward to Kafka / NATS / collector

**Off-host brain (asynchronous, heavy):**
- Kafka topics
- Stream processors
- State-contract comparison
- Graph builder
- Alert / RCA
- Policy compiler
- Push updated contracts to hosts

**Rule:** Never wait for Kafka to decide whether `/bin/sh` should be
blocked. The host already knows `php-fpm may not exec /bin/sh`. That
must be local.

### 2.5 Event tier model

| Tier | Event type | Handling |
|---|---|---|
| 0 | Known boring events | Aggregate locally |
| 1 | Normal route / file / network events | Compact stream |
| 2 | New path / destination / query | Full stream |
| 3 | Policy violation | Immediate local action + full evidence |
| 4 | Incident mode | Temporary deep capture |

### 2.6 Distributed / k8s / Docker evolution

The review correctly identifies this as a separate product phase:

- Single-host WordPress / PHP first
- Docker / container contracts second (cgroup + namespace tagging)
- Kubernetes node agents + CRDs third (DaemonSet, admission webhooks)
- Distributed trace / contract graph fourth
- Network + DB + app multi-agent fabric fifth

`request_id` becomes `global_trace_id + host_lineage_id + container_id
+ pod_id + service_id + request_id`. OpenTelemetry context propagation
is the right model.

### 2.7 Refined product positioning

The review proposes:

> **xhelix Causal Contract Guardian**
>
> xhelix binds request, application, OS, SQL, network, and response
> behavior into one causal contract, then locally blocks high-risk
> deviations and centrally analyzes the full graph.

---

## 3. Analysis of the review

### 3.1 What the review gets right (adopt directly)

| Review point | Action |
|---|---|
| Local fast + async heavy split | **Adopt.** Add to ARCHITECTURE.md §5 as an explicit principle. |
| Event tier model (0-4) | **Adopt.** Add to ARCHITECTURE.md §5.14 cold-tier section. |
| Three additional useful outcomes | **Adopt.** Update the contract-layer mapping in §1.3 above. |
| Mode-based tracing (training/shadow/enforce/incident) | **Adopt.** Add to ROADMAP.md Phase 5 (UI / operator workflow). |
| Percentages need real benchmarks | **Adopt.** All numbers re-stated as ranges with explicit conditions. |
| "Strongest publicly designed" is too marketing | **Adopt.** Reposition without superlatives. |
| Distributed evolution as separate product phase | **Adopt.** Document as Phase 8+ in ROADMAP.md (currently unscoped). |

### 3.2 The expanded ten-outcome model

The seven outcomes from §1.2 become ten:

1. Read a file the application normally wouldn't touch
2. Spawn a child process
3. Make a network connection to an unexpected destination
4. Issue a SQL query in an unexpected shape
5. Modify application code or persistence
6. Return data the route doesn't normally return
7. Affect another user's data via the same app function
8. **Abuse an allowed external API** (exfil via payment / email / S3 / webhook)
9. **Change business state incorrectly** (refund / coupon / order / role)
10. **Exhaust resources** (CPU / RAM / DB / file upload DoS)

Outcomes 8-10 each map to specific weaker contract coverage:

- **#8**: Per-route external-API contract with payload-class + volume
  limits. Realistic coverage 20-60%.
- **#9**: Application-semantic invariants. Realistic coverage 10-60%
  unless operator writes invariants.
- **#10**: Resource accounting per cgroup + per-request budgets.
  Realistic coverage 30-70% — DoS is a different product area.

### 3.3 Where the review's numbers refine mine

Honest ranges, by attack class, after accepting the review's tone-down:

| Attack class | Original estimate | Refined honest range | Condition for upper bound |
|---|---:|---:|---|
| RCE → shell | 98% | **90-98%** | child-exec deny strict |
| Webshell upload | 97% | **90-99%** | uploads no-exec + file rules |
| Secret file read | 92% | **75-95%** | sensitive-asset catalog precise |
| Unknown egress | 95% | **80-98%** | per-service default-deny egress |
| SQLi data dump | 85% | **50-90%** | DB query-AST contract present |
| IDOR / BOLA | 50-85% | **30-85%** | deep app-semantic integration |
| Business logic abuse | 30-60% | **10-60%** | custom invariants written by operator |
| Allowed-channel exfil | 40% | **20-60%** | per-route payload + action contract |
| Pure in-process exploit | 20-40% | **10-40%** | deep app runtime instrumentation |

The refined ranges are more defensible. The upper bound assumes
fortress-grade implementation; the lower bound is what a typical
operator gets without full instrumentation.

### 3.4 Where I'd push back on the review

1. **"No current tool combines this — mostly true."** The review
   softens this to "pieces exist." I'd hold the line slightly: pieces
   exist as separate products, but no single tool binds them by
   `request_id` and treats the combined graph as authoritative. Cilium
   Tetragon comes closest but is k8s-native and lacks the app-SDK
   integration. The honest claim is: "no current single-host tool
   produces a causally-bound contract graph across these layers."

2. **DB integration is hard, agreed — but the review may overstate
   the architectural change required.** Many production deployments
   could start with MySQL audit-log parsing (read-only, no proxy in
   the data path) and get 70% of the value at 20% of the operational
   cost. Full DB proxy is a v2 step, not a blocker.

3. **The review treats Kubernetes as a clear "yes" for the
   architecture.** I'd be more cautious: PID-namespace traversal,
   per-pod cgroup walking, and CRI-attribution are real engineering
   that adds months. The single-host MVP shouldn't promise k8s
   support until that work is done.

4. **The performance split is correct but the review doesn't quantify
   it.** Local fast path budget: < 500 µs p99. Off-host pipeline can
   tolerate 1-10 seconds. Document this as a hard contract; don't
   leave it implicit.

### 3.5 What both sides missed

The review and my original analysis both glossed over:

1. **App SDK adoption is the gating constraint, not the architecture.**
   The full-chain guardian requires the application to emit semantic
   context (route, user, role, phase, object). For WordPress this
   means a plugin. For Laravel a middleware. For Django a middleware.
   For Node an instrumentation library. **No SDK = no app-semantic
   layer = the contract degrades to OS+SQL+WAF only.** Operators who
   won't install the SDK get 60-70% of the value, not 80-90%. This is
   the single biggest practical risk.

2. **DB proxy is a real architecture change for managed databases.**
   AWS RDS / Cloud SQL / Azure SQL deployments cannot have a proxy
   sidecar in the data path without rearchitecting. For these cases,
   xhelix needs to use DB audit logs (slower, batchable) and accept
   the latency. Document this.

3. **Contract maintenance is the long-term operational cost nobody
   prices in.** Every WordPress plugin update changes legitimate
   behaviour. Every Laravel package adds new routes. The contracts
   need updates with the same cadence as application changes. Realistic
   maintenance: 10-30 minutes per app deployment if contracts are
   structured well; 2-4 hours if they're not.

4. **The "request_id propagation" mechanism is not free in PHP.** PHP
   under FastCGI doesn't natively expose request IDs to children. The
   SDK has to inject via `putenv()` or `$_SERVER` and the eBPF side
   has to read it from `/proc/PID/environ` or via a uprobe on
   `fcgi_handle_request`. Both have caveats. Document the propagation
   model concretely; don't hand-wave it.

---

## 4. Refined numbers and position

### 4.1 The defensible aggregate

For a **strict, instrumented, narrow workload** (e.g. WordPress with
limited plugins, the operator installs the SDK, DB query contracts
active):

- Most damaging post-exploitation outcomes (RCE / shell / persistence /
  C2 / secret read / exfil): **70-90% contained**
- Data-access (SQLi / IDOR / BOLA): **40-80% depending on integration**
- Business-logic and allowed-channel abuse: **10-50% unless operator
  writes invariants**
- Pure compute / in-process exploits: **10-40% — hardest class**

**Weighted aggregate: 60-80% of zero-day useful damage contained, for
fortress-grade deployment on the narrowed product wedge.**

For a **typical operator without full integration** (no app SDK,
no DB proxy, just the OS + WAF layers):

- 40-60% of zero-day useful damage contained.

The original 80-90% claim was the optimistic ceiling, not the
expected outcome. The refined position is honest about both.

### 4.2 Product positioning (revised)

The original framing:

> Stops 80-90% of zero-day damage by binding all layers causally.

The refined framing:

> **xhelix Causal Contract Guardian** binds request, application, OS,
> SQL, and response behaviour into a single causally-anchored graph.
> Verified deviations from declared contract are blocked locally;
> ambiguous patterns become evidence. On a fortress-grade deployment
> with full SDK integration, this materially raises the cost of
> turning a zero-day into a useful outcome — most post-exploitation
> follow-up actions (RCE shell, secret theft, persistence, C2) become
> hard to perform. Business-logic abuse and allowed-channel exfil
> remain residual classes that require app-specific invariants the
> operator declares.

This is defensible. No "100% zero-day proof." No "5-10x improvement"
without benchmarks. No "strongest publicly designed."

### 4.3 What the product is and isn't (sharpened)

**It is:**
- A causal contract enforcement system across five layers
- A fortress for *narrow, declared, controlled* workloads
- An evidence + RCA platform when the contract isn't strict enough
  to enforce
- A foundation that can extend to containers, k8s, and distributed
  service graphs in later phases

**It is not:**
- A WAF replacement (it sits alongside a WAF; uses it as an input)
- An EDR replacement (it doesn't scan for malware signatures)
- A DB firewall replacement (it integrates with one, doesn't replace)
- A guarantee against business-logic flaws
- A defence against kernel exploits in default mode
- A magic box that works without app SDK integration

---

## 5. Implementation realities the review didn't surface

### 5.1 App SDK is the critical adoption point

The single feature that determines whether you get 60% or 80%
containment is whether the operator installs the app SDK. For
WordPress this means a plugin shipping with xhelix that emits:

- Active route + action + hook
- Current user ID, role, session ID
- CSRF / nonce validation result
- Object IDs being accessed
- App phase (validate / query / write / render)

If the plugin is installed: app-semantic layer works. If not: the
guardian degrades to OS + WAF + (optional) DB layer.

**Adoption strategy must account for this.** Make the plugin trivial
to install (`apt install xhelix-wordpress` produces a working
WordPress plugin). Provide a "what you lose without the SDK" doc.

### 5.2 DB proxy vs audit log — two viable paths

For self-hosted MySQL/PostgreSQL on the same machine: xhelix can run
a thin proxy in front (real-time query inspection, ability to block).

For managed databases (RDS / Cloud SQL / Aurora): proxy is impractical.
Use the DB's native audit log (`mysql-audit` plugin / pg_audit) parsed
asynchronously. Trade-off: detection latency ~1-5 seconds, no block
capability, but operationally trivial.

**ARCHITECTURE.md should explicitly document both deployment shapes.**

### 5.3 Request-ID propagation in PHP / FastCGI

The mechanism:

1. WAF / ingress assigns `X-Request-ID` header (UUID)
2. nginx forwards as `HTTP_X_REQUEST_ID` to FastCGI
3. PHP receives via `$_SERVER['HTTP_X_REQUEST_ID']`
4. xhelix WordPress plugin reads it and sets via `putenv()` on its
   own process; xhelix eBPF reads `/proc/PID/environ`
5. SQL queries issued by that PHP request carry the ID in a comment:
   `/* xhelix-trace: req_abc */ SELECT ... `
6. DB proxy / audit log parser extracts the trace ID from the comment

This propagation must be documented exactly. Subtle bugs here corrupt
the causal graph silently.

### 5.4 Contract maintenance burden

Contracts need refresh with the same cadence as app changes. Realistic
estimate for a 50-plugin WordPress site:

- Major WordPress upgrade: 30-60 min of contract review
- Plugin update: 5-10 min per affected plugin
- New plugin install: 15-30 min to baseline its behaviour
- App refactor / feature addition: depends, hours

Operators who don't want this cost should run xhelix in **observe
mode** (evidence collection only, no enforcement). They still get the
audit chain and RCA value without the enforcement maintenance burden.

### 5.5 The "training mode → enforce mode" pipeline

The review correctly notes mode-based tracing depths. The operator
workflow should be:

1. **Install:** xhelix runs in training mode for 7-30 days. Deep
   tracing, no enforcement, evidence stream captures everything.
2. **Generate baseline:** xhelix synthesises proposed contracts from
   observed behaviour. Operator reviews + edits.
3. **Shadow mode:** Contracts loaded but enforcement off. Violations
   logged + surfaced. Operator tunes.
4. **Enforce mode:** Sync deny on hard violations; async contain on
   composite. Continued evidence stream.
5. **Incident mode:** Triggered manually or by alert; switches deep
   tracing back on temporarily.

This four-mode pipeline is the right operator UX. Document in
ROADMAP.md Phase 5.

---

## 6. Concrete adjustments to ARCHITECTURE.md and ROADMAP.md

### 6.1 ARCHITECTURE.md changes

| Section | Change |
|---|---|
| §3 (Design laws) | Add law #9: "Local fast path under 500 µs p99; off-host pipeline async with 1-10 s budget. Never wait on off-host to decide local enforcement." |
| §4 (Architecture diagram) | Show local fast path vs off-host brain split explicitly. |
| §5 (Layer specs) | Add event-tier model (0-4) under §5.14 cold-tier section. |
| §5.14 (Cold tier) | Document both deployment shapes for DB integration: proxy (self-hosted DB) and audit-log parser (managed DB). |
| §6 (Data model) | Add `request_id` propagation contract — exact wire format and PHP/FastCGI mechanism. |
| §8 (Threat model) | Add the ten outcomes (vs original seven). Document the three new classes (external API abuse, business-state, resource exhaustion). |
| §9 (Competitive position) | Soften "no current tool combines this" to "no current single-host tool produces a causally-bound contract graph across these layers." |

### 6.2 ROADMAP.md changes

| Phase | Change |
|---|---|
| New Phase 7 | App SDK distribution (WordPress plugin, Laravel middleware, Django middleware, Node library). Without this phase, the app-semantic layer is unreachable in production. |
| New Phase 8 | DB integration (proxy or audit-log parser, configurable). |
| New Phase 9 | Operator workflow modes (training / shadow / enforce / incident). |
| New Phase 10 | Distributed evolution — container tagging, k8s DaemonSet, CRDs, OpenTelemetry trace propagation. Documented as scoped but not committed for the first ship. |

Original P1-P6 are unchanged. The new phases extend the roadmap from
single-host fortress to full-stack guardian.

### 6.3 DEFENSE_PRIORITIES.md changes

| Section | Change |
|---|---|
| §2 (20-attack table) | Add three rows: external API abuse, business-state abuse, resource exhaustion. |
| §9 (Build order) | Add item 14: "App SDK distribution" between current items 9 and 10. |
| §11 (Priority shifts) | Add shift #8: "App SDK adoption is the gating constraint for the app-semantic layer; treat it as a first-class product surface, not a developer integration." |

---

## 7. Final consolidated position

### 7.1 The honest product description

**xhelix Causal Contract Guardian** is a single-host Linux security
engine that:

1. Binds requests, application semantics, OS behaviour, SQL queries,
   and HTTP responses into a single causal graph anchored by a shared
   `request_id`.
2. Enforces deterministic contracts at each layer with local
   sub-millisecond decisions for hard violations.
3. Streams the full event graph to an off-host brain for heavier
   analysis, baseline refinement, and cross-host correlation.
4. Operates in four explicit modes: training, shadow, enforce, incident.
5. Targets narrow controlled workloads (WordPress / PHP / single-purpose
   APIs / payment portals) first; extends to containerised and
   Kubernetes deployments in later phases.

### 7.2 What it achieves, realistically

On a fortress-grade deployment with full SDK integration and active
DB contracts:

- 70-90% of damaging post-exploitation outcomes contained
- 40-80% of data-access zero-days contained
- 10-50% of business-logic and allowed-channel abuse contained
- Full causal audit trail for everything else, including incidents
  that bypass active enforcement

On a typical deployment (OS + WAF only, no SDK):

- 40-60% of damaging outcomes contained
- Audit trail still valuable for forensics and RCA

### 7.3 What it does not promise

- 100% zero-day proof — impossible by construction
- Protection against kernel exploits in default mode (requires Phase 6
  hardened mode + Secure Boot + IMA + lockdown)
- Defence against business-logic flaws without operator-written
  invariants
- Container or Kubernetes support before Phases 7-10 land
- DDoS, firmware, hypervisor, or supply-chain compromise outside
  the post-exploitation containment scope

### 7.4 Why it's defensible

1. The architecture is technically sound and matches the design
   principles of mature systems (Cilium Tetragon, RASP, OpenTelemetry,
   service-mesh observability), assembled into a single coherent product.
2. The percentages are now stated as ranges with explicit conditions,
   not as marketing-grade single numbers.
3. The residual gaps (business logic, allowed-channel exfil) are
   honestly disclosed and explicitly out of scope for OS-level
   enforcement.
4. The operator-burden trade-off is documented: more contract precision
   = more containment = more maintenance cost.
5. The product evolution path (single-host → containers → k8s →
   distributed) is articulated but not promised; each phase is its
   own commitment.

### 7.5 What we commit to in the locked architecture

No changes to the existing locked architecture (ARCHITECTURE.md). The
adjustments in §6 are additions and refinements; no fundamental
redesign required.

The roadmap extends from 6 phases to 10 phases. P1-P6 remain
unchanged. P7-P10 cover SDK distribution, DB integration, operator
workflow modes, and distributed evolution.

The defense priorities document gets three new attack rows and one
new build-order item.

This document is the authoritative record of the zero-day-kill thesis
analysis. When in doubt about claims, percentages, or scope, consult
sections 4 (refined numbers) and 7 (final position) here.

---

## 8. OpenTelemetry as the correlation spine

### 8.1 Direct verdict

**Use OpenTelemetry, but do not make it the whole system.**

For xhelix Causal Contract Guardian, the right role split is:

| Layer | Tool |
|---|---|
| Correlation spine / trace context / standard telemetry language | **OpenTelemetry** |
| High-volume event transport | Kafka or NATS |
| Long-term event store | ClickHouse / Parquet / object storage |
| Security decision brain | Custom causal graph engine |
| Real-time enforcement | Local BPF / AppArmor / seccomp / nftables |

OpenTelemetry is excellent for end-to-end correlation. It is not
sufficient as the main security event database, the enforcement
engine, or the baseline comparison engine.

### 8.2 Where OpenTelemetry fits well

OTel solves the request-context-propagation problem that xhelix needs:

```
HTTP request enters
  → trace_id created
  → nginx / app / DB / cache / payment all share the same trace_id
  → traces, metrics, logs correlate
```

That is exactly the spine xhelix's per-layer contract enforcement
needs. Use OTel for:

| Need | OTel? | Why |
|---|:---:|---|
| `trace_id` / `span_id` propagation | ✓ | This is one of OTel's strongest areas |
| Application route traces | ✓ | HTTP / DB / messaging semantic conventions exist |
| App SDK instrumentation | ✓ | Mature multi-language ecosystem |
| DB span correlation | ✓ | DB semantic conventions exist |
| Service-to-service tracing | ✓ | Standard distributed tracing model |
| Metrics (CPU, latency, error rates) | ✓ | Stable |
| Application logs | ✓ | Good fit |
| Vendor-neutral export | ✓ | OTLP exports to many backends |
| Collector pipeline (receiver / processor / exporter) | ✓ | Solid plumbing |

### 8.3 Where OpenTelemetry is the wrong choice

OTel is observability, not security enforcement. Do not use it alone
for:

| Need | Why OTel alone is insufficient |
|---|---|
| Real-time blocking | OTel is telemetry; not inline enforcement |
| Kernel-level eBPF event firehose | Spans / logs too heavy for every kernel event |
| Syscall-level policy decisions | Need local BPF / seccomp / AppArmor |
| Signed forensic evidence chain | OTel has no tamper-proof audit by default |
| Causal graph security rules | Traces alone don't carry contract-state |
| Baseline / state-contract comparison | Needs custom state engine |
| Response blocking | OTel observes; cannot block inline |
| High-cardinality raw events | Expensive if every file / socket / syscall becomes a span |
| Strict local fail-closed mode | Collector / backend outage must not affect enforcement |

### 8.4 The architecture

```
                 ┌────────────────────────┐
                 │ OpenTelemetry context  │
                 │ trace_id / span_id     │
                 └────────────┬───────────┘
                              │
       ┌──────────────────────┼──────────────────────┐
       ▼                      ▼                      ▼
 ┌──────────┐           ┌──────────┐           ┌──────────┐
 │ WAF      │           │ App SDK  │           │ DB proxy │
 │ request  │           │ app spans│           │ SQL spans│
 │ span     │           │          │           │          │
 └────┬─────┘           └────┬─────┘           └────┬─────┘
      │                      │                      │
      └─────────┬────────────┴────────┬─────────────┘
                ▼                     ▼
       ┌─────────────────┐    ┌─────────────────┐
       │ xhelix agent    │    │ OTel Collector  │
       │ eBPF events     │    │ OTLP routing    │
       └────────┬────────┘    └────────┬────────┘
                │                      │
                ▼                      ▼
       ┌─────────────────────────────────────────┐
       │ Kafka / NATS event bus                   │
       └────────────────┬────────────────────────┘
                        ▼
       ┌─────────────────────────────────────────┐
       │ xhelix causal graph + contract brain     │
       └────────────────┬────────────────────────┘
                        ▼
       ┌─────────────────────────────────────────┐
       │ Policy compiler → local enforcement      │
       └─────────────────────────────────────────┘
```

OTel is the spine; xhelix is the brain. Local BPF / AppArmor / nftables
are the armed guard at the edge.

### 8.5 Event-class routing

Not every event should be an OTel span. That would blow up cardinality
and cost.

| Event class | Carrier |
|---|---|
| HTTP request | OTel span |
| App route / function phase | OTel span or event |
| DB query | OTel span |
| Outbound API call | OTel span |
| Security violation (verified) | OTel log + xhelix event |
| eBPF normal file_open | xhelix compact binary event (not OTel) |
| eBPF syscall event | xhelix compact binary event |
| Known-good repeating events | Aggregate buckets only |
| Incident-mode evidence | xhelix full event stream |
| Final alert / RCA narrative | OTel log + xhelix alert |

OTel for the request / service / DB layer. xhelix native compact
binary for the kernel firehose. Don't mix them.

### 8.6 Data model — OTel standard + xhelix extensions

Use OTel-standard attributes wherever they exist:

```
trace_id
span_id
service.name
service.version
http.request.method
url.path
http.route
db.system
db.query.summary
network.peer.address
server.address
container.id
k8s.pod.name
```

Add `xhelix.*` namespace for security-specific attributes that aren't
in OTel semantic conventions:

```
xhelix.contract.id
xhelix.contract.version
xhelix.policy.mode
xhelix.lineage.id
xhelix.actor.pid
xhelix.actor.start_time
xhelix.actor.cgroup
xhelix.actor.exe_sha256
xhelix.file.inode
xhelix.file.sensitivity
xhelix.sql.shape_hash
xhelix.response.class
xhelix.verdict
xhelix.violation.type
xhelix.enforcement.action
```

Rule: never overload OTel-standard attribute names with security
meanings. Keep xhelix-specific fields under the `xhelix.*` namespace.

### 8.7 Worked example — one request's data

**HTTP span:**
```json
{
  "trace_id": "a1b2c3",
  "span_name": "POST /checkout",
  "service.name": "wordpress",
  "http.request.method": "POST",
  "http.route": "/checkout",
  "xhelix.contract.id": "wp_checkout_v4",
  "xhelix.user.role": "customer",
  "xhelix.request.mode": "checkout"
}
```

**SQL span:**
```json
{
  "trace_id": "a1b2c3",
  "span_name": "mysql SELECT orders",
  "db.system": "mysql",
  "xhelix.sql.shape_hash": "sha256:991",
  "xhelix.sql.allowed": true
}
```

**eBPF security event:**
```json
{
  "trace_id": "a1b2c3",
  "kind": "file_open",
  "xhelix.actor.pid": 8821,
  "xhelix.actor.exe": "/usr/sbin/php-fpm8.2",
  "xhelix.file.path": "/var/www/site/wp-config.php",
  "xhelix.file.sensitivity": "wordpress_config_secret",
  "xhelix.contract.allowed": false,
  "xhelix.verdict": "blocked"
}
```

Three layers, one `trace_id`, one causal chain.

### 8.8 Storage split

OTel does not force one backend. For xhelix, do not use a normal tracing
backend as the only store — analytical queries are different from
trace viewing.

| Data | Recommended store |
|---|---|
| Traces | Tempo / Jaeger / ClickHouse trace table |
| Metrics | Prometheus / Mimir / VictoriaMetrics |
| App + security logs | ClickHouse / OpenSearch |
| Raw high-volume security events | Kafka → ClickHouse / Parquet |
| Long-term evidence | Object storage + signed index |
| Causal graph hot state | Custom in-memory graph |
| Policy / contracts | SQLite / Postgres / Git-style signed store |
| Alerts / verdicts | Postgres / ClickHouse |

Baseline-comparison queries — "show all new file paths touched by
route=/checkout in the last week" — are columnar-analytic workload.
ClickHouse fits better than a pure tracing backend.

### 8.9 OTel Collector role

The Collector is good as an ingestion / routing layer between apps
and the rest of the pipeline:

```
apps / nginx / DB proxy
  → OTLP
  → OTel Collector
  → processors (sampling, attribute manipulation, redaction)
  → exporters
      → xhelix brain (security events + spans of interest)
      → Kafka (high-volume stream)
      → ClickHouse (analytical store)
      → Prometheus (metrics)
      → trace backend (Tempo / Jaeger)
```

xhelix still needs its own collector for eBPF events because kernel
security events need custom normalisation (canonical paths, ProcKey
identity, source grading, loss accounting) that OTel Collector
processors aren't built for.

### 8.10 OTel vs Kafka vs custom — who owns what

| Requirement | OTel | Kafka / NATS | Custom xhelix graph |
|---|:---:|:---:|:---:|
| Trace propagation | ✓✓✓ | — | needs OTel-like concept |
| App instrumentation | ✓✓✓ | — | harder |
| Standard naming | ✓✓✓ | — | must define |
| High-volume event transport | ✓ | ✓✓✓ | — |
| Raw eBPF event stream | △ | ✓✓✓ | ✓ (local) |
| Real-time enforcement | — | — | ✓✓✓ |
| Baseline comparison | — | — | ✓✓✓ |
| Forensic evidence graph | △ | — | ✓✓✓ |
| Storage / query | — (needs backend) | (retention) | needs backend |
| Distributed correlation | ✓✓✓ | needs keys | yes if trace IDs used |
| Security policy decisions | — | — | ✓✓✓ |

The summary:

- **OTel** for identity and correlation
- **Kafka / NATS** for movement
- **ClickHouse / Parquet** for storage
- **xhelix graph + rule engine** for decisions
- **Local kernel / MAC layers** for enforcement

### 8.11 Distributed / Kubernetes mapping

OTel becomes more important once xhelix extends beyond single-host.
The correlation hierarchy:

| Concept | Scope |
|---|---|
| `trace_id` | Whole distributed request |
| `span_id` | One service operation |
| `xhelix.lineage_id` | Process / request chain on one host |
| `container.id` | Container boundary |
| `k8s.pod.uid` | Pod identity |
| `service.name` | Logical app service |
| `xhelix.contract.id` | Allowed-behaviour policy |

This mapping lives in ROADMAP.md Phase 10 (distributed evolution).

### 8.12 Required xhelix-only fields OTel doesn't cover

Even with full OTel adoption, xhelix needs these fields that OTel
semantic conventions don't natively express:

- `pid + start_time` (ProcKey)
- Process ancestry chain
- Binary hash (sha256)
- cgroup path
- Namespace inodes
- File inode / dev / mount namespace
- Sensitive-file class
- BPF event loss flag
- Kernel event source grade
- Enforcement result
- Contract violation reason

These all live under `xhelix.*` and stay outside the OTel standard
namespace.

### 8.13 Final decision

The right framing is **not** OTel-vs-xhelix. It is:

> **OpenTelemetry-powered xhelix.**
>
> OpenTelemetry carries the causal context.
> xhelix enforces the security contract.

### 8.14 Adjustments to ARCHITECTURE.md and ROADMAP.md

| Doc | Change |
|---|---|
| ARCHITECTURE.md §6 (data model) | Add `xhelix.*` attribute namespace; document OTel field reuse from the standard namespace. |
| ARCHITECTURE.md §5.14 (cold tier) | Document storage split: ClickHouse for analytical queries; Tempo / Jaeger optional for trace viewing. |
| ROADMAP.md Phase 5.5 (operator workflow) | Add training-mode → shadow-mode → enforce-mode → incident-mode workflow with OTel trace replay. |
| ROADMAP.md Phase 10 (distributed) | Specify OTel trace propagation as the inter-host correlation mechanism. |
| DEFENSE_PRIORITIES.md §11 (priority shifts) | Add shift #9: "OTel is the spine, xhelix is the brain — never wait on OTel pipeline for local enforcement." |

These additions extend the locked architecture without modifying it.
The core design is unchanged; OTel is named explicitly as the
correlation transport, and xhelix's own binary event format remains
the kernel-firehose path that OTel is not designed for.

