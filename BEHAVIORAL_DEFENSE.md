# Behavioral Defense — handling valid-looking attacks

xhelix subsystem for detecting attacks that **carry valid credentials,
emit valid HTTP requests, and pass the perimeter unchanged**. The
target threat class is the one that causes ~60–80% of real-world
breaches per Verizon DBIR and similar: stolen credentials, session
hijack, post-auth abuse, insider misuse, supply-chain-as-user.

> Status: design locked. Implementation tracked in
> `ROADMAP.md` → Phase P-RC and Phase P-BEHAVIOR.

## Companion documents

- `ARCHITECTURE.md` — base evidence fabric.
- `DATA_LEAK_FABRIC.md` — DLCF (catalog + taint + budget + passport + canary).
- `POST_COMPROMISE_DEFENSE.md` — playbook once an attacker is inside.
- `ENTERPRISE_ARCHITECTURE.md` — Control Plane / Data Plane split.

---

## 0. The hard truth (this sets every other claim in the document)

**100% detection with zero false positives is mathematically impossible
against truly valid-looking attacks.** By construction, the attacker
is using a real credential to perform an action the user is authorised
to take. The events they emit are byte-identical to events a real user
would emit. No detection technique can separate them with certainty.

What IS possible:

1. **100% detection of cryptographic / policy facts** — "passport
   missing", "nonce replayed", "canary touched". These are deterministic:
   the fact either holds or it doesn't. Zero false positives by
   construction.

2. **100% detection of causal-chain divergence** — if the request looks
   valid but the downstream lineage doesn't match the route's baseline,
   the request produced an outcome it shouldn't have. Near-zero FP
   in steady state; FP spikes after legitimate code changes until
   re-baselined.

3. **Statistical detection of behavioral anomaly** — useful but
   non-zero FP. Used as score contributors, never as standalone hard
   blocks.

4. **100% containment via evidence chain post-action** — even when
   prevention fails, the signed audit chain reconstructs exactly what
   happened, by whom, in what order. Containment is the floor; the
   detection techniques above raise the ceiling.

The product positioning that follows from this:

> xhelix does not promise to prevent every attack. It promises to
> **detect every fact** that a policy says must be detected, and to
> **reconstruct every action** that occurred. Probabilistic detectors
> exist only to *score* events, never to *decide* against the user.

If a vendor promises 100% detection of valid-looking attacks, they are
either lying or shipping a system that ground operators to dust with
false positives in 30 days. xhelix will not be that.

---

## 1. Threat model: what counts as "valid-looking"

| Attack class | Credential? | Request shape | Pre-action signature? |
|---|---|---|---|
| Stolen password | real | normal login | none |
| Stolen session cookie | real | normal API call | none |
| Stolen API key | real | normal API call | none |
| Phishing-derived session | real | normal | none |
| Session hijack on shared net | real | normal | weak (JA3/IP) |
| Insider abuse | real | normal | none |
| Supply-chain (real npm pkg, malicious update) | n/a (CI flow) | n/a | none in HTTP |
| Post-auth logic bug exploit (IDOR/BOLA) | real | valid shape | none |
| Stolen admin cookie + admin action | real | valid admin route | none |

Every row above passes a WAF clean. Every row above passes API schema
validation. The only differentiator visible at the perimeter is
sometimes a TLS fingerprint change, and not always.

These are the attacks this document targets.

---

## 2. Three detection tiers

The 12 engineering techniques in this document split cleanly into
three tiers. **Operators should treat tier as policy**: Tier-1 can
hard-block; Tier-2 can soft-enforce; Tier-3 informs scoring only.

### Tier 1 — Deterministic, zero false positive

These detect facts, not behaviours. They can hard-block without
operator backlash.

| Technique | What it detects | FP source |
|---|---|---|
| **Data Passport / JIT capability** | "this action requires an active signed passport for class X — none was presented" | Operator failed to issue passport (their fault, not ours) |
| **Canary users / routes / tokens** | "this asset was touched; no legitimate consumer exists" | Operator misconfiguration (canary leaks into real code) |
| **Single-use nonce / replay protection** | "this nonce was already redeemed" | Buggy app double-submits a form |
| **Causal-chain divergence (post-baseline)** | "request /admin/export produced lineage X; baseline says it should produce lineage Y" | Legitimate deploy changed the lineage |
| **Workflow state-machine** (deterministic version: route REQUIRES predecessor) | "POST /checkout without prior session bound to /cart" | App allows direct deep-link checkout |

### Tier 2 — Probabilistic, high precision (>99%)

Use these to soft-enforce: insert a delay, require step-up auth,
freeze the session. Do not hard-block.

| Technique | What it detects | Realistic FP rate |
|---|---|---:|
| **Session-to-lineage binding** | Cookie reappears with new JA3 / ASN mid-session | 1–5% |
| **Per-(user, route) baseline EWMA** | This account is doing something it has never done before in N weeks of observation | 5–15% |
| **Living-off-the-land lineage scoring** | curl / nc / bash -i spawned from a web-facing lineage in a way this app has never produced | 5–15% |
| **Velocity caps per (account, action_class)** | More destructive actions than the cap allows | 0–10% (depends on cap tuning) |

### Tier 3 — Probabilistic, moderate precision (90–99%)

Useful as score contributors, never as standalone signals.

| Technique | What it detects | Realistic FP rate |
|---|---|---:|
| **Blast-radius / distinct-set tracking** | Session touched more unique tables/routes than typical | 5–20% |
| **Cohort baseline** | This user behaves unlike their cohort | 10–30% |
| **Time-of-day / geo anomaly** | Login at unusual time / new country | 10–25% |
| **Workflow state-machine** (soft version: scoring) | Unusual workflow order | 5–20% |

---

## 3. Per-technique deep dive

Each technique below is described with: what it does, how it
integrates with existing xhelix work, the **honest FP source**, and a
recommended response posture (hard block / soft enforce / score only).

### 3.1 Data Passport / JIT admin capability (Tier 1)

**Detection**: A request to an admin / destructive / bulk-export route
must carry a valid ed25519-signed Passport (DLCF P7.1.7) with a TTL
covering the request time and a class set covering the data touched.
No passport → deny. Wrong class → deny. Expired → deny.

**Implementation status**: Shipped (P7.1.7). Needs Request Contract
plumbing to be enforced automatically per-request rather than only at
bulk export.

**FP source**: Operator did not issue the passport. This is not a
false positive — it is correct enforcement of an operator policy.
Mitigate friction with auto-issued short-TTL passports for admins on
whitelisted devices/ASNs.

**Response posture**: Hard block. Cryptographic certainty.

### 3.2 Canary users / routes / tokens (Tier 1)

**Detection**: Catalog declares synthetic identifiers — uid 999998
(canary user), `/api/v0/debug` (canary route), `xc-canary-...` (canary
token marker). No legitimate consumer exists. Any touch is by
definition unauthorised.

**Implementation status**: File-level canaries shipped (P7.1.5).
Extend to:
- canary uid ranges in user tables
- canary routes in the catalog's route map
- canary parameter names

**FP source**: An ops script accidentally references the canary, OR
backup/migration tooling reads the full table. Both are operator
failures, not detector failures — and both can be allow-listed by
process identity.

**Response posture**: Hard block + critical alert + auto-quarantine.
Near-zero FP, highest signal-to-noise in the entire architecture.

### 3.3 Single-use nonce / replay protection (Tier 1)

**Detection**: Sensitive endpoints issue HMAC nonces. The next
sensitive request must include + invalidate the nonce. Replayed
cookies don't have a fresh nonce.

**Implementation status**: New. Lives inside `xhelix-bridge` Request
Contract layer.

**FP source**: A real app that double-submits forms (legitimate user
clicks twice). Mitigate with idempotency keys for known double-submit
flows.

**Response posture**: Hard block on replay. Soft enforce on missing
nonce (the user may be on an older client version).

### 3.4 Causal-chain divergence (Tier 1 once baselined)

**Detection**: For every route, learn the legitimate downstream
lineage signature: the *set* of distinct (binary_sha, syscall_class)
tuples the route produces in 14 days of clean observation. At
runtime, every request whose actual lineage adds new tuples raises
an alert; the alert severity scales with how exotic the new tuple is.

Example signature for `/admin/export/orders`:
```
expected: {nginx, php-fpm, mysql_client, s3_putobject}
observed: {nginx, php-fpm, bash, curl, unknown_dest}
delta:    {bash, curl, unknown_dest}  ← critical
```

**Implementation status**: Substrate ready (hot graph P2.1, lineage
P1.4). Needs: signature builder + baseline storage + per-request
signature comparison.

**FP source**: Legitimate code deploys change lineage. Mitigate by:
- pinning baseline to (route, exe_sha) — when binary changes,
  re-baseline that one route
- 24h "learning mode" after every deploy, surfacing alerts to
  operator without enforcement
- operator confirmation step to graduate the new signature into
  baseline

**Response posture**: Hard block in steady state with confirmed
baselines. Score-only during learning window.

**This is the single highest-ROI detection xhelix can build.** Nothing
outside an EDR has the data to compute it.

### 3.5 Workflow state-machine — deterministic mode (Tier 1)

**Detection**: Per-route catalog declares required predecessor states.
`POST /checkout` requires a prior session-bound `GET /cart`.
`POST /admin/export` requires a prior `GET /admin/login` within 15
minutes.

**Implementation status**: New. State machine lives in Request
Contract layer; per-session ledger of route classes hit.

**FP source**: Legitimate deep-linking, bookmarks, page refresh during
checkout, mobile app jumping directly to checkout, password manager
auto-filling.

**Response posture**: Hard block for routes the operator marks
explicitly. Soft enforce (step-up auth) for the rest.

### 3.6 Session-to-lineage binding (Tier 2)

**Detection**: At first observation, bind the session to: TLS
fingerprint (JA3/JA4), ASN (not IP — too noisy), broad geo (country
or coarser), OS family. Subsequent requests in the same session that
violate the binding raise an alert.

**Implementation status**: Identity sensor stub exists. Needs JA3
extraction in `xhelix-bridge` + session-binding store.

**FP source** (concrete examples):
- Mobile user switches wifi ↔ cellular (~ASN change, common)
- VPN toggle
- Browser update changes TLS stack (rare but real)
- Same household, multiple devices sharing a synced session
- Network NAT changes

Per-FP-class mitigation:
- Allow same-country ASN drift (catch only cross-country)
- Allow same-major-version browser TLS drift
- Treat single-IP-event signals as score contributors, not hard signals

**Response posture**: Soft enforce. Insert a 1–3 s delay on next
sensitive action. Step-up auth if a second signal fires.

### 3.7 Per-(user, route, action) behavioral EWMA baseline (Tier 2)

**Detection**: Per `(account_id, route, action_class)` tuple, EWMA of:
query count, row count, response size, child process kinds spawned,
distinct files touched, outbound destinations, request inter-arrival
times. Deviation > 3σ raises a soft alert; > 5σ raises a hard alert.

**Implementation status**: xhelix already has baseline + EWMA infra
(`pkg/baseline`, `pkg/baselinehub`) keyed on binaries. Repoint key to
`(account, route)`.

**FP source** (concrete and unavoidable):
- User on vacation logs in from new country
- User receives an unusual data request (legal subpoena, compliance audit)
- Power user does a one-off bulk task
- New employee onboarding does many "first times" in week 1
- Service account behavior changes after a software update

Per-FP-class mitigation:
- 14-day learning window per (account, route) before scoring
- "First-time" actions always score lower than "anomalous-rate" actions
- Cohort fall-back for users with insufficient history

**Response posture**: Score-only contribution to the response ladder.
Never a standalone block. Stack with other Tier-2 signals.

### 3.8 Living-off-the-land lineage scoring (Tier 2)

**Detection**: `curl`, `wget`, `nc`, `python -c`, `bash -i`, `tar -czf`,
`rsync` are not malicious in isolation. But the lineage matters: same
`curl` is normal under `cron`, suspect under `nginx → php-fpm`,
**critical** under `sshd → bash → curl → unknown_dest`.

**Implementation status**: exec sensor + lineage already see this.
Needs catalog entries declaring (binary, lineage_root) scoring matrix.

**FP source**:
- Real ops use these tools from cron/scripts (build steps, monitoring,
  health checks)
- Some applications shell out to curl as a feature

Mitigation:
- Per-host warmup with operator allow-listing of known-clean
  (binary, lineage_root) pairs
- Score by (binary, full lineage chain), not just (binary, immediate
  parent) — sshd → bash → curl is a stronger signal than cron → curl

**Response posture**: Soft enforce when score crosses threshold.
Hard block only on specific high-signal patterns (e.g. `bash -i`
spawned by `php-fpm` is unambiguous).

### 3.9 Velocity caps per (account, action_class) (Tier 1 OR Tier 2)

**Detection**: Hard cap on rate of high-value actions per account.
Default caps in catalog; operator overrides. Examples:
- max 5 destructive ops / minute / account
- max 3 password-reset emails / day / account
- max 10 deletes / session
- max 500 sensitive-record reads / hour / account

**Implementation status**: DLCF Sensitivity Budget (P7.1.3) already
implements the counter machinery. Needs:
- `(account_id, action_class)` keys plumbed via Request Contract
- catalog entries declaring action_class per route

**FP source**:
- Real bursts: admin doing a cleanup, support agent handling a
  ticket spike
- Caps set too low to start

Mitigation:
- Caps are operator-set policy. Operator can lift a cap on-demand
  via Data Passport (two-person workflow). This converts the cap
  from a probabilistic detector into a *deterministic* one — the
  user is over the cap, full stop, and the policy allows them to
  request a temporary lift.

**Response posture**: This is the trick — **if cap-lift goes through
Passport, velocity caps become Tier-1** (policy fact, not behavioral
guess). Hard block at cap; user requests lift via OOB workflow.

### 3.10 Blast-radius / distinct-set tracking (Tier 3)

**Detection**: Per session, track the *set* of distinct (table,
route_class, data_class) tuples touched. Real users have small,
stable blast radius. Attackers fan out.

**Implementation status**: New. Small per-session HyperLogLog or
bitset.

**FP source**: Real users explore. New-user onboarding involves
touching many routes for the first time.

**Response posture**: Score-only. Combine with Tier-2 signals to
escalate.

### 3.11 Cohort baseline (Tier 3)

**Detection**: For sites where per-user baseline is infeasible
(millions of users), label users by cohort (free-tier, paid, admin,
API consumer). Detect within-cohort outliers.

**FP source**: Cohort labels are coarse. A power user inside a
free-tier cohort generates constant FPs.

**Response posture**: Score-only.

### 3.12 Soft enforcement ladder (response mechanism, not detector)

**Detection**: N/A — this is a response policy.

**Mechanism**: Compose Tier-1 + Tier-2 + Tier-3 signals into a single
score per (session, request). Map score ranges to response:

| Score | Response |
|---|---|
| 0–30 | log only, no user-visible effect |
| 30–60 | insert 1–3 s delay on next sensitive action (transparent to humans, devastating to scrapers) |
| 60–80 | require step-up auth (TOTP, hardware key) before next sensitive action |
| 80–100 | freeze session, force re-login, alert operator |
| 100 (Tier-1 deterministic hit) | hard block, auto-quarantine source |

**This is what makes a noisy detector usable.** Tier-2 signals at
moderate confidence cost the user 1 second of latency rather than a
locked account, so the FP backlash is minimal.

---

## 4. Mapping known attack types → which technique catches them

This is the table that matters. For each known attack class, which
techniques fire (and at what confidence)?

| Attack | T1 deterministic catch | T2 high-precision | T3 score |
|---|---|---|---|
| Stolen password (first login) | — | Session-binding (new JA3/ASN if from datacenter) | Time-of-day, geo |
| Stolen session cookie (replay from new device) | Replay nonce | Session-binding (JA3/ASN mismatch) | Per-route baseline |
| Stolen API key | — | Baseline (volume, distinct endpoints) | Cohort |
| Session hijack on shared net | — | Session-binding (if device differs) | Time-of-day |
| Insider abuse (real account, bad intent) | Canary if they touch one; velocity caps if they exceed | Behavioral baseline (acting outside historical norm) | Blast radius |
| Post-auth IDOR | Canary user id reads | Per-route baseline (touching others' data) | Blast radius |
| Post-auth RCE (exploit after valid auth) | **Causal-chain divergence (KILLER signal)** | LOTL lineage scoring | — |
| Stolen admin cookie | **JIT passport missing** | Session-binding | Time-of-day |
| Supply-chain (malicious npm update) | **Causal-chain divergence** (new binary in chain) | LOTL (curl from build step that's never used it) | — |
| Mass credential stuffing | — | Session-binding (datacenter ASN), velocity caps on login attempts | Cohort |
| Slow data scraping | Velocity caps (cumulative) | Blast radius, baseline | — |
| Account-takeover-then-export | **JIT passport missing**, canary rows in export | Baseline (volume), session-binding | — |

**The two killer signals against the dangerous attacks are:**
1. **Causal-chain divergence** — catches post-auth RCE and supply-chain
2. **JIT passport / Data Passport** — catches stolen-admin-cookie + bulk export

Both are Tier-1 deterministic. Both can hard-block with zero FP.

---

## 5. Composition principle

No single Tier-2 signal should ever produce a hard action. The
operating rule:

```
hard_action = (any Tier-1 signal fires)
            OR (two independent Tier-2 signals + one Tier-3 above threshold)
soft_action = (one Tier-2 signal)
            OR (two Tier-3 signals)
score_only  = (single Tier-3 signal)
```

"Independent" means signals derived from different observation
channels: JA3 binding is independent of baseline EWMA which is
independent of LOTL lineage.

---

## 6. Request Contract layer — the substrate

Every detection above needs `account_id`, `session_id`,
`request_contract_id` to flow from the HTTP request all the way to
kernel-level events. That's the **Request Contract layer** (P-RC),
the prerequisite for everything else in this document.

```
HTTP request
  ↓ xhelix-bridge issues RequestContract{id, account, session, route,
  ↓                         schema_hash, ja3, ttl}
  ↓
app worker (php-fpm / gunicorn / node)
  ↓ xhelix-bridge tags the worker's socket-cookie + cgroup with the contract_id
  ↓
sensors observe events
  ↓ enrichment looks up socket-cookie → contract_id and tags every event
  ↓
rule engine / taint ledger / budgets / Egress Valve
  evaluate every event against the contract that produced it
```

The Request Contract is **not** the perimeter — it doesn't validate
schemas or signatures (Envoy / nginx + ModSecurity already do that
upstream). It is the **runtime tag** that lets every downstream
sensor know "this event was caused by request X for user Y on
route Z". Without it, none of the behavioral detection in this
document attaches.

---

## 7. What xhelix will explicitly NOT promise

Honesty section. Read this as a contract with operators.

1. xhelix will **not** detect a stolen-cookie attacker who perfectly
   mimics the victim's behavior, touches only the victim's own data,
   and stays under every velocity cap. That attacker is invisible to
   every detector here. They will be visible in the post-action audit
   trail (chain + cold store) but not in real time.

2. xhelix will **not** promise a fixed FP rate to operators because
   FP rate depends on operator-set thresholds, application
   heterogeneity, and user-base diversity. We will publish per-tier
   typical ranges (Tier-1: 0%; Tier-2: 1–15%; Tier-3: 5–30%) and a
   tuning playbook.

3. xhelix will **not** ship a "block everything suspicious" mode.
   The default is score → soft enforce → hard block by tier, and the
   soft tier handles the bulk of operationally tolerable detection.

4. xhelix will **not** require operator-supplied threat intelligence.
   Every detection in this document fires from operator-declared
   *policy* (catalog, caps, allowed lineages) or *observed* baselines,
   not from external IOC feeds.

5. xhelix will **not** silently downgrade signals. Every fired
   detection is recorded in the signed chain with its source signal
   set, score, and the response taken. Operators can audit every
   decision.

---

## 8. Implementation phases

See `ROADMAP.md`. Summary:

### P-RC — Request Contract layer (~2 weeks)

Substrate for everything else. Carries `request_contract_id` from
`xhelix-bridge` through eBPF (socket-cookie or cgroup correlation)
to every downstream event.

| Task | Description | Days |
|---|---|---|
| P-RC.1 | `pkg/reqcontract`: ID issuance, signing, TTL, lookup | 3 |
| P-RC.2 | `xhelix-bridge` L7 hop: parse, issue contract, forward | 4 |
| P-RC.3 | eBPF socket-cookie correlation: tag worker process | 3 |
| P-RC.4 | Event enrichment: stamp every event with contract_id | 2 |
| P-RC.5 | LocalAPI: `reqcontract.lookup`, `reqcontract.stats` | 1 |

### P-BEHAVIOR — Behavioral defenses (~3 weeks)

Layered on top of P-RC. Each task contributes one or more detection
techniques. Order chosen so Tier-1 (deterministic, hard-blockable)
ships first.

| Task | Description | Tier | Days |
|---|---|---|---|
| P-B.1 | **Canary users + canary routes** extension (3.2) | T1 | 2 |
| P-B.2 | **Replay-resistance nonces** for sensitive endpoints (3.3) | T1 | 4 |
| P-B.3 | **Causal-chain divergence detector**: baseline builder + comparator (3.4) | T1 | 7 |
| P-B.4 | **Workflow state-machine** declarative engine (3.5) | T1/T2 | 5 |
| P-B.5 | **Session-to-lineage binding**: JA3 + ASN + cohort capture (3.6) | T2 | 3 |
| P-B.6 | **Per-(user, route) baseline EWMA**: repoint baseline package, plumb account_id (3.7) | T2 | 4 |
| P-B.7 | **LOTL lineage scoring matrix**: catalog + rule engine integration (3.8) | T2 | 3 |
| P-B.8 | **Velocity caps via Request Contract**: account/action_class keys (3.9) | T1 | 2 |
| P-B.9 | **Soft enforcement ladder**: score → delay → step-up → freeze (3.12) | n/a | 5 |
| P-B.10 | **Blast-radius set tracking** (3.10) | T3 | 3 |

### Sequencing relative to existing roadmap

```
P1 ✅ → P2 (in progress, hot graph done) → P-RC → P-BEHAVIOR → P7.2 (DLCF DB obs) → P7.3 → P3 / P4 / P5 / P6
```

P-RC + P-BEHAVIOR slot between P2 and P7.2 because:
- P2 (graph + cold store) is the substrate Behavioral Defense queries
- P-RC + P-BEHAVIOR deliver the highest-leverage detections against
  the threat class the product is positioned for
- P7.2 (DB observation) augments behavior detection rather than
  replacing it — it can land after

Total: ~5 weeks from end of P2 to end of P-BEHAVIOR.

---

## 9. Operator tuning playbook (short version)

Every detection in this doc has knobs. The operator tuning principle:

1. **Start in observe-only mode** for 14 days. Every detector logs;
   nothing blocks. Build trust.
2. **Promote one Tier-1 detector at a time** to hard-block. Start with
   canaries (effectively no FP risk). Then JIT/passport on bulk
   exports. Then causal-chain divergence once baselines are stable.
3. **Keep Tier-2 in soft-enforce** indefinitely. Promote to hard only
   for specific combinations (e.g. "JA3 mismatch AND baseline 5σ" can
   step up to hard block on bulk export routes).
4. **Tier-3 stays score-only**. They're real signals, but ground
   ops cannot survive a daily backlog of 15% FPs even on a 10-event
   day. Use them to escalate Tier-2 decisions.
5. **Re-baseline after every code deploy**. The cold store
   automatically opens a 24-h learning window on every observed
   binary-sha change.

If an operator follows this playbook, the achieved real-world
detection-vs-FP curve is:

- Tier-1: ~100% detection / 0% FP on the in-scope facts
- Tier-2: ~95% detection / 1–5% FP on observed attacks (when stacked)
- Tier-3: ~80% detection / 10–20% FP, used as score contributors

Aggregate across stacked tiers against the threat model in §1:
**~90% detection of valid-looking attacks at <2% operator-visible FP
rate**, with the residual ~10% caught post-action via the audit chain.

That is the honest number to plan against.

---

## 10. Open questions

1. **Cohort labels** — derive from app-side metadata (subscription
   tier, role), or learn via clustering? Decide before P-B.6.
2. **Step-up auth UI** — does `xhelix-bridge` inject the challenge
   itself, or call back to the app? Probably the latter (apps already
   have step-up UI for password resets).
3. **Baseline storage** — same cold-store SQLite (P2.3), or a separate
   `pkg/behaviorbase` store? Lean cold-store to avoid yet another
   data path.
4. **Privacy/regulatory posture** — JA3 + ASN binding is logging
   client fingerprints. Need an explicit operator toggle and a
   retention policy.
