# xhelix — Defense Priorities (Fortress Posture)

> Where to focus engineering attention, ranked by real-world frequency ×
> exploitability × damage × how well xhelix can stop it.
>
> Companion to [ARCHITECTURE.md](ARCHITECTURE.md) (the locked design) and
> [ROADMAP.md](ROADMAP.md) (phase-by-phase implementation plan).

---

## Contents

1. How to use this document
2. Highest-priority attack focus table (20 attack classes)
3. Critical correction — kernel exploit handling
4. Easiest high-impact wins (13 features by ROI)
5. What to ignore in MVP
6. Reorganized defense-scope tiers (10 tiers)
7. WAF-level state contracts (request-aware enforcement)
8. Corrected Fortress product scope (WordPress / PHP lockdown)
9. Final recommended build order (13 items, supersedes §4 for sequencing)
10. Mapping to ROADMAP.md phases
11. Priority shifts this analysis forces on the locked plan
12. Bottom line

---

## 1. How to use this document

- **Section 2** ranks the 20 attack classes xhelix Fortress can address.
- **Section 3** is the kernel-exploit correction — what cannot
  be solved by eBPF alone.
- **Section 4** ranks the 13 highest-ROI features by *security gain per
  engineering hour*.
- **Section 5** explicitly excludes scope that doesn't belong in MVP.
- **Section 6** restructures the defense surface into 10 tiers with
  priority annotations.
- **Section 7** designs the WAF-level state contract layer.
- **Section 8** narrows the product scope to WordPress / PHP fortress.
- **Section 9** gives the canonical build order that supersedes §4
  for sequencing decisions.
- **Section 10** maps every item to a roadmap phase.
- **Section 11** documents priority shifts this analysis forces.
- **Section 12** is the one-line product positioning.

When in doubt about what to build next: consult §2 (what attacks matter
most), then §9 (canonical build order), then check §10 for which phase
it belongs in.

---

## 2. Highest-priority attack focus table

Ranked by: real-world frequency + exploitability + damage + how well
xhelix Fortress can stop it.

| Priority | Attack class | Common? | Damage | Easy for attacker? | xhelix Fortress value | Final verdict | Build focus |
|---:|---|---|---|---|---|---|---|
| 1  | Web RCE → shell spawn | Very high | Critical | Medium | Very high | **Must block first** | php-fpm/nginx/apache → sh/bash/curl/wget/nc deny |
| 2  | Webshell / PHP in uploads | Very high | Critical | Easy | Very high | **Can almost eliminate** | uploads no-exec, deny *.php, quarantine |
| 3  | Secret read + egress | Very high | Critical | Medium | Very high | **Flagship xhelix use case** | sensitive-file catalog + unknown egress block |
| 4  | Unknown outbound C2/exfil | High | Critical | Easy | Very high | **Default-deny solves huge class** | per-service egress allowlist |
| 5  | Persistence: cron/systemd/authorized_keys | High | Critical | Easy | Very high | **Can almost eliminate from app user** | persistence watchlist + AppArmor/SELinux deny |
| 6  | Plugin/theme/core tampering | Very high in WordPress | Critical | Easy | Very high | **WordPress killer feature** | update-mode contracts + file integrity |
| 7  | SSRF to internal services / metadata | High | High | Medium | High | **Strong if egress is strict** | block metadata/RFC1918 except explicit allow |
| 8  | SQL injection through allowed DB | High | Critical | Medium | Medium | **Needs DB/app contract** | query-shape baseline + DB least privilege |
| 9  | Broken access control / IDOR | Very high | High | Easy | Low-medium | **Needs app semantics** | route/user/object contract |
| 10 | Credential / admin abuse | High | Critical | Easy if creds leaked | Medium-high | **Cannot solve alone** | MFA, hardware key, admin-mode approval |
| 11 | Supply-chain malicious plugin/update | Medium-high | Critical | Medium | Medium-high | **Needs clean contract workflow** | signed plugin/version contract review |
| 12 | Process injection / ptrace / memfd | Medium | Critical | Medium | High | **Good xhelix target** | deny ptrace, process_vm_writev, memfd exec |
| 13 | Privilege escalation from app user | Medium | Critical | Medium-hard | Medium-high | **Reduce, not eliminate** | seccomp, no caps, no-new-privileges, patching |
| 14 | Ransomware from app user | Medium | High | Medium | Medium-high | **Contain blast radius** | narrow write paths + write-rate SIGSTOP |
| 15 | Kernel / rootkit attack | Low-medium | Catastrophic | Hard | Low (normal) / High (hardened) | **Do not claim solved by eBPF alone** | Secure Boot, lockdown, IMA, module signing |
| 16 | Business logic fraud | High | High | Easy-medium | Low unless app-integrated | **Not OS-level problem** | app invariants, transaction contracts |
| 17 | Allowed-channel exfil | Medium | High | Medium | Medium | **Hard class** | per-route outbound contract + payload limits |
| 18 | DDoS / app-layer DoS | High | High | Easy | Low-medium | **Different product area** | CDN/WAF/rate limits |
| 19 | Baseline poisoning | Medium | Critical | Medium | Medium | **Dangerous for learning systems** | clean training, signed baseline, shadow mode |
| 20 | Operator mistake | High | High | n/a | Medium | **Governance issue** | blast-radius preview, two-person approval |

### How to read the verdicts

- **Must block first / Flagship use case / Can almost eliminate** — these
  are the items where xhelix's design genuinely shifts the outcome.
  Engineering effort here pays back proportionally.
- **Strong if egress is strict / Good xhelix target** — defensible but
  depends on adjacent controls being in place.
- **Needs app semantics / Cannot solve alone / Not OS-level problem** —
  xhelix can record evidence but is not the right primary control.
- **Different product area / Dangerous for learning systems** — explicit
  out-of-scope or careful-with markers.

---

## 3. Critical correction — kernel exploit handling

Kernel exploit protection **cannot rely on eBPF alone**. If the kernel
is compromised, normal in-kernel monitoring may be bypassed. eBPF programs,
ringbufs, and LSM hooks can all be disabled or subverted by an attacker
who controls the kernel.

Kernel-context attacks require **separate handling with integrity
context** — not normal process-chain proof:

- Kernel module signing (`module.sig_enforce=1`)
- Kernel lockdown (`lockdown=integrity` or `confidentiality`)
- IMA-appraise (`ima_policy=appraise_tcb ima_appraise=enforce`)
- Secure Boot with operator-controlled keys
- Measured boot with TPM PCR sealing of the audit-chain key

These primitives belong in **Phase 6 (Hardened mode)** of the roadmap.
They are *opt-in* — never assumed on by default — but they are the
only realistic answer to root-with-kernel-exploit threat models.

xhelix should never claim "stops kernel exploits" in default
configuration. Honest positioning:

> Verified runtime alerts cover post-exploitation behaviour on a
> functioning kernel. For kernel-tamper resistance, deploy in hardened
> mode (Phase 6) which requires kernel-cmdline integrity flags + Secure
> Boot + signed modules + IMA-appraise. Even hardened mode does not
> defend against undisclosed kernel 0-days.

This is reflected in ARCHITECTURE.md §8.4 (attackers not in scope)
and §5.11 (kernel-context rule class).

---

## 4. Easiest high-impact wins

Maximum security gain per engineering hour. Use as the **value-ranking**
of features; §9 below is the **sequencing-ranking** that should drive
implementation order.

| Rank | Feature | Difficulty | Security gain | Why high ROI |
|---:|---|---|---|---|
| 1  | Block web-process child exec | Low | Critical | PHP/WordPress almost never needs php-fpm → bash in normal mode |
| 2  | Deny PHP files in uploads | Low | Critical | Kills the classic WordPress webshell path |
| 3  | Per-service outbound default-deny | Medium | Critical | Stops C2 / exfil / unauthorised downloads |
| 4  | Sensitive file catalog | Medium | Critical | Protects .env, SSH keys, tokens, wp-config |
| 5  | Persistence path watch/deny | Medium | Critical | Blocks cron/systemd/authorized_keys persistence |
| 6  | WordPress update mode | Medium | Very high | Separates normal runtime from plugin/theme/core modification |
| 7  | AppArmor generated profile | Medium | Very high | Enforces file/exec boundaries outside xhelix logic |
| 8  | systemd hardening generator | Low-medium | High | Easy lockdown: no caps, no-new-privileges, restricted FS |
| 9  | cgroup / nftables egress policy | Medium | Very high | Fast local enforcement |
| 10 | Request ID → process lineage mapping | Medium-high | Very high | Bridges WAF / app / OS causality |
| 11 | Route-level contracts | High | Very high | Stops "normal app doing abnormal route behavior" |
| 12 | DB query-shape monitoring | High | High | Helps SQLi / business misuse; needs app/DB integration |
| 13 | IMA / lockdown / Secure Boot mode | High | Critical for elite users | Needed for root/kernel tamper resistance |

---

## 5. What to ignore in MVP

Not because they are impossible — because they are not the first
product wedge. Each entry below is documented as **explicitly
out-of-scope for MVP**, with a brief reason.

| Ignored in MVP | Reason |
|---|---|
| DDoS | CDN / WAF / upstream problem |
| Firmware / hypervisor attacks | Outside single-host Linux guardian |
| Full Kubernetes-native support | Huge separate product |
| Full SIEM / fleet workflow | Later, after single-host is solid |
| Full malware signature engine | AV / EDR domain |
| Full DLP / content inspection | Very hard and noisy |
| Full business-fraud engine | App-specific; can't be OS-mediated |
| Every possible kernel exploit | Hardened mode later (Phase 6) |

The MVP should not try to solve the whole universe. It should solve
one product wedge — see §8.

---

## 6. Reorganized defense-scope tiers

The 20 attack classes from §2 collapse cleanly into 10 tiers, each with
an enforcement mechanism, a local-vs-off-host placement decision, and a
roadmap priority.

| Scope tier | Attack types covered | xhelix mechanism | Enforce locally? | Off-host useful? | Priority |
|---|---|---|---|---|---|
| **T1: Runtime escape prevention** | shell spawn, curl/wget/nc, memfd exec, ptrace | eBPF + AppArmor + seccomp | Yes | For evidence / RCA | **P0** |
| **T2: Secret protection** | .env, wp-config, SSH keys, tokens | sensitive-asset catalog + file policy | Yes | For timeline / contract diff | **P0** |
| **T3: Egress lockdown** | C2, exfil, SSRF, lateral scan | cgroup / nftables / BPF egress allowlist | Yes | For anomaly refinement | **P0** |
| **T4: WordPress integrity** | webshell, plugin tamper, theme/core change | file integrity + update mode | Yes | For contract versioning | **P0** |
| **T5: Persistence prevention** | cron, systemd, authorized_keys, ld-preload | persistence path deny / watch | Yes | For proof chain | **P1** |
| **T6: Request contracts** | route doing abnormal IO / network / files | app SDK + WAF + eBPF lineage | Partly | Yes | **P1** |
| **T7: DB / query semantics** | SQLi, IDOR evidence, abnormal query shape | DB proxy / instrumentation | Partly | Yes | **P2** |
| **T8: Admin / update governance** | malicious plugin, bad admin action | signed update mode + approvals | Yes | Yes | **P2** |
| **T9: Root / kernel hardening** | rootkit, module load, BPF tamper | IMA, lockdown, Secure Boot | Yes | For remote evidence | **P3** |
| **T10: Business fraud** | coupon / refund / order abuse | app-level invariants | Mostly no | Yes | **P4** |

Priority codes (P0–P4) are independent of the roadmap phase numbers
(Phase 1–6). P0 means "in the MVP wedge"; P1 means "first follow-up";
etc. Roadmap mapping is in §10.

---

## 7. WAF-level state contracts

Traditional WAF: HTTP request → generic rules → block/allow. That
catches common payloads but not application-state violations.

The xhelix design extends this:

```
HTTP request
  → route / user / session / app-mode identified
  → expected request contract loaded
  → request checked before app
  → app emits request_id
  → OS/eBPF events tied to same request_id
  → response checked against route contract
```

### 7.1 State contract enforcement matrix

| Layer | What WAF can enforce | Example | Feasibility | Needs app integration? |
|---|---|---|---|---|
| Method / path | Allowed API routes | `POST /wp-login.php` only accepts form login | High | No |
| Content-Type | Expected content type | Login must be `application/x-www-form-urlencoded` | High | No |
| Body size | Size limits per route | Login body < 10 KB, upload < 10 MB | High | No |
| Parameter schema | Required / allowed params | Login only `log`, `pwd`, `nonce` | High | No |
| Parameter type | integer / email / slug / etc. | `user_id` must be int | High | No |
| Header contract | Allowed headers | Deny anomalous proxy headers | High | No |
| Sequence state | Expected flow | Checkout only after cart / session | Medium | Yes |
| Role-aware route | admin / user / guest | Admin endpoints require admin session | Medium | Yes |
| Payload shape | JSON / form schema | Exact keys allowed | High | Some |
| Response size | Normal response envelope | Login response should not be 10 MB | Medium | No |
| Response class | No secrets returned | No .env / tokens / SQL-dump patterns | Medium | Some |
| Per-route outbound | Route may call payment / mail / API | Checkout can call payment; login cannot | High | Yes |
| Request → process lineage | HTTP request maps to php-fpm PID | Request `abc` caused file/network events | Medium-high | Yes |
| App phase | login / checking_password / session_write | Only expected IO in phase | High | Yes |
| DB query shape | Expected query pattern | Login only user lookup / session update | High | Yes (or DB proxy) |
| Business object policy | User may access own order | Order-owner check | Medium | Strong app integration |

### 7.2 Ideal request flow

```
Client
  → xhelix WAF
      checks request contract
      assigns request_id
  → nginx
  → php-fpm / WordPress plugin
      app reports route / user / phase / request_id
  → eBPF
      records file/network/process events with lineage_id
  → xhelix local enforcer
      blocks hard violations
  → Kafka / off-host brain
      compares full request behavior against baseline
```

End-to-end graph per request:

```
HTTP POST /wp-login.php request_id=abc
  → nginx worker
  → php-fpm pid 8821
  → read WP files
  → connect mysql
  → write session
  → response 302
```

vs an exploit:

```
HTTP POST /wp-login.php request_id=evil
  → php-fpm
  → /bin/sh
  → read wp-config.php
  → connect unknown IP
```

The second case is a **deterministic violation** of the route
contract — no scoring needed.

### 7.3 What WAF-state contracts eliminate

| Attack | WAF-state contract effect |
|---|---|
| Oversized payload exploit | Strong block |
| Unexpected method / path | Strong block |
| Parameter pollution | Strong block |
| Route schema abuse | Strong block |
| Many SQLi/XSS/LFI payloads | Strong block (with OWASP CRS + schema) |
| Upload webshell | Strong block (extension + content rules) |
| SSRF route abuse | Strong if route has no outbound contract |
| Abnormal response dump | Medium-high detection |
| Admin action from wrong session/IP | Strong with app context |
| Business logic abuse | Only if app exposes semantic state |

### 7.4 What WAF-state cannot fully know alone

| Problem | Why WAF alone cannot solve |
|---|---|
| PHP function actually called | Needs app / PHP instrumentation |
| DB row ownership | Needs app / DB context |
| User authorization correctness | App logic |
| Payment / refund correctness | Business logic |
| Malicious behavior after app accepts request | Needs eBPF / runtime graph |
| Plugin internal behavior | Needs app / runtime tracing |
| Pure memory exploitation | Needs runtime symptoms / hardening |

WAF must not be standalone. It must be part of the xhelix causal chain.

---

## 8. Corrected Fortress product scope

### 8.1 Product wedge (locked)

**xhelix Fortress v1: WordPress / PHP Lockdown**

This is the MVP product. Narrow on purpose; wins decisively in one
attack family rather than partially against many.

**Must protect against:**

- Web RCE → shell
- Web RCE → secret read
- Web RCE → unknown egress
- Web RCE → persistence
- Webshell upload
- Plugin / theme tamper outside update mode
- SSRF to blocked ranges
- Unexpected child process
- Unexpected file write
- Unexpected outbound

**Must NOT claim full protection for:**

- Business logic fraud
- Valid-admin abuse
- Kernel / firmware compromise
- DDoS
- All zero-days
- All SQL-injection impact
- All data leakage through normal responses

### 8.2 Honest positioning

Avoid "0% false positives" or "stops everything" language. Use:

> **High-precision verified alerts backed by complete causal evidence,
> plus an evidence stream for everything else.**

This is the same positioning law as ARCHITECTURE.md §3 design law #2
("Tier-1 context complete = verified alert eligible; incomplete =
evidence only").

---

## 9. Final recommended build order

This is the **canonical sequencing** that drives implementation
decisions. Where it conflicts with §4 (value ranking) or §10 (phase
mapping), this section wins for ordering.

| # | Component | Why this position |
|---:|---|---|
| 1  | WordPress / PHP process contract | Easiest entry point with the highest impact |
| 2  | Deny child exec from php-fpm | Kills RCE shell chains immediately |
| 3  | Uploads no-PHP / no-exec contract | Kills webshell upload path |
| 4  | Per-service egress allowlist | Kills C2 / exfil / SSRF |
| 5  | Sensitive asset catalog | Protects secrets |
| 6  | Persistence write deny / watch | Kills common persistence techniques |
| 7  | WordPress mode system (normal/admin/upload/update/backup) | Separates routine traffic from configuration changes |
| 8  | AppArmor profile generator | Turns observed policy into enforced policy |
| 9  | WAF request contract | Schema / method / size / route control |
| 10 | request_id → process lineage | Ties WAF events to eBPF events |
| 11 | Kafka / off-host comparison | Heavy replay / cross-host analytics |
| 12 | DB query-shape contract | SQLi / business-layer visibility |
| 13 | Hardened kernel mode | Lockdown / IMA / Secure Boot |

---

## 10. Mapping to ROADMAP.md phases

| Build-order # | Item | Phase | Maps to roadmap task(s) |
|---:|---|---|---|
| 1  | WordPress / PHP process contract | P4 | New shipped rule + policy-template `wordpress_baseline` |
| 2  | Deny child exec from php-fpm | P4 | P4.3 rule: `web_worker_spawned_shell` |
| 3  | Uploads no-PHP / no-exec contract | P4 | New shipped rule `upload_path_exec_file` |
| 4  | Per-service egress allowlist | P4 | P4.6 enforcement plumbing + rule integration |
| 5  | Sensitive asset catalog | P3 | P3.1 BPF LSM `file_open` + catalog |
| 6  | Persistence write deny / watch | P3 | P3.2 persistence-write watchlist |
| 7  | WordPress mode system | P5 | New subsystem; document as P5.5 extension |
| 8  | AppArmor profile generator | P5.5 (new phase) | Policy-generation workstream |
| 9  | WAF request contract | Post-P5 | Requires HTTP-layer integration |
| 10 | request_id → process lineage | Post-P5 | Same workstream as #9; design RFC needed |
| 11 | Kafka / off-host comparison | Post-P5 / optional | Out-of-scope for single-host MVP; sidecar product |
| 12 | DB query-shape contract | Post-P5 / optional | App-layer instrumentation; document scope clearly |
| 13 | Hardened kernel mode | P6 | All of P6.1 – P6.5 |

### Phase 5.5 — Policy Generation (new workstream)

Items 7 and 8 from the build order justify creating a new phase
between P5 (UI / RCA) and P6 (Hardened mode):

- AppArmor profile generation from observed behaviour
- systemd hardening drop-in generation
- WordPress mode-system templates
- Operator-facing policy diff / preview UI

Estimated effort: ~5 days, parallelisable with P6.

---

## 11. Priority shifts this analysis forces on the locked plan

Comparing the priority tables against the original roadmap reveals
sequencing changes. None break the locked architecture; they tighten
what ships in which phase.

1. **WordPress / web-stack rules are #1 priority, not Phase-4 catalog
   filler.** Items 1-3 from §9 together cover the majority of
   single-server compromise paths. The P4 shipped-rule catalog should
   foreground these explicitly (`web_worker_spawned_shell`,
   `upload_path_exec_file`, `wordpress_core_modification`) rather than
   bury them in a generic list.

2. **Per-service outbound default-deny earns a Phase-4 must-ship slot.**
   Originally one of ten items; now #4 in the canonical build order.
   The egress engine is foundational, not optional.

3. **AppArmor / systemd policy generation deserves its own phase.**
   Phase 5.5 is added between P5 and P6 with ~5 days budget.

4. **Route-level / request-ID contracts (items 9, 10) need a separate
   design RFC.** They require application cooperation that crosses
   xhelix's process boundary. Mark as Post-P5 future work.

5. **DB query-shape monitoring (item 12) is genuinely out of MVP scope.**
   Document this explicitly so we don't accidentally promise it.

6. **Kafka / off-host comparison (item 11) is a separate product.**
   Mark as optional sidecar; never make it a hard dependency of the
   single-host MVP.

7. **Operator mistake (priority 20) needs explicit UX treatment.**
   Add P5.7: "blast-radius preview" — show what a policy change would
   have done over the last 24 h of traffic before applying.

---

## 12. Bottom line

> **xhelix Fortress locks a WordPress / PHP application into its
> approved behaviour and makes post-exploitation movement extremely
> difficult.**

The narrowed scope makes these attack paths nearly gone:

- Webshell uploads
- Web RCE shell spawn
- Unknown outbound C2
- Secret-read + exfil
- Cron / systemd persistence
- Plugin / theme tamper outside update mode
- Dangerous syscalls from app user

Do **not** claim that all zero-days, all business bugs, all
valid-admin abuse, or all DB-level misuse disappear. Those require
WAF / app / DB semantic contracts, not OS snapshots, and they belong
either in P5.5+ or out of scope entirely.

This document is the authoritative priority guide. When in doubt about
what to build next, work the canonical build order in §9 from item 1
downward, mapped to phases via §10.
