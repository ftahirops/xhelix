# Crown-Jewel Profile — protecting what matters in SMB & solo deployments

xhelix subsystem for identifying, classifying, and layering protection
around the **specific** assets and actions whose abuse causes
catastrophic damage. Per the proposal in this session: "build a
fortress around crown jewels, not around every endpoint."

Target audience: **solo operators, SMB, and medium enterprise (≤200
people).** Specifically NOT optimized for Fortune-500 security teams
with dedicated HSM ops; that's "enterprise edition" territory.

> Status: design locked. Implementation tracked in `ROADMAP.md`
> Phase P-CJ. Companion docs: `BEHAVIORAL_DEFENSE.md`,
> `DATA_LEAK_FABRIC.md`, `POST_COMPROMISE_DEFENSE.md`,
> `ARCHITECTURE.md`.

---

## 0. The hard truth (read this first)

**Same-host root cannot be made harmless by software alone.** If an
attacker has real root on the same Linux box xhelix runs on, they
can:

- ptrace any process and dump its memory
- read `/proc/<pid>/mem` of anything running
- disable any AppArmor / seccomp profile
- kill the xhelix daemon
- modify on-disk state (catalog, policy, keys)
- inject kernel modules

xhelix raises the cost and detects the noise of doing each of these.
xhelix does NOT make root-on-the-same-host into a no-op.

**The strategic move**: get the things worth stealing OUT of that
machine's trust boundary. Long-lived secrets stop living in app
memory. Destructive power stops being a direct app capability. Audit
proof stops living on the machine being attacked.

That is what this document is about.

---

## 1. Threat tiers we target

Different attackers warrant different mitigations. Be explicit so we
don't over-engineer the rare threat at the expense of the common one.

| Tier | Description | Share of real breaches¹ | xhelix posture |
|---|---|---:|---|
| T1 | Opportunistic web attacker — scanners, public-CVE exploits, default-password scans | ~50% | **Strongly defended** by existing perimeter + xhelix runtime |
| T2 | Credential-theft attacker — stolen cookies, phishing-derived sessions, malware-grabbed creds | ~30% | **Strongly defended** with P-B.0a WebAuthn + DBSC + replay nonces shipped |
| T3 | Targeted post-auth — logic exploits, IDOR, post-auth RCE, supply-chain in user code | ~15% | **Strongly defended** by P-B.3 causal-chain divergence + LOTL scoring + canaries |
| T4 | Targeted with same-host root — webshell escalated, kernel exploit, malicious admin | ~4% | **Cost-raised, not blocked.** Honest limit. |
| T5 | Nation-state, supply-chain compromise of xhelix itself, zero-day kernel + EDR bypass | <1% | **Out of scope.** No SMB-tier solution stops this; honest. |

¹ Approximate, from Verizon DBIR + Mandiant M-Trends 2023/2024 distributions.

**Design rule**: T1-T3 mitigations must work for a 5-person ops team
with no dedicated security engineer. T4 mitigations may demand more
operational rigor (cloud KMS integration, off-host backups). T5 is
documented and out of scope.

---

## 2. Memory-resident secret tiers (M0-M6)

The five-line summary of the entire post-compromise hard problem:

| Tier | What | Defends against | SMB-realistic? |
|---|---|---|---|
| **M0** | Env vars, plain config files | Nothing — first thing an attacker `cat`s | n/a (anti-pattern) |
| **M1** | Hardening: no env, no core dumps, `hidepid=2`, AppArmor, seccomp | Most non-root attackers | ✅ Yes — sysctl + AppArmor profiles |
| **M2** | Short-lived dynamic secrets (5-min TTL) | Reduces the value of any single dump | ✅ Yes — Vault dynamic creds, AWS STS |
| **M3** | Secret broker — app asks for credentials per-session | App never stores long-lived secrets | ✅ Yes — **integrate Vault / cloud secret manager**, don't build |
| **M4** | Action broker — broker performs the action, app never receives the secret | Narrow use cases (signing, decryption) | ⚠ Selective — only for the most sensitive ops |
| **M5** | HSM / KMS / TEE — key never leaves hardware boundary | Same-host root | ✅ Yes for *cloud* KMS (AWS/GCP/Azure); ❌ usually not for on-prem HSM in SMB |
| **M6** | Separate trust-boundary host — secret lives on a different machine, network-segmented | Compromise of the app host | ✅ Yes — cloud KMS counts; on-prem requires a separate server |

**SMB-realistic posture**: M1 + M2 + cloud-KMS-backed M5 for signing
keys + Vault-backed M3 for app credentials. That stack is achievable
with one part-time engineer, costs <$50/month for a small deployment,
and closes ~95% of the realistic memory-secret theft surface.

---

## 3. Crown-jewel categories

For SMB / medium-enterprise deployments, the assets and actions worth
declaring as crown jewels:

### Data (the things that can leak)

| Category | Examples | Default protection tier |
|---|---|---|
| Customer PII | user table rows with email/phone/address | L4 |
| Payment data | card tokens, IBAN, payment_intents | L5 |
| Source code | `/var/www/*/src/`, `.git/` | L4 |
| Backups | `*.tar.gz`, `*.sql.gz` under `/srv/backups/` | L5 |
| Application secrets | `wp-config.php`, `.env`, `/etc/xhelix/*` | L5 |
| Audit data | xhelix chain, application audit logs | L5 |

### Actions (the things that can destroy)

| Category | Examples | Default protection tier |
|---|---|---|
| Authentication | `/login`, `/wp-login.php`, OAuth token mint | L5 |
| MFA reset | `/forgot-password`, `/mfa/reset` | L5 |
| Role change | grant admin, change permission level | L5 |
| Bulk data export | `/admin/export/*`, large CSV download | L5 |
| Destructive DB | `DROP`, `TRUNCATE`, mass `DELETE` | L5 |
| Backup deletion | snapshot remove, archive purge | L6 |
| Code/plugin install | new WP plugin, theme upload, deploy push | L5 |
| API key/token mint | new bearer token, OAuth client secret | L5 |
| Payment/refund | `/refund/*`, `/wallet/transfer` | L5 |

### Identities (the things that can grant)

| Category | Examples | Default protection tier |
|---|---|---|
| Admin accounts | user role=admin | L5 |
| Service accounts | API consumers with elevated privilege | L5 |
| Recovery codes / break-glass | emergency-access credentials | L6 |

---

## 4. Protection-tier definitions (L1-L6)

Six tiers, mapped to what xhelix actually requires at the runtime
enforcement layer. The numbers escalate with attacker cost.

| Tier | Required for the request to succeed | Typical use |
|---|---|---|
| **L1** | Valid session cookie | Public content, blog posts, marketing pages |
| **L2** | L1 + admin-allow-listed source ASN/IP (if route is operator-flagged) | User-data routes for logged-in users |
| **L3** | L2 + fresh WebAuthn assertion ≤60s old | Profile changes, contact-info edits |
| **L4** | L3 + DBSC device-binding active | Admin dashboards, user-management lists |
| **L5** | L4 + Data Passport signed by xhelix-managed key (cloud KMS for SMB / HSM for enterprise) | Destructive actions, bulk export, role grants |
| **L6** | L5 + two-person approval (two distinct Data Passports issued by different operator identities within 15min) | Backup deletion, root account changes, policy disable |

**What this gives the operator**: a single tier number per route.
The catalog declares `protection: L5`. xhelix-bridge enforces it.
Cross-checks (allow-list, WebAuthn, DBSC, Passport, two-person)
collapse to one config knob.

---

## 5. What xhelix builds vs. integrates vs. delegates

The strategic correction from the proposal that came in this session:
**do not rebuild Vault, AWS KMS, or HSM functionality. Integrate.**

For SMB scale, the right architecture is:

```
                            ┌──────────────────┐
                            │ Cloud KMS         │
                            │ (AWS / GCP / Az)  │
                            │ Stores: passport  │
                            │   signing key     │
                            │   chain key       │
                            └────────▲─────────┘
                                     │ Sign API
                                     │ (~10ms)
┌─────────────────────────────────────┼─────────────────────────────┐
│ Host running xhelix                 │                             │
│                                     │                             │
│  ┌─────────┐    ┌────────────────┐ │      ┌────────────────────┐│
│  │ app     │───▶│ xhelix daemon  │─┘      │ HashiCorp Vault    ││
│  │ (PHP /  │    │   verifier of  │◀───────│ (separate host or  ││
│  │  Go /   │    │   passports,   │ Get    │  HCP Vault hosted) ││
│  │  Node)  │    │   nonces,      │ Cred   │ Stores: app secrets ││
│  │         │    │   reqcontract  │        │   dynamic DB creds  ││
│  └─────────┘    │   webauthn vfy │        └────────────────────┘│
│                 └────────────────┘                              │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │ xhelix-exportd / xhelix-deleted brokers                 │   │
│  │ (separate Unix users, separate cgroups, distinct trust) │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Build inside xhelix

| Component | Why | Effort | Status |
|---|---|---|---|
| Crown-Jewel Wizard — scanner that proposes catalog entries from observed activity | Solves "operator didn't declare X" gap | ~5d | planned |
| Crown-jewel diff alert — new file/route appears, prompt to classify | Catches drift | ~3d | planned |
| Delete-broker (mirror xhelix-exportd) | Destructive DB / file ops gated | ~10d | partially planned (P7.3.x) |
| Watchdog + remote heartbeat | "Cannot kill silently" | ~5d | planned (Phase 6 ROADMAP) |
| Two-person workflow generalization | Data Passport already supports `approved_by`; extend to require N distinct passports for L6 | ~3d | small extension |
| WebAuthn assertion verification | Already on the roadmap as P-B.0a | ~4d | queued |
| DBSC verifier (Chrome-only OK for SMB) | Replay-resistance per request | ~3d | new task |
| **Total build** | | **~33d / ~6.5 weeks** | |

### Integrate (don't build)

| Component | Service | Effort | Why integrate |
|---|---|---:|---|
| Passport signing key | AWS KMS, GCP KMS, or Azure Key Vault | ~3d | $1/month, key never leaves cloud HSM, all majors support ed25519. Replace `loadOrGenerateEd25519Key` with KMS `Sign` API. |
| App secret broker | HashiCorp Vault (self-hosted, ~1h to install) or HCP Vault (~$22/month hosted) | ~5d | Mature dynamic-credential issuance; xhelix becomes a Vault *client*, not a competitor |
| Audit log destination | Cloud object storage with write-once policy (S3 Object Lock, GCS Bucket Lock) | ~2d | Tamper-prevent, not tamper-detect. xhelix chain still signs; the chain ALSO lives in WORM storage. |
| Hosted MFA / SSO (optional) | Authentik, Authelia, Keycloak — self-hosted; Auth0, Clerk — hosted | varies | xhelix verifies their assertions; doesn't compete |
| **Total integrate** | | **~10d / ~2 weeks** | |

### Delegate to the operator (xhelix does NOT do this)

| Item | Why xhelix doesn't | What operator does |
|---|---|---|
| Identity proofing (real-name KYC) | Different product domain | Onfido, Persona, Veriff |
| Hardware key procurement | Physical logistics | YubiKey 5C NFC at $55/admin |
| Vault server operations | Already mature OSS | Run it, or pay HCP |
| Cloud KMS account / IAM | Already mature SaaS | Set up KMS key, give daemon limited Sign role |
| Off-host backup target | Already mature SaaS | S3 with Object Lock, separate AWS account |

### Punt to "enterprise edition" (future)

| Item | When SMB cares | Approach |
|---|---|---|
| Full HSM (PKCS#11) on-prem | Compliance demands physical hardware | YubiHSM 2 (~$650) or Thales — operator chooses |
| SGX / TDX enclave for daemon | Defending against same-host root cryptographically | Highly specialized; defer until paying customer asks |
| Multi-tenant secret broker | xhelix as a managed service | Different product line |
| Cross-account fleet correlation at scale | xhub already exists; needs hardening | Mature what's there; don't rebuild |

---

## 6. Specific gap closures (mapping to assets)

For each crown-jewel category from §3, what the SMB-targeted defense
looks like:

### Customer PII / payment data
- Catalog classifies the tables as `pii` / `payment_token`
- Sensitivity Budget (P7.1.3) caps reads per session/account
- Egress Valve (P7.1.6) refuses outbound to undeclared destinations
- Bulk-export requires L5 Data Passport (operator approval, KMS-signed)
- Canary rows in user table (P-B.1) fire on any touch
- DB user lacks `DROP/TRUNCATE/ALTER` privileges (operator setup, lint by `xhelixctl posture db`)

### Backups
- Cataloged path `/srv/backups/*` classified as `backup`
- Egress Valve denies outbound from any process tainted with `backup`
  unless destination is the operator-declared backup mirror
- Deletion requires L6 (two distinct Data Passports + maintenance
  window flag)
- **Backups live off-host in WORM storage** (S3 Object Lock) — root
  on the app host cannot delete what isn't there

### Application secrets (wp-config.php, .env)
- M3 broker model: app gets dynamic credentials from Vault, not env
- For existing apps that can't be re-architected: file is classified
  `credentials` in catalog; Egress Valve denies outbound from any
  process tainted with `credentials`
- Read of these files by non-app-user → critical alert (FIM sensor)

### Authentication routes (/login, MFA reset)
- L5 policy: require fresh WebAuthn assertion
- Replay nonces (P-B.2) prevent captured-request replay
- Admin allow-list (P-B.0b) restricts source ASN/IP
- Behavioral baseline (P-B.6, future) detects "logged in from new ASN"
- DBSC binds the session cookie to the device

### Destructive DB actions
- App's DB user does NOT have `DROP/TRUNCATE/ALTER` (operator config)
- Destructive operations go through `xhelix-deleted` broker
- Broker requires L5 Data Passport + maintenance window flag
- Pre-action snapshot verified via separate identity
- All operations go through DDL audit trigger (logged to chain)

### Code/plugin install
- FIM sensor flags writes to `/var/www/*/wp-content/plugins/`
- LOTL scoring (P-B.7) catches the installer toolchain
- Require L5 Data Passport for the deploy path
- New binary on disk → catalog diff alert prompts classification

### Audit erasure
- Ed25519-signed event chain (P0/P1) — tamper-detect
- Chain ALSO streams to off-host WORM bucket via cloud upload (P-CJ.X new task)
- `xhelix-verify` runs against the off-host chain — operator gets the
  forensic trail even if the local host is incinerated

---

## 7. Daemon kill problem — solving it for SMB

The proposal is correct: you can't make the daemon unkillable on the
host where it runs. The goal is "cannot kill silently."

Stack of mitigations that are SMB-realistic:

1. **Systemd `Restart=always`** + restart-burst limits
2. **Watchdog peer** — a tiny secondary process that monitors the
   main daemon's heartbeat file and re-spawns it; if both die, syslog
   emits a critical via the systemd journal
3. **Remote heartbeat to xhub** — operator-controlled remote endpoint
   that alerts on missed heartbeats. ~5 minutes detection.
4. **Cloud-side observability** — your existing monitoring (Datadog,
   Grafana Cloud, etc.) already alerts on process disappearance for
   free
5. **Chain gap detection** — `xhelix-verify` shows the precise minute
   the audit chain stopped flowing. Forensic guarantee, not
   preventive.

What SMB DOES NOT need: dedicated kernel-mode anti-tamper, custom
init-system shimming, ring -1 modules. Those are enterprise-tier.

---

## 8. Passport key — moving it to cloud KMS

The proposal correctly flagged that `/var/lib/xhelix/passport.key`
being root-readable is the weakest link in the Data Passport story.

**SMB-realistic fix**: cloud KMS. Concrete steps:

1. Operator creates an asymmetric KMS key (AWS:
   `CreateKey --key-spec ECC_SECG_P256K1` — also ed25519 supported on
   GCP KMS and Azure Key Vault).
2. KMS IAM policy grants `Sign` (only) to the xhelix host's role.
3. xhelix calls `kms.Sign(payload)` instead of `ed25519.Sign(key, payload)`.
4. Latency: ~10-30 ms per passport. Passports are issued at human
   pace (operator approval), not event rate, so this is fine.
5. Cost: $1/key/month + $0.03/10k requests. For an SMB issuing maybe
   100 passports per day, total cost <$2/month.

**What this gives**: even with full root on the xhelix host, the
attacker cannot mint a new passport. They can verify existing
passports (the public half lives on the host); they cannot sign.

**Implementation**: ~3 days. Wrap `pkg/passport.Issue` so it accepts
a `Signer` interface; provide both `LocalEd25519Signer` (current,
default) and `KMSSigner` (cloud). Operator chooses at config time.

---

## 9. Crown-Jewel Wizard — solving the "we forgot to declare X" gap

The single biggest practical adoption risk: an operator deploys
xhelix, doesn't bother updating the catalog with their actual asset
list, and then doesn't notice when something gets stolen because the
asset wasn't crown-jewel-classified.

The wizard solves this. Concept:

```
$ xhelixctl wizard scan
Scanning /var/www/... for sensitive files... (12s)
Scanning DB schemas... (3s)
Sniffing common routes via xhelix-bridge access log... (10s)

Proposed catalog entries (review and approve):

  Tables:
    [Y/n] wp_users                  → classify as: pii, credentials
    [Y/n] wp_woocommerce_orders     → classify as: pii, customer_order
    [Y/n] wp_options                → classify as: credentials
    [Y/n] wp_postmeta               → SKIP (no sensitive fields detected)

  Files:
    [Y/n] /var/www/.../wp-config.php           → classify as: credentials
    [Y/n] /srv/backups/2026-05-15.tar.gz       → classify as: backup
    [Y/n] /root/.ssh/id_rsa                    → classify as: credentials
    [Y/n] /etc/ssl/private/*.key               → classify as: credentials

  Routes (require operator confirmation — wizard cannot infer purpose):
    [skip] /admin/                  → suggested: L4 (admin)
    [skip] /admin/export/orders     → suggested: L5 (export)
    [skip] /wp-login.php            → suggested: L5 (auth)

Found 3 likely canary candidates:
    [Y/n] uid 9999998 (no email, never logged in) → mark as canary
    [Y/n] uid 9999999 (no email, never logged in) → mark as canary

Operator review: 8 entries accepted, 4 deferred. Writing patch to
/etc/xhelix/dlcf/catalog.yaml.proposed (review + merge manually).
```

This is a 1-week operator-UX investment that probably 5×s adoption
quality. **Highest leverage build item in the entire post-compromise
roadmap.**

---

## 10. Honest non-promises (the operator contract)

What xhelix will NOT promise SMB operators, by design:

1. **"Your data cannot be stolen if you have xhelix."** False against
   T4-T5. The honest claim: data theft becomes 5-50× more expensive
   against T1-T3 attackers, and detectable-and-bounded against T4.

2. **"Same-host root is harmless with xhelix."** False. We raise the
   cost, log everything, and make many specific damages
   impossible (canary touch, passport-required actions, off-host
   audit). We do not make root harmless.

3. **"No false positives, ever."** False for Tier-2/3 behavioral
   detectors. True for Tier-1 deterministic detectors (canaries,
   passports, nonces, allow-lists). The composition rule from
   `BEHAVIORAL_DEFENSE.md §5` ensures user-visible false-action rate
   stays low.

4. **"Set up once and forget."** False. The Crown-Jewel Wizard
   reduces ongoing cost dramatically, but the catalog drifts as the
   app evolves. Plan for ~30 minutes / month of catalog review.

5. **"Defends against nation-state attackers."** Out of scope. Use
   different products for that threat model.

What xhelix WILL promise SMB operators:

1. **"You will know when your audit trail is incomplete."** The
   signed chain + off-host mirror gives this guarantee even against
   root.

2. **"Tier-1 deterministic detections fire with zero false
   positives."** Canary touch, missing passport, replayed nonce, IP
   outside allow-list — these are policy facts, not statistical
   inferences.

3. **"Bulk data exfiltration takes operator approval to succeed."**
   The Data Passport + Egress Valve + Sensitivity Budget combination
   makes this true unless the operator explicitly disables it.

4. **"Destructive actions go through a broker."** Once the
   delete-broker ships (P-CJ.3) and the operator removes
   `DROP/TRUNCATE` from the app DB user, direct destructive ops are
   prevented, not just detected.

5. **"Your audit trail is forensically usable even after the
   machine is destroyed."** Off-host WORM mirror + offline verifier
   guarantee this.

---

## 11. Implementation phases (P-CJ, ~10 weeks SMB-realistic)

| Phase | Task | Days | Build/Integrate/Delegate |
|---|---|---:|---|
| P-CJ.1 | **Crown-Jewel Wizard** — scan + propose catalog entries | 5 | Build |
| P-CJ.2 | **Crown-jewel diff alert** — new file/route, prompt classification | 3 | Build |
| P-CJ.3 | **Delete-broker** — gate destructive ops behind L5 passport | 10 | Build |
| P-CJ.4 | **Two-person L6 generalization** — N-distinct-passport workflow | 3 | Build |
| P-CJ.5 | **Watchdog + remote heartbeat** | 5 | Build |
| P-CJ.6 | **WebAuthn enforcement** (= existing P-B.0a) | 4 | Build |
| P-CJ.7 | **DBSC verifier** | 3 | Build |
| P-CJ.8 | **Cloud KMS Signer for passport key** | 3 | Integrate |
| P-CJ.9 | **Vault integration for app secrets** — secrets.broker LocalAPI | 5 | Integrate |
| P-CJ.10 | **Off-host chain mirror to S3 Object Lock / GCS Bucket Lock** | 2 | Integrate |
| P-CJ.11 | **`xhelixctl posture db`** — flag DB users with `DROP/TRUNCATE/ALTER` | 3 | Build (matches P7.3.3 plan) |
| P-CJ.12 | **Operator setup wizard** — connect KMS / Vault / WORM bucket interactively | 4 | Build |
| **Total** | | **~50d / ~10 weeks** | |

Of which **build effort: ~40 days**; integration scripting: ~10 days.

Order chosen so the highest-leverage items ship first:
- P-CJ.1 (wizard) before everything else, because misconfigured
  catalog defeats the whole stack
- P-CJ.6 (WebAuthn) early, biggest stolen-cookie defense
- P-CJ.8 (KMS) early, removes the local passport-key risk
- P-CJ.3 (delete-broker) once L5 passport workflow is solid

---

## 12. Cost to operator (the honest dollar number)

For a typical SMB deployment (one production host, one operator):

| Component | Monthly cost |
|---|---:|
| Cloud KMS key + Sign calls | $1.50 |
| HCP Vault Dev tier (or self-hosted) | $0 (self) or $22 (HCP) |
| S3 Object Lock bucket for off-host audit | $1 (low data) |
| YubiKey 5C NFC for the operator (one-time) | $55 |
| **Total monthly** | **~$3-25** |
| **One-time** | **$55** |

This is achievable for a solo operator without a security budget.
Solo / single-client deployment: same numbers; operator approves
their own passports (the one-person workflow is just "operator
clicks 'issue' in the wizard").

For medium enterprise (~50-200 people), add:
- Hosted Vault: ~$22-100/month
- A second operator for L6 two-person approval workflow
- Internal training: ~2 hours per operator to understand the L1-L6
  tier model

Total for medium enterprise: ~$50-200/month + the operator labor.

---

## 13. What the proposal said vs. what we're going to do

For posterity — the corrections from this session's discussion:

| Proposal said | We're going to | Why |
|---|---|---|
| Build a secret broker | Integrate Vault | Re-implementing mature product takes 3-4 weeks of avoidable work |
| Build a remote signer service | Use cloud KMS Sign API | Same — KMS is 2 days of integration, $1/month |
| Build HSM/TEE mode for high assurance | Punt to enterprise edition | SMB target doesn't have on-prem HSM; cloud KMS covers most cases |
| App asks broker for every action | App receives short-lived credentials from broker; xhelix verifies scope | Realistic for existing apps (WordPress, etc.); "broker every action" requires re-architecture nobody will do |
| Standalone "delete broker" | Yes, build this | Real new code |
| Standalone "export broker" | Already on roadmap as P7.3.1 (xhelix-exportd) | We were already building this |
| Watchdog + remote heartbeat | Yes, build this | ~5 days, high value |
| Cross-host xhub correlation | Already in code base | Document + soak-test; don't rewrite |

---

## 14. Operator setup checklist (one-page reference)

The minimum SMB operator does to get crown-jewel protection working:

```
[ ] 1. Run `xhelixctl wizard scan` and approve catalog entries
[ ] 2. Create a cloud KMS key for passport signing
       (AWS, GCP, or Azure — all supported)
[ ] 3. Grant xhelix's IAM role the KMS:Sign permission only
[ ] 4. Set xhelix config: passport.signer = kms; passport.kms_arn = ...
[ ] 5. Pick a Vault deployment (HCP Vault hosted, OR run on a
       separate host)
[ ] 6. Migrate one app secret (DB password) from env to Vault
       dynamic-creds; observe it work; then migrate the rest
[ ] 7. Create an S3 bucket with Object Lock (compliance mode) for
       off-host audit mirror
[ ] 8. Set xhelix config: chain.offhost = s3://bucket/audit/
[ ] 9. Buy one YubiKey, enroll it for the admin account
[ ] 10. Set protection tier on admin routes: L5 (requires WebAuthn
        + DBSC + Passport)
[ ] 11. Test bulk-export-without-passport — confirm it's blocked
[ ] 12. Test admin login from a non-allow-listed ASN — confirm it's
        blocked
[ ] 13. Test canary-touch — confirm alert fires
[ ] 14. Subscribe to the xhub heartbeat alerting channel
```

Steps 1-3 cost a few minutes. Steps 4-9 take an afternoon. Steps
10-14 are a half-day. Total: **~1 day of operator work** for the
full SMB-grade crown-jewel posture.

---

## 15. Open questions

1. **Should the wizard scan be passive (operator runs it manually)
   or continuous (daemon proposes new entries as assets appear)?**
   Recommend: passive for v1; continuous as a P-CJ.2 follow-on.

2. **Should we ship a default Vault integration library, or just
   document how to use HashiCorp's official one?** Recommend:
   document. Operators with their own Vault setup will use what
   they have.

3. **Do we mandate cloud KMS for passports, or keep local-key as
   default with KMS as the documented upgrade?** Recommend: local
   default, KMS as the operator's "production hardening" step (in
   the checklist).

4. **For the L6 two-person workflow, do the two passports have to
   come from different humans, or just different operator
   identities?** Recommend: enforce different identities (different
   API tokens / WebAuthn assertions); humans are an external
   policy question.

5. **Should the delete-broker support a "dry run" mode showing what
   would be deleted?** Recommend: yes, mandatory for the first
   destructive op in any operator session.

---

## 16. Closing — the honest one-line product positioning

> xhelix gives SMB operators **layered defense around their crown
> jewels**, with **integration (not reinvention) of cloud KMS and
> Vault**, and **honest non-promises** about what software-only
> defense can achieve when the attacker has root on the same host.

That positioning is defensible, sellable, and accurate. The full
"unbeatable fortress" framing isn't.
