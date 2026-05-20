# Full Takeover Detection — leveraging the causal-chain substrate

xhelix subsystem for detecting full-host compromise by aggregating
existing per-event signals into a unified per-lineage "takeover
confidence" score, and for executing the right containment actions
when that score crosses critical thresholds.

> Status: design locked. Implementation tracked in `ROADMAP.md` Phase
> P-FT. Companion docs: `BEHAVIORAL_DEFENSE.md`, `DATA_LEAK_FABRIC.md`,
> `CROWN_JEWEL_PROFILE.md`, `POST_COMPROMISE_DEFENSE.md`,
> `ZERO_DAY_GUARDIAN.md`, `ARCHITECTURE.md`.

---

## 0. The honest preamble

xhelix cannot make same-host root harmless. This is restated for the
fifth time because product positioning keeps drifting toward
"unkillable." It isn't.

What xhelix CAN do — and what this doc is about — is make full
takeover **noisy, expensive, delayed, and detectable with high
confidence even after the attacker has root**, by:

1. Aggregating signals across MITRE ATT&CK phases into one operator-
   facing score per lineage / per session
2. Executing containment actions that preserve evidence and bound
   damage rather than trying to "fight back"
3. Streaming the audit trail off-host so even total local destruction
   leaves a forensically usable record

The framework is the right consumer of the causal-chain substrate
xhelix has already built (lineage, taint, hot graph, egress valve,
budget, chain).

---

## 1. The full-takeover model

Adapted from MITRE ATT&CK phases. The model treats compromise as a
sequence of detectable phases, where each phase produces signals
xhelix already collects via its existing sensors.

| Phase | Description | Adversary behavior | MITRE tactic |
|---|---|---|---|
| A | Initial execution | RCE from web exploit, malicious upload, supply-chain pkg | Execution |
| B | Privilege escalation | sudo abuse, capability change, kernel exploit | Privilege Escalation |
| C | Credential / memory theft | ptrace, /proc/mem, secret-file read | Credential Access |
| D | Defense tampering | stop EDR, disable audit, alter firewall | Defense Evasion |
| E | Persistence | systemd/cron, authorized_keys, webshell | Persistence |
| F | Discovery / lateral | network scan, ssh/kubectl/aws-cli | Discovery + Lateral Movement |
| G | Collection / staging | tar, mysqldump, /tmp staging | Collection |
| H | Exfiltration | outbound to attacker C2, DNS exfil, slow drip | Exfiltration |
| I | Impact / destruction | DROP TABLE, rm -rf, encrypt files, delete backups | Impact |

The detection rule:

> **One suspicious event = candidate. One impossible event = alert.
> Two impossible events in the same lineage = critical. Defense
> tamper + credential access + egress = assume takeover.**

---

## 2. The causal-chain substrate (what's already shipped)

Before mapping signals to phases, here are the xhelix primitives the
takeover detector consumes:

| Primitive | Role in takeover detection |
|---|---|
| `pkg/lineage.LineageID` + `Chain` | Identifies the causal root (Web/SSH/Cron/Container/Sudo) and links every downstream event to it. The "same lineage" predicate in the proposal's rules. |
| `pkg/lineage.TaintSet` | Once a lineage touches credentials/PII/backup/canary, taint propagates. Egress Valve consults this. Substrate for "tainted lineage" detection. |
| `pkg/hotgraph` | In-memory DAG of processes, indexed by cgroup/lineage/origin_ip/tty. Ancestors/Descendants in <1 µs. Enables fast "who else is in this lineage right now" queries. |
| `pkg/canonical.ProcKey` | PID-reuse-safe identity. Required because the same PID number can refer to different processes over time. |
| `pkg/eac` | Reorder window + monotonic sequence ids — ensures detection of session/passport replay across time. |
| `pkg/coldstore` | Per-day SQLite partitions. Historical query for "did this lineage touch a secret in the last hour?" |
| `pkg/evidence` | Per-(rule, kind, exe_sha, cgroup) bucket aggregation — turns noisy repeated alerts into single deduplicated signals. |
| `pkg/catalog` | Data class declarations, canary uids/routes, LOTL scoring matrix, route protection tiers. |
| `pkg/egress` | Refuses outbound from tainted lineage to undeclared destinations — *prevents* exfil, doesn't just detect. |
| `pkg/budget` | Sliding-window sensitivity-point counters per key (lineage / session / user). Slow-drip detection. |
| `pkg/passport` | Required for destructive actions; ed25519-signed; short TTL. |
| `pkg/reqcontract` | Per-request HMAC tags carrying account/session/route/JA3/ASN/WebAuthnTS/DBSCBound. Tags every kernel event back to a request. |
| `pkg/chain` | Ed25519-signed event chain. Tamper-detect: `xhelix-verify` names the exact tampered batch offline. |
| Live sensors | exec, exit, mem (mprotect_rwx), file_open, FIM, LSM audit, netflow, capwatch, decoy, identity, baseline, beacon, dnsexfil, threatintel, tamperguard. |

That substrate is the engine. The takeover scorer is the new
consumer on top.

---

## 3. Phase-by-phase coverage (the honest matrix)

Each cell scores what fires *today*, not what's planned. "Planned"
column is what coverage looks like after the existing roadmap items
ship (P-B.3, P-RC.2, P-CJ.3, P-CJ.10, etc.).

### Phase A — Initial execution

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| `php-fpm → /bin/sh` | LOTL scoring (P-B.7), `parent_risk: php-fpm: 100` | ✅ | ✅ |
| `curl/wget/nc` from app lineage | LOTL `web_tier` multiplier 8x | ✅ | ✅ |
| Upload `.php` to writable path | FIM `creat`/`write` + core rules | ✅ | ✅ |
| Reverse shell outbound | Egress Valve (needs taint flow) | ⚠ | ✅ |

Coverage today: ~80%. After P-RC.2/.4 lineage taint flows: ~95%.

### Phase B — Privilege escalation

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| Unexpected `sudo` from service lineage | `cap.gained` rule (live, observed today) | ✅ | ✅ |
| `capset` / privileged capability gain | capwatch | ✅ | ✅ |
| Kernel module load | `ebpf.module` sensor | ✅ | ✅ |
| Unexpected `bpf()` load | Needs xhelix-signed BPF allow-list | ⚠ | ✅ |
| SUID binary modification | FIM + chmod tag | ✅ | ✅ |
| Namespace escape (`setns`, `unshare`) | LSM audit (sensor sees it; rule needed) | ⚠ | ✅ |

Coverage today: ~85%. After 2 rule additions: ~95%.

### Phase C — Credential / memory theft

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| `ptrace` on sensitive process | ebpf.proc `ptrace_attach` tag | ✅ | ✅ |
| `/proc/<pid>/mem` open | LSM audit | ✅ | ✅ |
| `/proc/<pid>/environ` against sensitive comm | LSM audit (needs scoped rule) | ⚠ | ✅ |
| `SSH_AUTH_SOCK` access by non-owner | LSM audit | ⚠ | ✅ |
| Reads `.env`, `wp-config.php`, `/etc/shadow` | FIM + catalog `credentials` class + taint propagation | ✅ | ✅ |
| `gdb/gcore/strace` outside maintenance | Needs catalog LOTL extension (~5 lines) | ⚠ | ✅ |
| Cloud metadata path access | netflow + rule | ⚠ | ✅ |

Coverage today: ~75%. After ~1 day of rule/catalog additions: ~95%.

### Phase D — Defense tampering

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| `systemctl stop xhelix` | tamperguard sensor | ✅ | ✅ |
| Kill xhelix / auditd | tamperguard | ✅ | ✅ |
| Disable AppArmor/SELinux | `fim.posture` + LSM | ✅ | ✅ |
| Delete logs / truncate | FIM unlink/truncate tag | ✅ | ✅ |
| Firewall changed | `posture lsm` (offline) | ⚠ | ✅ |
| Audit chain signature gap | `xhelix-verify` offline | ⚠ | ✅ (need online watchdog) |
| eBPF programs removed | tamperguard | ✅ | ✅ |
| xhelix policy unsigned change | **No signed-config gate yet** | ❌ | ✅ (P-FT.4) |
| Remote heartbeat gap | xhub exists; operator setup missing | ⚠ | ✅ (P-CJ.5) |

Coverage today: ~75% local, ~50% remote. After P-CJ.5 + signed-policy + chain-gap watchdog: ~90% / ~85%.

### Phase E — Persistence

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| Write to `/etc/systemd/system/` | FIM + core rules | ✅ | ✅ |
| Write to `/etc/cron*` | FIM + core rules | ✅ | ✅ |
| `authorized_keys` modified | Core rules `ssh_key_added_root`, `ssh_key_added_user` | ✅ | ✅ |
| `.bashrc` / `/etc/profile.d/*` | FIM (need explicit rule) | ⚠ | ✅ |
| `/etc/ld.so.preload` | Core rule `ld_so_preload_modified` | ✅ | ✅ |
| `/etc/pam.d/*` | FIM (need rule) | ⚠ | ✅ |
| `/etc/sudoers*` | FIM (need rule) | ⚠ | ✅ |
| Webshell upload | See Phase A | ✅ | ✅ |
| New DB admin user / API token | Needs DLCF DB observation (P7.2) | ❌ | ✅ |

Coverage today: ~75%. After 5 rule additions: ~85%. After DLCF P7.2: ~95%.

### Phase F — Discovery / lateral movement

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| Network port scan | netflow + correlator (need rule) | ⚠ | ✅ |
| Read SSH config / known_hosts | FIM (need rule) | ⚠ | ✅ |
| `ssh/scp/rsync` from app lineage | LOTL extension (5 lines catalog) | ⚠ | ✅ |
| `aws/az/gcloud/kubectl` from app | LOTL extension | ⚠ | ✅ |
| `.kube/config` read | FIM + catalog (wizard P-CJ.1 proposes it) | ⚠ | ✅ |
| New east-west connection | xhub correlation needed | ❌ | ⚠ (xhub exists; operator setup) |

Coverage today: ~50%. After LOTL + rule additions + xhub setup: ~80%. Cross-host gap is fundamental to single-host EDR.

### Phase G — Collection / staging

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| `tar/zip` of sensitive paths | LOTL (`tar` in catalog) + lineage taint | ⚠ | ✅ |
| `mysqldump`, `pg_dump` | LOTL extension | ⚠ | ✅ |
| Sensitive read + archive process | **Causal-chain divergence (P-B.3)** — THE killer | ❌ | ✅ |
| `/tmp` staging after sensitive read | Budget + lineage taint | ⚠ | ✅ |
| DB sensitivity budget spike | `pkg/budget` (needs account_id from P-RC.2) | ⚠ | ✅ |

Coverage today: ~50%. After P-B.3 + P-RC.2: ~90%.

### Phase H — Exfiltration

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| Tainted lineage outbound | **Egress Valve (P7.1.6)** | ✅ | ✅ |
| Slow-drip | **Sensitivity Budget (P7.1.3)** | ⚠ (substrate; needs taint flow) | ✅ |
| DNS exfil | dnsexfil sensor + rules | ✅ | ✅ |
| SaaS/webhook misuse | Egress Valve destination policy + threatintel | ✅ | ✅ |
| Object-storage upload | Egress Valve + catalog destinations | ✅ | ✅ |

Coverage today: ~95%. This is xhelix's strongest area.

### Phase I — Impact / destruction

| Signal | xhelix primitive | Today | Planned |
|---|---|:--:|:--:|
| `unlink/rmdir` on protected path | FIM detection | ✅ | ✅ (prevent: delete-broker P-CJ.3) |
| `O_TRUNC` / truncate | FIM | ✅ | ✅ |
| Mass file rewrite + entropy (ransomware) | Existing pattern detection | ⚠ | ✅ |
| `DROP DATABASE/TABLE` direct | Needs DB observation (P7.2) + delete-broker | ❌ | ✅ |
| Backup file deletion | FIM + Egress Valve (`backup` taint) + WORM mirror | ⚠ | ✅ |
| Disable backup jobs | FIM + signed-policy gate | ⚠ | ✅ |

Coverage today: ~50%. After delete-broker + WORM + signed policy: ~85%.

### Aggregate

| Phase | Today | After roadmap |
|---|---:|---:|
| A. Initial execution | 80% | 95% |
| B. Privilege escalation | 85% | 95% |
| C. Credential / memory theft | 75% | 95% |
| D. Defense tampering | 75% / 50% | 90% / 85% |
| E. Persistence | 75% | 95% |
| F. Discovery / lateral | 50% | 80% |
| G. Collection / staging | 50% | 90% |
| H. Exfiltration | **95%** | 95% |
| I. Impact / destruction | 50% | 85% |
| **Aggregate** | **~71%** | **~89%** |

Honest numbers, not marketing. ~71% of the proposal's full-takeover
detection matrix fires *today* against an attacker running the
canonical RCE → credential → exfil chain. The remaining gap is
addressed by items already on the roadmap.

---

## 4. The three things genuinely missing

After the phase mapping, three concepts in the proposal don't directly
map to a shipped primitive. They are the real new work.

### 4.1 Unified Takeover Confidence Scorer (`pkg/takeover`)

xhelix has every individual signal. It does NOT have a component
that aggregates per-lineage signal accumulation into a single
score with confidence thresholds.

The closest existing thing is `pkg/evidence` — but it deduplicates
alerts within a 1-min window, not across alert types and MITRE
phases over a session lifetime.

**Goal**: emit one operator-facing event per lineage when the
accumulated evidence crosses a confidence threshold.

```text
Score key per lineage:
  10  suspicious
  25  strong suspicion
  50  likely compromise
  75  full takeover likely      -> first user-visible alert
  90  full takeover confirmed   -> auto-containment actions
 100  critical confirmed         -> immediate hard block + notification
```

Design summary:

```go
// pkg/takeover/scorer.go

type Scorer struct {
    // Per-lineage running score + signal history
    lineages map[lineage.LineageID]*lineageState

    // Phase weights from ruleset/dlcf/takeover.yaml
    weights map[string]Weight   // ruleID -> {phase, score, decay_secs}
}

type lineageState struct {
    Score       int
    Phases      map[Phase]int     // per-phase contribution
    Signals     []SignalEvent     // last N for explanation
    FirstSeen   time.Time
    LastSeen    time.Time
    Tier        Tier              // suspicious / strong / likely / takeover / confirmed
}

func (s *Scorer) Observe(alert *model.Alert) Verdict
func (s *Scorer) Snapshot(id lineage.LineageID) (lineageState, bool)
func (s *Scorer) All() []lineageState
func (s *Scorer) Sweep(now time.Time) int  // age out scores
```

Inputs come from the alert bus (`emit()` in dispatch). The scorer:

1. Looks up each alert's `RuleID` in the weights table
2. Adds the weight to the lineage's running score per-phase
3. Promotes the lineage's tier when thresholds cross
4. Emits a `takeover.confidence` event for tier promotions
5. Periodically sweeps stale lineages (e.g., 60-min inactivity)

The weights config (`ruleset/dlcf/takeover.yaml`):

```yaml
version: 1
phases:
  A_initial_exec: 30
  B_privesc:      35
  C_credential:   40
  D_defense:      50
  E_persistence:  35
  F_lateral:      25
  G_collection:   30
  H_exfil:        50
  I_impact:       60

# Per-rule contribution (defaults to phase value)
rules:
  dlcf_lotl_critical:        { phase: A_initial_exec, score: 30 }
  tamper_passwd:             { phase: E_persistence,  score: 40 }
  ld_so_preload_modified:    { phase: E_persistence,  score: 50 }
  dlcf_canary_file_opened:   { phase: A_initial_exec, score: 100 }  # canary = instant top
  ssh_key_added_root:        { phase: E_persistence,  score: 40 }

  # Composition multiplier: two phases in same lineage within 60s
  # gets 1.5x; three phases gets 2x.

thresholds:
  suspicious:     10
  strong:         25
  likely:         50
  takeover_likely: 75
  takeover_confirmed: 90
  critical_confirmed: 100
```

The thresholds map directly to the proposal's score table.

Effort: ~5-7 days build + ~2 days weight tuning + ~1 day LocalAPI.

### 4.2 Negative-space invariants (`pkg/invariants`)

The proposal's framing — *"do not baseline everything; baseline
impossibilities"* — matches xhelix's Tier-1 philosophy exactly.
What's missing is a *first-class concept* in the catalog for
operator-friendly impossible-action declarations.

```yaml
# ruleset/dlcf/invariants.yaml

invariants:
  - name: web_tier_no_shell
    scope: { actor_class: web_tier }   # nginx/apache/php-fpm/etc
    forbid:
      action: process_exec
      comm_in: [bash, sh, zsh, dash]
    severity: critical
    phase: A_initial_exec

  - name: backup_path_no_unlink
    scope: { target_class: backup }
    forbid: { action: unlink }
    unless: { actor_user: xhelix-exportd }
    severity: critical
    phase: I_impact

  - name: shadow_no_read_outside_passwd
    scope: { target_path: "/etc/shadow" }
    forbid: { action: open_read }
    unless: { actor_comm_in: [passwd, chpasswd, vipw, useradd] }
    severity: critical
    phase: C_credential
```

Loaded at startup, generated into the existing CEL rule engine.
Operator-friendly declarative form. The takeover scorer naturally
counts these.

Effort: ~3 days (loader + CEL generator + tests).

### 4.3 System-state stateguard (`sensors/stateguard`)

xhelix signs *events*. It does NOT sign *system state as a whole*.
We have FIM watching individual files but no "the entire authorized
config has hash X; alert on any drift" snapshot.

```go
// sensors/stateguard/stateguard.go

// Periodic state hash sensor.
// Hashes a configurable set of critical files; emits an
// invariant_drift event when a hash changes outside a signed
// maintenance window.

type Sensor struct {
    paths   []string  // /etc/passwd, /etc/sudoers, /etc/cron.d/*,
                     // /root/.ssh/authorized_keys, /etc/nftables.conf,
                     // /etc/apparmor.d/*, /etc/systemd/system/*,
                     // /etc/xhelix/*.yaml
    baseline map[string][32]byte  // path -> sha256
    interval time.Duration  // default 5 min
    bus      *alert.Bus
}
```

Effort: ~3-4 days. Partially overlaps with existing `fim.posture`
which could be extended.

---

## 5. Response actions when takeover is detected

This is the second half of the design: WHAT does xhelix do when the
scorer crosses a critical threshold? Detection without containment is
incomplete.

### 5.1 The action hierarchy (by confidence tier)

| Score | Tier | xhelix automatic action | Operator notification |
|---|---|---|---|
| 10-24 | suspicious | log + bucket in `pkg/evidence` | none |
| 25-49 | strong | log + raise lineage's risk tag | optional digest email |
| 50-74 | likely | soft enforce: insert delay on next sensitive action; refuse new Data Passport issuance for this lineage | immediate alert to operator channel |
| **75-89** | **takeover likely** | **FREEZE the lineage** (see §5.2) | immediate multi-channel alert |
| 90-99 | takeover confirmed | freeze + revoke + block + capture (see §5.3) | page operator |
| 100 (canary touch / passport-required-action-without-passport) | critical confirmed | full containment + immediate forensic snapshot (see §5.4) | page operator + escalate |

The escalation is **strictly automatic at the lower tiers and
escalating-but-conservative at the higher ones**. Specifically: at
critical thresholds xhelix does NOT auto-reboot, auto-restore, or
auto-kill processes — those decisions belong to the operator.

### 5.2 At Tier "takeover likely" (75-89): FREEZE

Goal: stop further action without destroying evidence.

| Action | Mechanism | Why this and not something else |
|---|---|---|
| **`SIGSTOP` the lineage's processes** | `pkg/enforce` already has signal-sending infra; expose lineage-scoped freeze | SIGSTOP preserves memory state for forensics; SIGKILL loses it forever |
| **Refuse new Data Passport issuance for this lineage** | `pkg/passport` adds a `lineageBlocklist` set | The attacker often pivots by minting a passport for `delete` or `export` — cut that off |
| **Block all outbound from tainted lineage** | Egress Valve already does this on `data_classes=canary` taint; ensure all 9 sensitive classes tainted | Prevents in-flight exfil |
| **Revoke active sessions tied to the lineage** | Mark req_contracts with the lineage as invalid | Prevents the attacker from issuing follow-on requests |
| **Force flush of the alert + chain batch** | `pkg/chain` already batches; trigger immediate flush | Don't let the attacker disable xhelix before evidence reaches off-host mirror |
| **Trip xhelix into containment mode** | New: `pkg/enforce/containment.go` global flag | All destructive actions require operator clear; no new passport issuance |

What we do **NOT** do at this tier:
- Don't `SIGKILL` (loses forensics)
- Don't reboot
- Don't block ALL traffic (legitimate users)
- Don't notify the user being attacked (they may BE the attacker, or
  compromised in a way that helps the attacker)
- Don't restore from backup (operator decision)

### 5.3 At Tier "takeover confirmed" (90-99): full containment

Goal: bound damage, preserve everything, force operator review.

In addition to §5.2:

| Action | Mechanism |
|---|---|
| **Snapshot `/proc` state for all PIDs in the lineage** | `pkg/forensic` (new) — capture argv, environ, fds, maps, cwd, status |
| **Capture network 4-tuples** | netflow already has this; serialize the in/out connection set for the lineage |
| **Hash all binaries + config files touched** | `imagecache` already has SHAs; export the involved set |
| **Lock cold-store partition for past 1 hour** | Prevent any sweep/overwrite of recent evidence |
| **Mirror chain to off-host WORM bucket IMMEDIATELY** | Force-flush the off-host uploader (P-CJ.10) |
| **Revoke all Data Passports issued in the last hour** | Conservative — possibly some legit operator action was in flight |
| **Refuse all destructive actions until operator clears containment** | Global flag |
| **Pull host from load-balancer rotation** (if integrated) | Operator hook, not built-in |

### 5.4 At Tier "critical confirmed" (100): canary or passport-violation

These signals are zero-FP by construction. Auto-action with confidence:

In addition to §5.3:

| Action | Mechanism |
|---|---|
| **Page the operator immediately** | Multi-channel: Slack + email + SMS + PagerDuty |
| **Lock the affected catalog routes** | Refuse traffic to any route in the lineage's touch set |
| **Disable any catalog crown-jewel exports until cleared** | Global no-passport flag |
| **Force chain off-host mirror flush** | Critical: even if attacker kills xhelix in the next 30s, evidence is already off-host |

### 5.5 What xhelix explicitly does NOT do (the operator's job)

These belong to the operator's incident-response playbook, not the
daemon's autonomous logic:

| Action | Why not xhelix |
|---|---|
| Reboot the host | Loses memory state needed for forensics |
| Restore from backup | Attacker may have poisoned backups; operator decides |
| Kill processes | Use SIGSTOP first — SIGKILL is irreversible |
| Block all network | Punishes legitimate users; LB drain is the right move |
| Rotate credentials | Operator playbook — must verify the attacker is contained first |
| Wipe the host | Decisions of this magnitude need human approval |
| Notify "the user" | The "user" may be the attacker, or compromised |

### 5.6 Operator playbook (post-detection, semi-automated)

When the operator receives a "takeover likely" or "confirmed" page,
the recommended sequence:

1. **Verify the chain is off-host**: confirm latest off-host mirror
   timestamp. If not, do that first.
2. **Read the takeover snapshot via LocalAPI**: `takeover.detail
   <lineage_id>` returns the full causal chain + contributing
   signals + ProcKey tree + sample event IDs.
3. **Decide containment scope**: this lineage only, this host, or
   pull the whole service from rotation.
4. **Execute conservative containment first**: LB drain + forced
   user re-authentication. Don't kill processes until forensics is
   captured.
5. **Snapshot the host for forensics**: VM/cloud snapshot if
   possible; otherwise rely on the xhelix forensic snapshot.
6. **Rotate credentials accessible from this host**: DB password,
   API keys, signing keys, SSH keys. Use Vault dynamic credentials
   to make this quick. KMS-stored passport key is unaffected.
7. **Determine entry vector via causal chain**: walk the lineage
   from root → first compromised process → first sensitive read.
   Update catalog if a new asset surfaced.
8. **Rebuild from known-good image** (preferred) or **forensically
   clean** (slower, riskier).
9. **Run `xhelix-verify` against the off-host chain end-to-end** —
   prove the audit trail is intact.
10. **Update operator allow-lists, catalog, and rules** if new
    patterns surfaced. Add ERRORS.md entry. Lessons learned.

### 5.7 What the operator must have set up IN ADVANCE

For the response to work, these must already exist when an alert
fires:

- Off-host audit chain mirror (P-CJ.10) — without this, attacker
  with root can destroy evidence
- Cloud KMS-backed passport signing (P-CJ.8) — without this,
  attacker can mint a passport from on-host credentials
- Pre-configured operator alert channels (Slack/email/SMS/PagerDuty)
  with rotation
- Pre-defined "containment runbook" linked from the alert
- WORM backups (S3 Object Lock / GCS Bucket Lock) — without these,
  recovery is uncertain
- An identified second operator for two-person workflows on the
  most destructive recovery actions

If these aren't in place, the detection still works but the
containment depends on attacker speed vs. operator response time.

---

## 6. Roadmap (Phase P-FT)

| Task | Description | Days |
|---|---|---:|
| P-FT.1 | `pkg/takeover` — scorer with per-lineage state, phase weights, threshold promotion, alert bus integration | 7 |
| P-FT.2 | `ruleset/dlcf/takeover.yaml` — weight config + initial tuning against the 61 existing rules | 2 |
| P-FT.3 | `pkg/invariants` — declarative impossible-action loader generating CEL rules | 3 |
| P-FT.4 | `sensors/stateguard` — periodic signed state-hash snapshots; emit drift events | 4 |
| P-FT.5 | Containment actions in `pkg/enforce`: lineage SIGSTOP, passport blocklist, contract revocation, global containment-mode flag | 5 |
| P-FT.6 | `pkg/forensic` — snapshot /proc state for a lineage on demand or auto-trigger | 4 |
| P-FT.7 | LocalAPI: `takeover.list`, `takeover.detail`, `takeover.clear`, `containment.engage`, `containment.disengage` | 2 |
| P-FT.8 | Operator notification fan-out (Slack/email/SMS/PagerDuty webhook) | 3 |
| P-FT.9 | Rule additions to close detected gaps (LOTL extension, /etc/pam.d, /etc/sudoers, /proc/<pid>/environ scoped to sensitive comm) | 2 |
| P-FT.10 | End-to-end takeover scenario test against a synthetic compromised lineage | 3 |

**Total: ~35 days.** This realizes the proposal's full-takeover detection
framework on top of the existing causal-chain substrate.

### Sequencing

The phases above are roughly independent, but the natural order is:

1. P-FT.3 (invariants) + P-FT.9 (rule additions) → close the
   coverage gaps in Phases C/E/F. Cheap.
2. P-FT.4 (stateguard) → defense-tampering signal completion.
3. P-FT.1 + P-FT.2 (scorer + weights) → the unified score.
4. P-FT.7 (LocalAPI) → operator visibility.
5. P-FT.5 (containment actions) → automated response.
6. P-FT.6 (forensic snapshot) + P-FT.8 (notifications) → polish.
7. P-FT.10 (E2E test) → confidence.

---

## 7. Honest non-promises

For the operator contract:

1. **xhelix does NOT make same-host root harmless.** Restated. The
   scorer raises the visible cost; the containment actions limit
   damage. Neither makes root into nothing.

2. **The score has a tuning window.** First 2-4 weeks of deployment
   on a new host will produce some false-confirmed cases. Operators
   should run the scorer in "report-only" mode for the first week
   before enabling automatic containment.

3. **Containment can affect legitimate users.** If the scorer
   freezes a lineage that turns out to be legitimate, those users
   see "session frozen, contact admin" until the operator clears
   containment. This is by design — the alternative is to risk
   missing real compromises.

4. **The forensic snapshot is best-effort.** If the attacker has
   already disabled `/proc` access (`hidepid=2` plus tamper) or
   already killed xhelix, the snapshot may be incomplete. Off-host
   chain mirror is the floor; the snapshot is the ceiling.

5. **Nation-state attackers may still win.** A zero-day in the
   kernel that lets the attacker disable xhelix's eBPF hooks before
   any signal fires is out of scope for this document and almost
   certainly for any EDR.

What xhelix WILL promise:

1. **Off-host audit chain integrity** survives total local destruction.
2. **Tier-1 deterministic signals fire with zero FP** (canary, passport
   missing, replay nonce, IP/ASN allow-list miss).
3. **Containment actions are recorded in the signed chain** —
   operators can audit what xhelix did and why.
4. **Containment is reversible** via operator clear — no daemon
   action permanently destroys state.

---

## 8. The single most important thing to build first

Of the ~35 days, the highest-leverage single item is **`pkg/takeover`
(P-FT.1)**. Reason: 61 rules already fire today; the scorer turns
them from a stream of individual alerts into one operator-facing
"this host is being taken over" signal with a confidence number
behind it. Everything else in this doc — invariants, stateguard,
containment — has more value when there's a unified scorer to
trigger them.

The runner-up is **finishing P-RC.2/P-RC.4** (xhelix-bridge L7 hop +
dispatch enrichment) so lineage taint flows through real traffic,
making the Egress Valve + Sensitivity Budget primitives load-bearing
instead of armed-but-waiting.
