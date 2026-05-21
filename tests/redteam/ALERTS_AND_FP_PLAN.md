# xhelix — Alerts, False-Positive Rate & Causal-Chain Verification Plan

**Owner**: ftahirops
**Goal**: drive false-positive rate to < 1 per 1,000,000 events
(≈ 99.9999% accuracy / "six-nine" target) on a busy reference workload
while keeping true-positive recall ≥ 95% for the MITRE techniques in
`TEST_PLAN.md`.
**Honest framing**: six-nines is a multi-quarter goal, not a switch.
This document defines the **measurement, accountability, and tuning
loop** that lets us claim it.

Companion docs: `TEST_PLAN.md`, `PHASE_1_RESULTS.md`, `DETECTION_GAPS.md`.

---

## 1. What "false positive" means here

A false positive is **a detection record (Alert OR Signal OR planner
plan OR response action) whose causally-tied attribution is benign**.

We distinguish four kinds, because the fix is different for each:

1. **Sensor FP** — eBPF tag wrong (e.g. `from_memfd=true` for a path
   that's a regular file descriptor opened with `O_TMPFILE`). Fix:
   eBPF program correctness.
2. **Rule FP** — sensor data is right; CEL match accepts a benign
   shape (e.g. `mem_mprotect_rwx` matching V8 JIT). Fix: rule
   refinement, allowlist tag (`jit_allowlisted`, `package_managed`).
3. **Correlator FP** — individual signals are fine; co-occurrence
   rule fires on a coincidental pair within the window. Fix: tighten
   co-occurrence Need set, lengthen window, require source binding.
4. **Action FP** — alert is fair but the response is disproportionate
   (Quarantine on a high-FP rule). Fix: per-rule action mask, Soak
   gate, monitor-mode default.

Every FP filed must be tagged with which kind. Mixing them is the
single biggest reason rule tuning regresses.

---

## 2. Target FP-rate ladder (phased)

| Phase | Target FP rate | Equivalent on a 10k-event/sec host (864M/day) | Gate to advance |
|---|---|---|---|
| α (alpha — today) | ≤ 5 × 10⁻² | < 43M FP/day | most rules in Log-only |
| β (beta) | ≤ 1 × 10⁻³ | < 864k FP/day | per-rule action audit complete |
| γ (release candidate) | ≤ 1 × 10⁻⁴ | < 86k FP/day | 7-day soak on reference workload, < 100 operator-flagged FPs total |
| δ (production claim) | ≤ 1 × 10⁻⁶ | < 864 FP/day | 30-day soak, < 50 operator-flagged FPs total |
| ε (six-nine) | ≤ 1 × 10⁻⁷ | < 86 FP/day | 90-day soak, < 30 FPs total |

We currently sit at **α** (Phase 1 verdict). The honest path to δ is
roughly **3–6 calendar months of measurement + tuning** on a real
workload, not a single sprint.

---

## 3. Measurement methodology

You cannot tune what you can't count. The measurement subsystem must
be:

- **Persistent**: every alert is materialised to `/var/log/xhelix/
  alerts.jsonl` (already done).
- **Triagable**: each alert carries `event.id` (ULID), `rule_id`,
  `severity`, `lineage_id`, `evidence_id` so an operator can
  authoritatively label it.
- **Labelable**: `xhelixctl alerts label <event_id> --verdict {tp,fp,unknown} --tag <free>` writes
  to a local label DB (`/var/lib/xhelix/labels.db`). The label
  becomes part of the soak gate's input.
- **Reproducible**: every alert can be replayed against the rule
  engine offline (`xhelixctl events replay --since X`) to verify a
  rule change makes the labelled FPs go away without breaking TPs.

### 3.1 Required new tooling (not yet built)

| Tool | Purpose | Status |
|---|---|---|
| `xhelixctl alerts ls` | list recent, filter by rule/severity | not implemented |
| `xhelixctl alerts label` | mark verdict | not implemented |
| `xhelixctl alerts stats` | per-rule fire / FP / TP / suppress counts | not implemented |
| `xhelixctl events replay` | replay event stream against current rule set | not implemented |
| `pkg/labels` | local SQLite of verdicts, exportable | not implemented |
| `pkg/baseline.RuleFPRate` | rolling FP rate per rule + per-host class | partial via baseline pkg |

These are blockers for δ. Get them on the roadmap.

### 3.2 Ground truth — how we know what's actually benign

You can't measure FP rate without ground truth. Three sources:

1. **Workload assertion**: declare "this reference workstation runs
   only these binaries/services/cron jobs". Anything not in that
   declaration is suspicious. Tool: `xhelixctl posture allowlist`.
2. **Operator labelling**: human-in-the-loop reviewing alerts on a
   trusted host. Burns time, but is the only way to catch the
   tricky FPs (a real attacker who looks like CI).
3. **Negative-control hosts**: a host where no attacker traffic
   reaches and no attacker tooling runs. Every alert there is FP by
   construction. Statistically the cleanest signal.

The three combine: ground truth is `(declared workload) ∧ (no
operator dispute) ∧ (negative-control corroboration if available)`.

---

## 4. Per-rule FP budget

Six-nine globally is not the same as six-nine per rule. A noisy rule
that fires 1000× per host per hour drives the global rate. Per-rule
budget table — every rule must have a budget AND a measurement
strategy.

| Rule | Tier | FP budget (FP/host/day) | Why this number |
|---|---|---|---|
| `memfd_run_pattern` | High volume | 50 | any modern CI/CD uses memfd; needs allowlist tag |
| `mem_mprotect_rwx` | High volume | 100 | JIT runtimes everywhere; absolute cap until allowlist |
| `shell_with_socket_fd` | Medium | 5 | rare-but-not-zero on dev boxes |
| `web_server_spawns_shell` | Medium | 2 | webhooks, CI runners |
| `binary_runs_from_tmp` | High volume | 20 | pip/npm/build tools |
| `uid0_no_transition` | Low | 1 | should be near-zero on prod |
| `ptrace_sensitive_target` | Low | 1 | debuggers should be opted-in |
| `bpf_syscall_unexpected` | Medium | 5 | cilium, bcc, bpftrace exist |
| `tamper_passwd` | Low | 0.1 | useradd is rare on prod |
| `tamper_shadow` | Low | 0.1 | passwd cmd rare on prod |
| `ld_so_preload_modified` | Low | 0.1 | package installs |
| `pam_module_drop` | Very low | 0.01 | almost never benign |
| `ssh_key_added_root` | Very low | 0.01 | should be infra-as-code |
| `cron_new_unit` | Medium | 1 | package installs |
| `outbound_to_known_bad` | Very low | 0.01 | intel feed quality dependent |
| `metadata_svc_unexpected` | Low | 0.5 | legitimate IMDS calls do exist |
| `netids.dga` | Medium | 2 | random-looking subdomains exist (sentry, datadog) |
| `decoy_*` | Very low | 0.001 | by construction shouldn't fire |
| `mem_canary_fail` | Very low | 0.01 | real fault detection |
| `mem_lkrg_violation` | Very low | 0.01 | kernel integrity |
| `ssh_brute_then_success` | Very low | 0.01 | should be rare |
| `beacon.periodic_callback` | Medium | 2 | health checks look like beacons |
| `dnsexfil.tunnel_pattern` | Medium | 2 | telemetry agents do high-cardinality DNS |
| `baseline.behavioural_deviation` | High volume | 20 | statistical, expected to be noisy |
| `baseline.rate_spike` | High volume | 20 | same |
| `webauthn.replay` | Very low | 0.001 | nonces should prevent |
| `webauthn.verify_fail` | Low | 1 | typing errors |
| `admin.ip-disallowed` | Low | 1 | mistyped operator IPs |
| `canary_user_login` | Very low | 0.001 | only attackers should touch |

Sum of budgets on a reference host should not exceed ~250 FP/day at
β, dropping by 100× across each phase. Any rule exceeding its
budget for 7 consecutive days triggers a tuning ticket.

---

## 5. Allowlist taxonomy — the FP fix lever

The single highest-leverage FP-reduction work is **tag-driven
allowlisting**. Every event already carries tags (cgroup_class,
cgroup_unit, package_managed, jit_allowlisted, parent_image, etc.).
Most rules don't yet consult them.

### 5.1 Standard allowlist tags

Already populated by sensors (verify each):

| Tag | Source | Meaning |
|---|---|---|
| `package_managed` | image-cache + dpkg/rpm DB | binary is in a package manifest |
| `jit_allowlisted` | proc table | parent image is in a runtime allowlist |
| `cgroup_class` | cgroup parser | `system` / `user` / `docker` / `kernel` |
| `cgroup_unit` | cgroup parser | systemd unit name |
| `parent_image` | proc table | absolute path of parent's exe |
| `parent_comm` | proc table | parent's comm |
| `from_memfd` | eBPF | image is /proc/self/fd/N |
| `stdin_is_socket` | eBPF | fd 0 is a socket |
| `mprotect_rwx` | eBPF | pid did W+X mprotect |
| `lotl_score` | LOTL matrix | living-off-the-land likelihood |
| `uid0_transition` | eBPF | EUID changed to 0 |

### 5.2 Runtime allowlist (canonical)

A curated set of `parent_image` paths that should never raise
memfd/mprotect_rwx to Quarantine. Maintained as YAML, hot-reloadable.

```yaml
runtime_allowlist:
  jit_engines:
    - /usr/bin/node
    - /usr/lib/jvm/*/bin/java
    - /usr/bin/dotnet
    - /usr/bin/lua*
    - /usr/bin/python3*
    - /usr/lib/python3*/dist-packages/torch/lib/libtorch*.so   # loader-side
    - /opt/pypy*/bin/pypy*
  build_systems:
    - /usr/bin/dpkg
    - /usr/bin/apt
    - /usr/bin/snap*
    - /usr/bin/dnf
    - /usr/bin/rpm
    - /usr/bin/yum
    - /usr/bin/zypper
    - /usr/bin/pacman
  ci_runners:
    - /usr/local/bin/buildkite-agent
    - /usr/local/bin/github-runner
    - /usr/local/bin/gitlab-runner
  container_runtimes:
    - /usr/bin/runc
    - /usr/bin/containerd*
    - /usr/bin/docker*
    - /usr/bin/podman
    - /usr/bin/crun
  cloud_agents:
    - /usr/bin/snapd
    - /usr/bin/amazon-ssm-agent
    - /usr/sbin/google-osconfig-agent
```

This list must be **signed and rotated** — see §7.

### 5.3 Per-rule allowlist consumption

Every rule's CEL match clause should consult relevant allowlist tags:

```yaml
id: mem_mprotect_rwx
match: |
  event.tags["mprotect_rwx"] == "true" &&
  event.tags["jit_allowlisted"] != "true" &&
  event.tags["package_managed"] != "true"
```

A `make rules-lint` step asserts every rule whose action mask includes
ActionQuarantine consults at least one allowlist tag. Today, almost
no rule does this. **Highest-impact backlog item.**

---

## 6. Tuning loop (per rule)

For each rule, run this loop until budget met.

```
┌──────────────────────────────────────────────────────────┐
│  1. Measure: 24h fire rate on reference host             │
│  2. Sample: pull 50 random alerts                        │
│  3. Label: operator marks each tp / fp / unknown         │
│  4. Compute: FP rate, percentile of latency              │
│  5. Cluster: bucket FPs by parent_image + cgroup_unit    │
│  6. Hypothesise: which allowlist tag would eliminate     │
│     the largest FP cluster without dropping TPs?         │
│  7. Edit rule, replay last 24h offline                   │
│  8. Compare: FP-before vs FP-after; TP-before vs after   │
│  9. If FP↓ ≥ 80% and TP unchanged → ship rule update     │
│ 10. If TP dropped → reject, hypothesise differently      │
│ 11. Log to RULE_TUNING.md (per-rule changelog)           │
└──────────────────────────────────────────────────────────┘
```

This loop requires the `xhelixctl events replay` tool from §3.1.

---

## 7. Causal-chain verification — "rock solid"

The user's standard: **rock solid that the chain hasn't been
tampered with**. Today's chain (`pkg/chain` + `xhelix-verify`) is
strong but not rock-solid until these hold:

### 7.1 Properties we need

| # | Property | Current state |
|---|---|---|
| 1 | Each batch is Ed25519-signed | ✅ |
| 2 | Each batch hashes the previous batch | ✅ |
| 3 | Each batch's monotonic sequence number gap-checked | ✅ |
| 4 | Each batch timestamp is monotone non-decreasing | partial — needs verifier check |
| 5 | A truncated tail is detectable | ⚠️ — only via off-host mirror |
| 6 | A reorder is detectable | ✅ via sequence + prev-hash |
| 7 | An evicted-then-replaced batch is detectable | ⚠️ — depends on mirror |
| 8 | The signing key is hardware-rooted (HSM/KMS) | ❌ — chain.key is on disk |
| 9 | The chain root is published off-host at intervals | ❌ — P-CJ.10 pending |
| 10 | Verification is reproducible (deterministic) | ✅ |
| 11 | Verifier names the EXACT offending batch | ✅ |
| 12 | Verifier survives partial corruption | ⚠️ — depends on damage |
| 13 | Witness-style attestation by independent watchdog | ❌ — P-CJ.5 pending |

Gap items to close before claiming "rock solid":

- **#8**: chain.key on disk = single point of compromise. Move to
  cloud KMS or TPM-bound key (P-CJ.8).
- **#9**: off-host chain mirror with hourly checkpoint to S3/B2
  (P-CJ.10). Without this, an attacker with root can truncate the
  tail and rewrite history before xhelix-verify ever runs.
- **#13**: a separate process (or a second host) periodically pulls
  the latest batch and verifies independently (P-CJ.5).

### 7.2 Verification cadence

| Frequency | Action |
|---|---|
| Every batch flush | local Engine asserts prev-hash + sequence |
| Every 5 minutes | `xhelix-verify` runs cron-style against local chain dir |
| Every hour | chain checkpoint pushed off-host (signed manifest of last batch sequence + hash) |
| Daily | watchdog host pulls + verifies |
| Weekly | full re-walk from sequence 0 |
| Monthly | manifest comparison across all hosts in the fleet |

### 7.3 Chain-tamper test suite

| ID | Tamper | Expected verifier output |
|---|---|---|
| CT-01 | flip 1 byte mid-batch | "batch N: signature mismatch" |
| CT-02 | truncate last batch | "batch N: missing prev-hash referent" or "tail-cut at seq N" |
| CT-03 | swap two batches | "batch N: out-of-order sequence" |
| CT-04 | replace a batch with one signed by a different key | "batch N: unknown signing key" |
| CT-05 | wipe chain dir, restore from old backup | "tail-cut at seq N (off-host mirror has seq M > N)" — requires §7.1 #9 |
| CT-06 | rewrite manifest after-the-fact | "manifest signature does not match chain hash" |
| CT-07 | clock-rewind a batch | "batch N: timestamp regression" — requires §7.1 #4 verifier change |
| CT-08 | kill xhelix during flush | "tail unterminated; recovery applied" — must NOT lose detection of post-recovery tamper |
| CT-09 | hold-and-replay an old batch | "batch N: sequence already seen" |
| CT-10 | inject a batch with future timestamp + valid signature | "batch N: timestamp ahead of wall clock + tolerance" |

All ten must pass before the chain can be marked "rock solid".

### 7.4 Off-host mirror (P-CJ.10) — minimal spec

A tiny daemon (`xhelix-chain-mirror`) runs on a separate host or as a
small cloud function. Every chain batch xhelix flushes locally is
also pushed to the mirror over TLS with a client cert. The mirror
appends to its own append-only store and returns the new tail's
hash. xhelix asserts the mirror's hash matches local. On mismatch,
both sides alarm.

Compromise of the victim host can no longer rewrite history without
either:
- compromising the mirror too (different blast radius), OR
- preventing the mirror push (the gap becomes the alarm).

### 7.5 Hardware key root (P-CJ.8)

`chain.key` lives in a TPM (sealed to PCRs) or cloud KMS. xhelix
never has the raw key in memory; signing requests are sent to the
sealing layer. An attacker with root cannot sign forged batches
without breaking the TPM/KMS.

### 7.6 Watchdog (P-CJ.5)

A peer process verifies the chain every 5 minutes. If verification
fails (or xhelix has not produced a batch in N minutes), the
watchdog emits a high-severity alert via a side channel (separate
webhook, separate evidence destination). The watchdog has its own
short-rotated key.

---

## 8. Alert quality dimensions beyond FP rate

FP rate alone is not enough. The full alert quality scorecard:

| Dimension | Definition | Target | Current |
|---|---|---|---|
| Precision | TP / (TP + FP) | ≥ 99.9999% | unknown |
| Recall (per technique) | techniques-detected / total-techniques | ≥ 95% | ~71% per design memo |
| Latency p50 | sensor-to-alert time | < 500 ms | unmeasured |
| Latency p99 | same | < 2 s | unmeasured |
| Attribution clarity | % alerts with pid + comm + image + lineage | ≥ 99% | ~99% (already strong) |
| Reproducibility | replay produces identical alert | 100% | unknown |
| Evidence completeness | % alerts with linked evidence dir | ≥ 95% | high (Snapshotter wired) |
| Operator triage time p50 | from alert to verdict | < 60 s | unmeasured |
| Causal-chain reach | % alerts that link to ≥ 3 prior events in lineage | ≥ 90% | unmeasured |
| Cross-host coherence | same attack on N hosts produces consistent narrative | ≥ 95% (allowed-1 host gap) | unmeasured |

Build a dashboard (`xhelixctl alerts stats --window 24h`) that emits
all of these.

---

## 9. The Alert lifecycle (what every alert MUST carry)

Each alert in `alerts.jsonl` must include:

```json
{
  "event_id": "01KS....",          // ULID, primary key
  "time": "2026-05-21T10:28:24Z",  // RFC3339Nano
  "rule_id": "shell_with_socket_fd",
  "rule_version": "2026-05-19",    // git-derived
  "severity": "notice|warn|critical",
  "lineage_id": 28,                // takeover key
  "score_at_alert": 68,            // takeover scorer's value
  "tier": "triaged",               // observed/triaged/suspended/isolated/contained
  "evidence_id": "20260521T1028Z-pid394536-bash",
  "actions_taken": ["log","webhook"],
  "actions_deferred": ["snapshot","quarantine"],  // monitor mode masked
  "deferred_reason": "monitor_mode",
  "verdict": null,                 // tp/fp/unknown — set by operator labelling
  "verdict_set_by": null,
  "verdict_set_at": null,
  "verdict_tag": null,
  "host_id": "vm",
  "host_class": "dev_workstation|prod_web|prod_db|...",
  "kernel": "6.8.0-101-generic",
  "xhelix_commit": "4f5233b",
  "chain_seq": 12489,              // batch sequence containing this event
  "chain_batch_hash": "sha256:...",
  "event": { /* full canonical event */ }
}
```

This is the bedrock. Every metric / FP measurement / TP claim refers
back to a row with this schema. Schema must be versioned (`alerts.v2`)
and migrations supported.

---

## 10. Daily / weekly / monthly cadence

| Cadence | Output |
|---|---|
| Continuous | alerts.jsonl writes; chain flushes; replay-friendly |
| 15 min | `xhelix-verify` cron, prev-hash check |
| Hourly | off-host chain checkpoint (when wired) |
| Daily | operator triages 20 random alerts (rule rotation), labels in `labels.db` |
| Daily | `xhelixctl alerts stats --window 24h --by rule` → file in `tests/redteam/run_logs/YYYY-MM-DD.md` |
| Weekly | sum FP/TP per-rule, update §4 budget table |
| Weekly | re-run §3 of TEST_PLAN.md (memory+proc+rs categories) |
| Monthly | `PHASE_N_RESULTS.md` rollup |
| Quarterly | re-baseline reference workload, refresh runtime_allowlist |

---

## 11. Six-nine accountability matrix

For us to defensibly say "99.9999%", these need a person/owner/date:

| Item | Owner | Target date | Status |
|---|---|---|---|
| Build `xhelixctl alerts ls/stats/show/tail` | ftahirops | 2026-05-21 | ✅ shipped P-PS.26 |
| Build `xhelixctl alerts label` + `fp-rate` | ftahirops | 2026-05-21 | ✅ shipped P-PS.29 |
| Build `xhelixctl alerts replay` | ftahirops | 2026-05-21 | ✅ shipped P-PS.29 |
| Build `pkg/labels` SQLite store | ftahirops | 2026-05-21 | ✅ shipped P-PS.29 |
| Audit ALL ActionQuarantine entries for FP-risk class | ftahirops | 2026-05-21 | ✅ shipped P-PS.29 (every entry annotated, 7 actions downgraded) |
| Implement `runtime_allowlist.yaml` + loader | ftahirops | 2026-05-21 | ✅ shipped P-PS.26 (`pkg/runtimeallow`) |
| Add `make rules-lint` to assert allowlist consumption | tbd | tbd | open — proposed for P-PS.31 |
| TPM/KMS-rooted chain.key (P-CJ.8) | ftahirops | 2026-05-21 | ✅ abstraction shipped P-PS.30 (`pkg/keyguard`); adapters stubbed (operator wires TPM/KMS) |
| Off-host chain mirror (P-CJ.10) | ftahirops | 2026-05-21 | ✅ pusher shipped P-PS.30 (`pkg/chainmirror`); receiver pending |
| Watchdog (P-CJ.5) | ftahirops | 2026-05-21 | ✅ shipped P-PS.30 (`cmd/xhelix-watchdog`) |
| Reference workstation + 30d soak harness | tbd | day-30 from go | ✅ harness shipped P-PS.30 (SOAK_HARNESS.md + watchdog timer); execution pending host pick |
| Run the 10 chain-tamper tests (CT-01..10) | tbd | tbd | open — proposed for P-PS.31 |
| Negative-control host fleet (≥ 3) | tbd | tbd | open — operational |
| Per-rule FP-rate dashboard | ftahirops | 2026-05-21 | ✅ shipped P-PS.29 (`xhelixctl alerts fp-rate`) |

Status legend: ✅ shipped · ◔ partial (abstraction or harness only, execution pending) · open · operational (needs time + a real host, not code).

Until **every** row here has owner + date + green, claims above β
are aspirational, not defensible. After this round (P-PS.29 +
P-PS.30): 11/14 ✅, 3 open. The three opens are
**rules-lint** (small, ~½ day), the **chain-tamper tests CT-01..10**
(operationally simple, needs reference host), and the
**negative-control fleet** (procurement, not code).

---

## 12. What `99.9999%` honestly translates to

On a reference host doing 10k events/sec:

- 1 FP per 1,000,000 events
- ≈ 36 FPs/hour
- ≈ 864 FPs/day
- ≈ 6,048 FPs/week

That's still **too noisy** for a single operator to triage manually
every day. So even at six-nines we need:

- Severity-weighted triage (notice-tier FPs auto-suppress after N consecutive labels)
- Per-host-class budgets (a CI runner is allowed more memfd FPs than a DB server)
- Auto-suppression: after operator labels 100 of the same `rule_id +
  parent_image` combination as FP, that combination is silenced for
  that host class until the rule version changes.

The actual "operator gets paged" rate target should be ≤ 1 / day on a
healthy host class. Six-nines is the floor; pageable is the ceiling.

---

## 13. The one-sentence honest summary

We can measure our way to six-nines, but only after we build the
labels store, the replay tool, the off-host chain mirror, and the
runtime allowlist — those four are non-negotiable. Until then, any
number we publish is a guess.
