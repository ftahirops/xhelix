# xhelix — Roadmap

> Implementation phasing for the locked architecture in [ARCHITECTURE.md](ARCHITECTURE.md).
> Each phase has: scope, ordered tasks, success criteria, performance
> implementation spec, and explicit out-of-scope items.

---

## Phase summary

| Phase | Name                              | Days | Status     |
| ----- | --------------------------------- | ---: | ---------- |
| P1    | Evidence truth foundation         |    5 | planned    |
| P2    | Hot causal graph + cold store     |    4 | planned    |
| P3    | High-value collectors             |    4 | planned    |
| P4    | Deterministic decisions           |    4 | planned    |
| P5    | UI / RCA / operator workflow      |    3 | planned    |
| P6    | Hardened mode (optional add-on)   |    3 | planned    |
| P7    | Data Leak Containment Fabric      |   55 | planned    |

Total core ship: 17 days (P1–P4). Polished release: 23 days (P1–P6).
DLCF subsystem (P7): adds ~11 weeks on top, split into v1/v2/v3 (see § Phase 7).

P1–P4 are sequential. P5 can start in parallel with P4 once P3 is done.
P6 has no dependencies on P5 and can be deferred indefinitely.

---

## Phase 1 — Evidence truth foundation

**Goal**: Every event that reaches the rule engine is canonicalized,
PID-reuse-safe, race-free, and tagged with source trust grade. No
rules yet; no decisions yet. Pure plumbing.

### Tasks

- [ ] **P1.1 — ProcKey identity model**
  - [ ] Replace all internal `uint32 pid` keys with `ProcKey{pid, start_ns}`
  - [ ] Read `start_time` from `/proc/PID/stat` field 22 at first observation
  - [ ] Cache `ProcKey → enrichment` map with TTL = process lifetime
  - [ ] Invalidate cache entry on `sched_process_exit`
  - [ ] Unit tests for PID reuse scenario

- [ ] **P1.2 — Canonicalizer**
  - [ ] Canonical path resolver with symlink chase, mount-aware
  - [ ] Socket inode → owning pid via /proc/PID/fd scan + sock_diag fallback
  - [ ] cgroup path from /proc/PID/cgroup line
  - [ ] pidns/mntns/netns inodes from /proc/PID/ns/*
  - [ ] Container ID parsed from cgroup line (docker/, kubepods/, lxc/)

- [ ] **P1.3 — Event Admission Controller**
  - [ ] Bounded ring buffer per CPU; events ordered by `bpf_ktime_get_ns()`
  - [ ] Reorder window: configurable 50-200 ms, default 100 ms
  - [ ] `/proc` enrichment scheduled in parallel with reorder wait
  - [ ] Events admitted with `partial=true` if enrichment incomplete at window close
  - [ ] Loss detection: ringbuf overflow counters surfaced as `health.source_loss` events
  - [ ] Source grading attached to every event (A+ / A / B / C)

- [ ] **P1.4 — Lineage ID chain**
  - [ ] Six lineage roots identified: SSH, PAM, cron, systemd, container, sudo
  - [ ] `LineageIDs []uint64` propagated from parent to child at exec
  - [ ] Sudo creates inner lineage_id, preserves outer
  - [ ] SSH session lineage extracted from `SSH_CLIENT` env + sshd lineage
  - [ ] Lineage_id index in the graph

- [ ] **P1.5 — Self-exclusion universal**
  - [ ] BPF programs check `xh_is_self()` for own cgroup (not just pid)
  - [ ] Userspace double-check on event admission
  - [ ] xhelix's own activity logged at debug level only, never as security event

- [ ] **P1.6 — Health metrics + drop accounting**
  - [ ] Per-source-grade event counters
  - [ ] Drop counters: BPF, ringbuf, enrichment queue, cold writer
  - [ ] Exposed via LocalAPI `health.snapshot`

### Success criteria

- PID reuse test: create 100 short-lived processes with deliberate PID
  reuse; graph correctly distinguishes them via start_ns
- Out-of-order test: inject events from 4 CPUs with reverse timestamps;
  EAC emits in correct order at window close
- /proc race test: fork+exit pid during enrichment; event admitted
  with `partial=true`, no panic
- Self-exclusion test: xhelix's own file_open of policy.yaml never
  appears in the event stream

### Performance implementation spec

| Target                              | Mechanism                                           |
| ----------------------------------- | --------------------------------------------------- |
| ProcKey lookup < 1 µs               | sharded `map[ProcKey]*ProcessNode`, 16-way RWMutex  |
| Enrichment cache hit                | per-ProcKey cache; populate at exec; evict at exit  |
| /proc read avoided per event        | enrichment cache lookup; only read /proc on cache miss |
| Reorder window doesn't stall syncs  | sync rules bypass EAC entirely, operate on raw      |

### Out of scope (P1)

- BPF LSM file_open (P3)
- Rule evaluation (P4)
- UI changes (P5)

---

## Phase 2 — Hot causal graph + cold store

**Goal**: Every admitted event lands in two places — the hot graph
(in-memory, 30-min retention, queryable) and the cold store (SQLite,
daily partitions, append-only).

### Tasks

- [ ] **P2.1 — Hot graph data structures**
  - [ ] `nodes map[ProcKey]*ProcessNode` primary
  - [ ] Index by cgroup, by lineage_id, by origin_ip, by tty
  - [ ] Edge map: `children map[ProcKey][]ProcKey`
  - [ ] File/socket nodes alongside process nodes (whole-system DAG)

- [ ] **P2.2 — Retention + eviction**
  - [ ] Live processes: in graph until exit + 5 min
  - [ ] Dead processes: 30 min warm, then forensic stub
  - [ ] Verified-alert chains: pinned for 24 h
  - [ ] LRU eviction triggered at 80% of memory budget
  - [ ] Eviction emits `health.eviction` event with counters

- [ ] **P2.3 — Cold writer**
  - [ ] SQLite database with daily partition tables
  - [ ] Schema: events, evidence_buckets, verified_alerts, acks, lineage_index
  - [ ] WAL mode, `synchronous=NORMAL`, journal_size_limit set
  - [ ] Bounded write-behind queue (256k entries default)
  - [ ] Drop oldest on overflow; emit `health.cold_overflow`
  - [ ] Batch writes (1000 rows per transaction)
  - [ ] Daily partition rotation at 00:00 UTC

- [ ] **P2.4 — Evidence bucket aggregation**
  - [ ] Bucket key: `(rule_id, kind, actor_exe_sha, target_class, cgroup, origin_type, 1-min window)`
  - [ ] Aggregate: first_seen, last_seen, count, sample_event_ids (up to 8)
  - [ ] Bucket promotion: operator-marked buckets become candidate rules

- [ ] **P2.5 — Graph query API**
  - [ ] `GET /api/v1/graph/lineage/<lineage_id>` — full chain
  - [ ] `GET /api/v1/graph/process/<proc_key>/ancestors`
  - [ ] `GET /api/v1/graph/process/<proc_key>/descendants`
  - [ ] `GET /api/v1/graph/by_origin/<ip>` — all processes from origin
  - [ ] All queries hot-graph-first, cold-store fallback for older data

### Success criteria

- 50k events/sec sustained for 5 minutes, cold writer keeps up
- 30k events/sec sustained for 1 hour, no drops, no growth in queue
- Memory under 256 MB at 50k live process simulation
- Graph queries < 1 ms for any lineage chain in hot retention
- Eviction stress test: fill to 80%; LRU keeps total within bound

### Performance implementation spec

| Target                      | Mechanism                                       |
| --------------------------- | ----------------------------------------------- |
| Graph insert < 10 µs        | per-shard lock, pre-sized maps                  |
| Lineage lookup < 1 µs       | `byLineageID[uint64][]EventRef` map             |
| Cold write 30k/s            | 1000-row batched prepared inserts, WAL mode     |
| Memory per live proc < 4 KB | inline scalars; intern strings (exe path, cgroup) |

### Out of scope (P2)

- BPF LSM file_open events (P3)
- Verified alerts (P4)
- ClickHouse sidecar (deferred indefinitely)

---

## Phase 3 — High-value collectors

**Goal**: Wire the kernel-side collectors that produce the highest-signal
events. Each one feeds the EAC → canonicalizer → enrichment → graph
pipeline already built.

### Tasks

- [ ] **P3.1 — BPF LSM `file_open` sensitive-path gate**
  - [ ] Kernel-side path filter using inode set from sensitive catalog
  - [ ] Initial catalog: ~30 path globs (SSH, AWS, kube, env, GPG, browser, wallets)
  - [ ] Operator can extend via `/etc/xhelix/sensitive_paths.yaml` hot-reload
  - [ ] Event includes target inode, mount, mode, owner

- [ ] **P3.2 — Persistence-write watchlist**
  - [ ] BPF LSM `file_open` with O_WRONLY filter on persistence path set
  - [ ] Paths: `/etc/cron.*`, `/etc/systemd/system/*`, `~/.ssh/authorized_keys`,
    `/etc/ld.so.preload`, `/etc/sudoers.d/*`, `/etc/profile.d/*`,
    `~/.bashrc`, `~/.profile`, `~/.config/systemd/user/*`,
    `/etc/cron.d/*`, `/var/spool/cron/*`
  - [ ] Event tagged with `class=persistence`

- [ ] **P3.3 — Byte-count kprobes (already partial in code)**
  - [ ] tcp_sendmsg, tcp_recvmsg, udp_sendmsg, udp_recvmsg
  - [ ] ≥64-byte filter in kernel
  - [ ] UDP connstate row creation on first udp_sendmsg for a flow

- [ ] **P3.4 — ptrace + memory-injection detection**
  - [ ] BPF LSM `ptrace_access_check` hook for PTRACE_ATTACH, POKE*
  - [ ] kprobe `process_vm_writev`
  - [ ] /proc/PID/mem open detection via file_open
  - [ ] Self-exclusion ensures debugger sessions targeting xhelix don't recurse

- [ ] **P3.5 — Namespace transition events**
  - [ ] kprobe `setns`, `unshare` with new-NS flags
  - [ ] Event records old NS inodes vs new NS inodes
  - [ ] Container boundary cross flagged explicitly

- [ ] **P3.6 — AF_PACKET sniffer hardening**
  - [ ] Already in place for TLS SNI; extend to JA3 fingerprint
  - [ ] Add per-flow sample of first 256 bytes for HTTP plaintext (host header)
  - [ ] Per-flow cap to prevent payload buffer growth

- [ ] **P3.7 — journald subscription**
  - [ ] sd-bus subscriber for `_COMM=sshd`, `_COMM=sudo`, `_COMM=su`, PAM
  - [ ] Events folded into lineage chain at corresponding root
  - [ ] No PAM module required for this path

### Success criteria

- curl https://example.com generates: tcp_connect + tcp_sendmsg ≥64 +
  AF_PACKET SNI, all attributed to the curl ProcKey, all reach hot graph
- `cat /root/.ssh/id_ed25519` triggers file_open event with target.class=sensitive_secret
- `tee /etc/cron.d/x` triggers persistence event with class=persistence
- `gdb -p <pid>` triggers ptrace event with target.pid
- `unshare -n` triggers namespace transition event
- ssh from a known IP creates a lineage_id rooted at sshd; subsequent
  exec of bash inherits the lineage chain

### Performance implementation spec

| Target                                | Mechanism                                       |
| ------------------------------------- | ----------------------------------------------- |
| BPF file_open filter < 200 ns         | inode set in BPF_MAP_TYPE_HASH, O(1) lookup      |
| BPF tcp_sendmsg overhead < 500 ns/event | ≥64-byte filter rejects keepalives at kernel boundary |
| journald subscriber CPU < 0.5%         | filter by `_COMM` in sd-bus subscribe, not userspace |

### Out of scope (P3)

- Rule engine (P4)
- PAM module (P6)
- IMA ingestion (P6)
- ClickHouse sidecar

---

## Phase 4 — Deterministic decisions

**Goal**: Closed-grammar rule engine with verified / candidate /
evidence classification, ack ledger, maintenance window, sync + async
enforcement.

### Tasks

- [ ] **P4.1 — Predicate implementation (18 predicates)**
  - [ ] Each predicate in `pkg/rules/predicates.go`
  - [ ] Per-predicate doc comment with: returns, data dependency, cost
  - [ ] Each predicate tagged `pre_admission_safe: true|false`
  - [ ] Unit tests for each predicate; benchmark for cost target

- [ ] **P4.2 — Rule compiler + evaluator**
  - [ ] YAML rule loader with strict schema validation
  - [ ] Composite rules: `events[]`, `window`, `match.all_of|any_of`, `actor: same_as:<tag>`
  - [ ] Per-(event.kind, target.class) rule index for sub-100µs evaluation
  - [ ] Rule type dispatch: single_event | composite | kernel_context_rule

- [ ] **P4.3 — Shipped rule catalog (10 rules)**
  - [ ] `sensitive_file_read_unauthorized_actor`
  - [ ] `persistence_write_unauthorized_actor`
  - [ ] `sensitive_read_then_novel_egress` (composite)
  - [ ] `sudo_escalation_then_persistence_write` (composite)
  - [ ] `web_worker_spawned_shell` (composite)
  - [ ] `ptrace_attach_to_service_process`
  - [ ] `memfd_exec_with_network_egress` (composite)
  - [ ] `container_escape_host_secret_read` (composite)
  - [ ] `unsigned_kernel_module_load` (kernel_context_rule)
  - [ ] `loginshell_spawned_from_non_tty_parent`

- [ ] **P4.4 — Ack ledger**
  - [ ] Append-only ledger inside the signed audit chain
  - [ ] Ack fields: rule, actor.exe_sha, actor.uid, actor.loginuid,
    origin.type, origin.ip, target.inode, ttl, reason, created_by_uid
  - [ ] `matched_count`, `last_matched_at` updated on each match
  - [ ] Context-shift detection: Tier-2 fields differing from original ack
  - [ ] LocalAPI `policy.ack`, `policy.ack_list`, `policy.ack_revoke`

- [ ] **P4.5 — Maintenance window**
  - [ ] `policy.maintenance_window_start` / `_end` LocalAPI
  - [ ] Scope: user, optional cgroup glob
  - [ ] Hard cap 15 min; no auto-extend
  - [ ] Banner displayed in UI while active
  - [ ] Window start/end are signed audit-chain entries

- [ ] **P4.6 — Enforcement plumbing**
  - [ ] Sync deny via cgroup_sock_addr (per-cgroup eBPF program)
  - [ ] Async contain: SIGSTOP subtree + nft drop destination
  - [ ] Sync rules validated at load time to use only `pre_admission_safe` predicates
  - [ ] Enforcement results recorded on every verified alert

- [ ] **P4.7 — Verified / candidate / evidence classification**
  - [ ] Every rule match emits one of three classes
  - [ ] Tier-1 completeness check before verified classification
  - [ ] Source-loss check downgrades verified → candidate

### Success criteria

- 10-rule catalog loads, validates, executes
- A `cat /etc/shadow` from non-allowlisted actor produces a verified alert
  with full chain
- A composite `sensitive read + novel egress` produces a verified alert
  with SIGSTOP applied to the subtree within 2 s of the egress
- An ack with TTL 1h suppresses matching events; context-shift surfaces
  matching events with a "shifted" tag
- Maintenance window suppresses alerts but records them as evidence
- Rule evaluation under 100 µs p99 for 20 loaded rules
- Sync rule using a non-pre-admission-safe predicate is rejected at load

### Performance implementation spec

| Target                            | Mechanism                                              |
| --------------------------------- | ------------------------------------------------------ |
| Rule eval < 100 µs                | per-(kind,class) index narrows candidates per event    |
| Predicate `chain.contains_exe`    | depth-capped graph walk (≤16 hops), short-circuit       |
| Predicate `has_recent_event`      | per-actor circular buffer (last 32 events × 60 s)       |
| Ack lookup O(1)                   | `map[ackKey]*Ack` keyed by canonical context tuple     |

### Out of scope (P4)

- UI policy editor improvements (P5)
- LLM analyst slot (deferred indefinitely)
- Network-wide policy distribution (out of single-host scope)

---

## Phase 5 — UI / RCA / operator workflow

**Goal**: Operator can investigate, ack, edit policy, and run RCA
queries entirely from the web UI. No more YAML editing required for
common workflows.

### Tasks

- [ ] **P5.1 — Verified alert proof tree**
  - [ ] Alert detail view renders the full causal chain as a tree
  - [ ] Each node shows: actor, target, time, lineage_id, source grade
  - [ ] Click any node → drill into that process or file

- [ ] **P5.2 — Candidate triage tab**
  - [ ] Lists candidate-class events
  - [ ] Operator can: ack, promote to evidence-only rule, escalate to verified
  - [ ] Bulk actions: ack-all-by-pattern, dismiss-all

- [ ] **P5.3 — Evidence search**
  - [ ] Full-text + structured query on evidence buckets
  - [ ] Time range, exe, target, origin, lineage_id filters
  - [ ] Bucket detail expands to sample events

- [ ] **P5.4 — Lineage timeline**
  - [ ] Given a lineage_id, render every event in time order
  - [ ] Process spawns + file accesses + network connects on one timeline
  - [ ] Export as JSON for offline forensics

- [ ] **P5.5 — Per-process policy editor (in-UI YAML-free)**
  - [ ] Click a process row → policy editor modal
  - [ ] Allow-only-domains, deny-domains, deny-ports as line-per-entry textareas
  - [ ] Save writes one `policy.upsert_app` LocalAPI call

- [ ] **P5.6 — "Why did this happen?" view**
  - [ ] Given any verified alert, show the predicate-by-predicate trace
  - [ ] Each predicate result with its data source and match value
  - [ ] One-click "edit rule" if the rule needs tuning

### Success criteria

- Alert detail loads in < 1 s for any verified alert in hot retention
- Evidence query returns 1000 results in < 2 s on 30 GB cold store
- Lineage timeline renders 500 events in < 500 ms
- Per-process editor save round-trip < 200 ms

### Out of scope (P5)

- Mobile-responsive design (deferred)
- Multi-host fleet dashboard (out of single-host scope)
- Real-time collaboration (out of scope)

---

## Phase 6 — Hardened mode (optional add-on)

**Goal**: For high-assurance deployments, integrate kernel integrity
features. None of this is on by default; all of it is opt-in via
explicit configuration.

### Tasks

- [ ] **P6.1 — IMA ingestion**
  - [ ] Read `/sys/kernel/security/ima/ascii_runtime_measurements`
  - [ ] Map IMA hashes to executed processes via ProcKey
  - [ ] Surface as `actor.ima_hash` Tier-2 field

- [ ] **P6.2 — Module signing state**
  - [ ] Parse `/proc/modules` + signature state per module
  - [ ] Rule: alert on any unsigned module load

- [ ] **P6.3 — Lockdown state observation**
  - [ ] Read `/sys/kernel/security/lockdown`
  - [ ] Surface in `health.snapshot`
  - [ ] Rule: alert if lockdown transitions from `confidentiality` to `integrity` or `none`

- [ ] **P6.4 — Secure Boot state**
  - [ ] Read EFI variables for SecureBoot status
  - [ ] Surface in `health.snapshot`

- [ ] **P6.5 — TPM-sealed audit chain key (optional)**
  - [ ] Audit chain signing key sealed under PCR values
  - [ ] Daemon unseals at startup; sealing fails if boot chain changed
  - [ ] Behind `tpmhw` build tag (preserves CGO-free default)

- [ ] **P6.6 — Hardened-mode installation playbook**
  - [ ] Document kernel cmdline: `lockdown=integrity ima_policy=appraise_tcb module.sig_enforce=1`
  - [ ] Document Secure Boot + signed kernel + signed initramfs
  - [ ] Document MOK enrollment for self-signed modules
  - [ ] Document recovery if integrity check fails at boot

### Success criteria

- IMA hashes appear in events when `ima_policy` is set
- Unsigned module load produces a verified kernel-context alert
- Daemon refuses to start in hardened mode if PCR values don't match expected

### Out of scope (P6)

- Remote attestation server (out of single-host scope)
- Cross-host PCR-comparison (out of scope)

---

## Phase 7 — Data Leak Containment Fabric (DLCF)

**Goal**: Detect and block data exfiltration without firehose recording.
Built on the lineage chain from P1. Full design in
[DATA_LEAK_FABRIC.md](DATA_LEAK_FABRIC.md). Three sub-phases.

### P7 v1 — cheap tier (~5 weeks, ~25 days)

Builds the core fabric using only event-tier infrastructure already paid
for by P1–P4. No new in-band components.

| Task   | Description                                                | Days |
| ------ | ---------------------------------------------------------- | ---: |
| P7.1.1 | Data Catalog: YAML schema + loader + sensitivity table     |    3 |
| P7.1.2 | Extend `pkg/lineage` with `TaintSet` (bitset) + propagator |    4 |
| P7.1.3 | Sensitivity Budget counters (bucketed sliding window)      |    5 |
| P7.1.4 | LocalAPI: `taint.snapshot`, `budget.usage`, `passport.list`|    2 |
| P7.1.5 | Canary rules pack (~10 detectors over alert bus)           |    3 |
| P7.1.6 | Egress Valve: extend `pkg/netban` with taint-aware policy  |    5 |
| P7.1.7 | Data Passport: issuance CLI + ed25519 verifier             |    3 |

**Success criteria (v1)**
- Catalog loads from `ruleset/dlcf/catalog.yaml` and is hot-reloadable.
- `pkg/lineage` carries a `TaintSet` per lineage root; propagation is
  atomic and append-only.
- Sensitivity budgets enforce per-hour and per-day caps; overflow
  raises an alert with the contributing lineage chain.
- Canary touch raises a `severity=critical` alert in < 50 ms.
- Egress Valve blocks outbound connection when destination is not in
  the passport for the lineage's taint set.
- Daemon refuses to start in DLCF mode without a valid Control Plane
  pubkey for passport verification.

### P7 v2 — DB observation (~3 weeks, ~15 days)

Non-proxy DB visibility. Four layers; no SQL proxy in v2.

| Task   | Description                                                          | Days |
| ------ | -------------------------------------------------------------------- | ---: |
| P7.2.1 | eBPF DB socket watcher (labels endpoints from catalog, byte counts)  |    4 |
| P7.2.2 | MySQL `performance_schema` digest poller                             |    3 |
| P7.2.3 | PostgreSQL `pg_stat_statements` poller                               |    2 |
| P7.2.4 | App DB tap protocol over Unix socket (route/user/query-shape/rows)   |    3 |
| P7.2.5 | WordPress `wpdb` drop-in reference implementation                    |    3 |

**Success criteria (v2)**
- eBPF watcher reports bytes-in/out per (pid, DB endpoint) without
  parsing SQL.
- Digest poller surfaces new query shapes within 60 s of first
  execution.
- WordPress drop-in emits `db.query` events with route, user,
  shape hash, tables, row count — verified end-to-end against a live
  WP install.
- Tap, eBPF, and digest disagreement (e.g., app reports 10 rows but
  bytes suggest 10 MB) raises a `signal_disagreement` alert.

### P7 v3 — broker tier (~3 weeks, ~15 days)

Bulk-export accountability + role posture.

| Task   | Description                                              | Days |
| ------ | -------------------------------------------------------- | ---: |
| P7.3.1 | `cmd/xhelix-exportd/` daemon (Unix-socket IPC)           |    6 |
| P7.3.2 | Watermarking (CSV ordering + manifest signature)         |    3 |
| P7.3.3 | DB role posture lint in `xhelixctl posture db`           |    3 |
| P7.3.4 | Selective audit-plugin integration (MariaDB + Postgres)  |    3 |

**Success criteria (v3)**
- All bulk exports flow through `xhelix-exportd`; direct exports from
  php-fpm/nginx/node are denied by LSM hook.
- Every approved export carries a watermark traceable to passport id
  + operator id.
- `xhelixctl posture db` flags overprivileged DB users with concrete
  remediation steps.

### Out of scope (P7)

- Full SQL proxy (latency-sensitive, per-engine protocol burden — explicitly NOT planned).
- Byte-level memory taint tracking.
- Per-row value capture (shape + count only).
- Always-on DB audit of every statement.
- IDOR detection without app-supplied object identity.
- Business-logic leak detection without semantics.
- Response Valve (deferred to `xhelix-bridge` track, not DLCF).

---

## Open design questions (decisions still needed)

These don't block P1–P4 but should be resolved before P5.

1. **Cold tier query language.** SQL over the SQLite tables, a small
   custom DSL, or both? Recommendation: SQL for power users, a
   visual query builder in the UI for typical ops. Decide before P5.3.

2. **Evidence bucket compaction policy.** Buckets older than 24 h: keep
   per-minute granularity, or downsample to per-hour? Recommendation:
   per-hour after 24 h, per-day after 7 days. Tune from real workload data.

3. **Per-process policy editor identity binding.** Bind to comm, exe
   path, or exe_sha by default? Comm is most user-friendly but
   spoof-able. Exe_sha is robust but breaks on package updates.
   Recommendation: bind to (exe_path, current_sha) and warn the
   operator when sha changes (e.g., after `apt upgrade`).

4. **ClickHouse sidecar trigger.** At what cold-tier size or write
   rate does the UI suggest graduating? Recommendation: hard
   suggestion at 10 GB cold tier, soft hint at 5 GB.

5. **Maintenance window scope granularity.** Allow per-cgroup-glob
   scope (current design) or only per-user? Recommendation: keep
   per-cgroup-glob; document the risk model clearly.

---

## Cross-cutting concerns

These apply to all phases:

- **Testing**: Every public package has unit tests with race detector.
  Integration tests stand up a real kernel + collectors in CI on a
  fixed kernel version.

- **Backwards compatibility**: LocalAPI envelope format frozen; new
  fields added with omitempty. Rule YAML schema versioned;
  unrecognised top-level keys rejected.

- **Operator documentation**: Each shipped rule has a markdown card
  in `docs/rules/<rule_id>.md` (not pushed to public repo;
  generated from rule frontmatter) explaining when it fires, what
  to investigate, and how to safely ack.

- **Performance regression gates**: CI runs benchmarks for the
  performance targets in §7 of ARCHITECTURE.md. A 20% regression
  on any target fails the build.

- **Drop-and-record everywhere**: No queue is unbounded. Every drop
  is counted, surfaced via health metrics, and logged at warn level.

- **Self-audit**: xhelix records its own configuration changes,
  arm/disarm events, and ack creations in the same signed chain as
  security events.

---

## Definition of done (per phase)

A phase is done when:

1. All tasks marked complete in the checklist
2. Success criteria verified on the target host
3. Performance targets met (benchmark output recorded)
4. Unit + integration tests pass in CI
5. No new TODOs or `// fixme` in shipped code paths
6. The phase's user-facing behavior is reproduced from a clean install
7. ARCHITECTURE.md and this document are updated if any spec drifted

Done means done. No "mostly done." No "works on my machine."
