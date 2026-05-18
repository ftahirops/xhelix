# xhelix — Architecture (Locked)

> Causal Evidence Fabric for individual Linux hosts.
> Status: architecture locked. Implementation phasing in [ROADMAP.md](ROADMAP.md).

---

## 1. Mission

xhelix is a chain-attributed runtime security and observability engine for
individual Linux hosts. It detects, contains, and forensically attributes
post-exploitation behavior — credential theft, persistence installation,
command-and-control, and data exfiltration — using deterministic rules
over a kernel-grounded causal graph.

The same evidence layer answers root-cause-analysis, performance,
compliance, and audit queries. One data pipeline, two consumers.

xhelix does not replace network defenses, multi-factor authentication,
code signing, or measured boot. It complements them.

## 2. Honest scope

### Stops outright (hard prevention before damage)
- Outbound connection to a policy-denied destination (cgroup_sock_addr)
- Persistence-file write by a non-package-manager actor (BPF LSM)
- Unsigned kernel module load (kernel `module.sig_enforce=1`, observed)
- Telemetry endpoint connection (when hard-mode enforcement is armed)
- Connection from a non-allowlisted source IP to a sensitive port (nft)

### Detects and contains within milliseconds (composite verdicts)
- Web RCE → reverse shell → credential read → exfiltration
- Supply-chain compromise (npm/pip/apt postinstall reading secrets)
- Insider abuse: privileged user reads someone else's secrets
- Container escape touching host-sensitive resources
- Sudo escalation followed by sensitive file write

### Only detects (no live containment possible)
- Time-shifted attacks where read and exfil don't co-occur in a rule window
- In-memory-only attacks that touch no sensitive file and make no novel egress
- Operator-pattern attacks (legitimate-looking activity)

### Out of scope
- Kernel exploits that disable LSM hooks (requires kernel lockdown + IMA-appraise)
- Firmware / SMM / hypervisor attacks (requires measured boot + remote attestation)
- Physical access
- Side-channel attacks (Spectre/Meltdown class)
- Pre-boot / pre-daemon-start attacks

xhelix is honest about these limits. They require defense-in-depth at
layers above and below the host.

## 3. Design laws (non-negotiable)

1. **No raw event reaches rules.** Admission first, enrichment second,
   rules third.
2. **Tier-1 context complete = verified alert eligible; incomplete =
   evidence only.** Incomplete enrichment cannot fire a verified alert.
3. **Closed predicate grammar.** New predicates require code review.
   The rule language never becomes a free-form expression language.
4. **History is enrichment for display, never a rule gate.** First-seen
   counters surface novelty but cannot decide maliciousness.
5. **Synchronous enforcement uses pre-admission context only.**
   Asynchronous enforcement may wait for the reorder window.
6. **Acks are ledgered.** TTL-bound by default, blast-radius tracked,
   would-have-alerted events recorded as evidence. No silent suppression.
7. **Cold-tier writes cannot backpressure the hot path.** Drop with
   counter; never block kernel collectors.
8. **Self-exclusion is universal.** xhelix never observes its own
   activity as a security event.

## 4. Architecture (canonical reference)

```
┌──────────────────────────────────────────────────────────────┐
│ Kernel collectors                                            │
│ BPF LSM (file_open, inode_permission), tracepoints, kprobes  │
│ cgroup_sock_addr, sock_ops, AF_PACKET, audit, fanotify       │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│ Event Admission Controller (EAC)                              │
│ source grading, loss detection, kernel timestamp normalize,   │
│ bounded 50-200 ms reorder window, PID-reuse guard, /proc       │
│ race handling, self-exclusion, sequence validation            │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│ Canonicalizer                                                 │
│ (pid, start_ns) keys; canonical path + inode + mount;        │
│ socket inode → owner pid; cgroup path; ns inodes; exe path    │
└────────────────────────────┬─────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────┐
│ Enrichment Engine                                             │
│ Tier-1 mandatory: pid_start, exe, uid/euid, cgroup, ns,       │
│   target, chain rooted to init/systemd/container, source grade│
│ Tier-2 optional: exe_sha, package, loginuid, PAM session,     │
│   SSH key fingerprint, IMA hash, SNI, JA3/JA4                 │
│ lineage_ids chain assigned at SSH/PAM/cron/systemd/container/ │
│ sudo roots                                                    │
└────────────────────────────┬─────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
┌──────────────────────────┐    ┌──────────────────────────────┐
│ Hot causal graph         │    │ Cold evidence store           │
│ in-memory DAG            │    │ SQLite, daily partitions      │
│ 30 min retention warm    │    │ (ClickHouse sidecar at scale) │
│ lineage_id index         │    │ bounded write-behind queue    │
│ self-eviction LRU        │    │ drop-and-record on overrun    │
└────────────┬─────────────┘    └──────────────────────────────┘
             │
             ▼
┌──────────────────────────────────────────────────────────────┐
│ Deterministic Rule Engine                                     │
│ closed predicate grammar (18 named predicates)                │
│ allow → unless → deny semantics                               │
│ single-event + composite (events[], window, all_of, any_of)   │
│ classifies each match: verified | candidate | evidence        │
└────────────────────────────┬─────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐  ┌──────────────────┐  ┌───────────────────┐
│ Verified      │  │ Candidate        │  │ Evidence stream   │
│ alerts        │  │ triage           │  │ aggregated buckets│
│ (proof chain) │  │ (incomplete ctx) │  │ + queryable       │
└──────┬────────┘  └──────────────────┘  └───────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│ Enforcement                                                   │
│ sync deny: cgroup_sock_addr -EPERM at connect()               │
│ async contain: SIGSTOP subtree + nft destination block        │
│ evidence-only: no action, record only                         │
│ operator-confirmed: manual via UI                             │
└──────────────────────────────────────────────────────────────┘
```

## 5. Layer-by-layer specification

### 5.1 Kernel collectors

Trust grades for source signals:

| Grade | Source                                          | Use                |
| ----- | ----------------------------------------------- | ------------------ |
| A+    | BPF LSM hooks, eBPF tracepoints, cgroup BPF     | Decision-grade     |
| A     | Audit netlink, fanotify permission events       | Decision/evidence  |
| B     | /proc, /sys, sock_diag, journald                | Enrichment only    |
| C     | Application logs (nginx, php, app stdout)       | Attribution hints  |
| D     | Heuristics, statistical baselines               | Never for verified |

Active collectors:

- `sched_process_fork`, `sched_process_exec`, `sched_process_exit`
- BPF LSM `file_open` (sensitive-path catalog filter in kernel)
- BPF LSM `inode_permission` (optional strict mode; off by default)
- Kprobe `tcp_connect`, `tcp_sendmsg`, `tcp_recvmsg`, `udp_sendmsg`, `udp_recvmsg`
- BPF `cgroup_sock_addr` for synchronous deny
- BPF `sock_ops` for flow lifecycle
- AF_PACKET sniffer for TLS ClientHello SNI / JA3
- Audit netlink (fallback identity + compliance trail)
- Fanotify (file-permission events fallback)
- journald subscription (sshd, sudo, su, PAM logs)
- /proc and /sys polled for enrichment only, never for decision

### 5.2 Event Admission Controller

Mandatory pre-rules pipeline:

1. **Source grading** — every event tagged with its kernel source grade.
2. **Loss detection** — per-CPU ringbuf drops counted; affected events
   marked `lossy_source=true`. Verified alerts depending on lossy
   sources downgrade to candidate.
3. **Kernel timestamp normalization** — events ordered by `bpf_ktime_get_ns()`.
4. **Bounded reorder window** — events buffered for 50-200 ms before
   admission to allow out-of-order ringbuf arrivals to align. Window
   length tuned per workload; configurable.
5. **PID-reuse guard** — `(pid, start_ns)` is the actor key. A
   subsequent process with the same pid but different start_ns is a
   different actor in the graph.
6. **/proc race handling** — enrichment reads for a process are
   scheduled at event arrival in parallel with the reorder window.
   If the process exits before its enrichment completes, the event
   is admitted with what was captured + a partial flag.
7. **Self-exclusion** — events whose actor is in xhelix's own cgroup
   are dropped (already done in BPF for ringbuf cost reasons).
8. **Sequence validation** — events whose ancestry references a parent
   not yet known are queued briefly; if the parent never appears,
   the event is admitted with `chain_partial=true`.

Synchronous enforcement bypasses the reorder window. It operates on
pre-admission events with a restricted set of predicates (declared
per rule via `enforcement_class`).

### 5.3 Canonicalizer

Every event field is converted to a stable identity before enrichment.

| Raw            | Canonical                                                         |
| -------------- | ----------------------------------------------------------------- |
| PID            | `(pid, start_ns)` from `/proc/PID/stat` field 22                   |
| file path      | `realpath()`-resolved + inode + mount source                       |
| socket         | socket inode + remote (ip, port) + local (ip, port) + owner pid    |
| process binary | exe path + (if available) sha256 + (if available) package+signer   |
| identity       | uid + euid + loginuid + (if PAM module installed) PAM session id   |
| container      | cgroup path + pidns/mntns/netns inodes + container id (parsed)     |
| origin         | walked ancestry → first-matching root: ssh / web / cron / systemd / |
|                | container / local / kernel                                         |

Never used as identity: PID alone, comm alone, exe path alone, uid alone.

### 5.4 Enrichment tiers

**Tier-1 (mandatory for verified alerts):**

- `actor.pid_start_key`
- `actor.exe` (resolved path)
- `actor.uid`, `actor.euid`
- `actor.cgroup` (full path)
- `actor.pidns`, `actor.mntns`, `actor.netns`
- `target.canonical_path` or `target.socket_inode`
- `target.inode` (for file events)
- `chain.rooted` (chain walked successfully to PID 1 or container root)
- `source.grade`, `source.lossy`

**Tier-2 (optional, strengthens specific rules):**

- `actor.exe_sha256`
- `actor.package_owner` (apt/dpkg/rpm/snap query)
- `actor.signed`, `actor.signer`
- `actor.loginuid`
- `actor.pam_session_id`
- `origin.ssh_key_fingerprint`
- `actor.ima_hash`
- `network.sni`, `network.ja3`, `network.ja4`
- `target.fanotify_class`

**Tier-3 (hint only, never gates verified alerts):**

- `actor.first_seen` for this exe
- `actor.first_seen_for_target` (this exe touching this target)
- `actor.seen_count_30d`
- `network.first_seen_destination`

Tier-3 fields are shown to operators for context but the rule grammar
prohibits using them as match predicates.

### 5.5 Lineage IDs

Every event carries `lineage_ids: []uint64` ordered outermost to
innermost. Lineage roots that mint a new ID:

- SSH session accepted (`sshd: user@pts/N` fork)
- PAM `pam_open_session`
- Cron firing a job (cron daemon → child)
- systemd activating a unit
- Container task creation (containerd-shim → workload init)
- sudo / pkexec / su succeeding (preserves outer + adds inner)
- Web request candidate (accepted connection on a worker, heuristic)

Queries match at any level:
- "Everything from SSH session 8821" → match outermost
- "Everything after the sudo at 14:25" → match innermost

### 5.6 Hot causal graph

In-memory directed-acyclic-graph (with cycle protection on at most
2-edge anomalies). Nodes:

- Process (`pid_start_key`)
- File (inode + mount)
- Socket (inode + tuple)
- Identity (login session)
- Cgroup
- Namespace
- Container
- Package
- Kernel object (module, BPF program)

Edges:

- fork, exec
- read, write, mmap-exec
- connect, accept, send, recv
- auth, escalate (sudo, setuid, capset)
- inject (ptrace, process_vm_writev, /proc/PID/mem)
- persist (write to persistence-path watchlist)
- module_load

Retention:

- Live processes: in graph until exit + 5 min warm window
- Dead processes: 30 min warm, then minimal forensic stub
- Verified-alert chains: pinned (excluded from eviction) for 24 h
- Evidence buckets: compacted (count + sample event ids) per 1-minute window

Indexes (in-memory maps under sharded RWMutex):

- `nodes[ProcKey]` — primary
- `byPID[uint32]` — current live process for a pid
- `byCgroup[string][]ProcKey`
- `byOriginIP[netip.Addr][]ProcKey`
- `byLineageID[uint64][]EventRef`
- `byTTY[uint32]ProcKey`
- `children[ProcKey][]ProcKey`

### 5.7 Closed predicate grammar (initial set)

Exactly these 18 predicates. New predicates require code review.

| Predicate                                            | Returns | Data source                |
| ---------------------------------------------------- | ------- | -------------------------- |
| `actor.exe in <list>`                                | bool    | static config              |
| `actor.exe_sha in <list>`                            | bool    | enrichment                 |
| `actor.uid in <list>`                                | bool    | enrichment                 |
| `actor.cgroup matches <glob>`                        | bool    | enrichment                 |
| `actor.has_recent_event(kind, window)`               | bool    | per-actor event ring       |
| `target.path matches <glob>`                         | bool    | enrichment                 |
| `target.inode in known_set(class)`                   | bool    | sensitive-asset catalog    |
| `network.remote.ip in <cidr_list>`                   | bool    | static config + corpus     |
| `network.remote.sni matches <glob>`                  | bool    | DPI enrichment             |
| `network.dns.resolved_by_same_actor_within(window)`  | bool    | per-actor DNS ring         |
| `chain.contains_exe(<exe>)`                          | bool    | graph walk, depth ≤ 16     |
| `chain.rooted_in_origin(<type>)`                     | bool    | origin attribution         |
| `origin.user in <list>`                              | bool    | identity enrichment        |
| `origin.ssh_key_hash in <list>`                      | bool    | identity enrichment        |
| `integrity.binary_signed`                            | bool    | IMA / dpkg / rpm           |
| `integrity.package_owner_matches(<glob>)`            | bool    | dpkg / rpm query           |
| `time.within_maintenance_window`                     | bool    | operator-set state         |
| `actor.has_active_ack(<rule_id>)`                    | bool    | ack ledger                 |

### 5.8 Rule schema

```yaml
id: sensitive_read_then_novel_egress
type: composite
window: 60s
enforcement: async        # sync | async | evidence_only | operator_confirmed

events:
  - tag: read
    kind: file_open
    target.class: sensitive_secret

  - tag: egress
    kind: tcp_connect
    actor: same_as:read

match:
  all_of: [read, egress]

require_context:
  - read.actor.pid_start
  - read.actor.exe
  - read.target.inode
  - read.chain.rooted
  - egress.network.remote_ip

allow:
  - read.actor.exe in policy.secret_readers
  - egress.network.remote.ip in policy.allowed_destinations

unless:
  - egress.network.dns.resolved_by_same_actor_within: 30s
  - time.within_maintenance_window
  - actor.has_active_ack: sensitive_read_then_novel_egress

deny:
  - anything_else
```

`enforcement_class` constraints:

- `sync` rules may use only predicates marked `pre_admission_safe`
  (config-only, no graph walk, no history ring)
- `async` rules may use the full predicate set
- `evidence_only` rules never fire alerts, only record
- `operator_confirmed` rules block awaiting human action

### 5.9 Verified / Candidate / Evidence

Every rule match produces one output class:

| Class               | Condition                                              | Operator UX     |
| ------------------- | ------------------------------------------------------ | --------------- |
| **Verified alert**  | All Tier-1 required context present, rule fully matched | Surfaced loudly |
| **Candidate**       | Tier-1 context partial, or rule matched with `lossy_source` | Triage tab      |
| **Evidence**        | Rule matched but classification rule was `evidence_only` | Searchable log  |

No event becomes a verified alert unless `require_context` is fully
satisfied and no `allow` or `unless` branch matched.

### 5.10 Synchronous vs asynchronous enforcement

| Class                  | Path                                              | Latency budget |
| ---------------------- | ------------------------------------------------- | -------------- |
| Sync deny              | cgroup_sock_addr in kernel → EPERM at connect()    | < 50 µs        |
| Sync deny (alt)        | nft drop rule keyed by source IP                  | < 1 ms         |
| Async contain          | SIGSTOP the subtree, nft drop destination          | 200 ms-2 s     |
| Evidence-only          | Record only, no signal to attacker                 | n/a            |
| Operator-confirmed     | Hold pending UI decision                           | until ack      |

Sync rules never depend on composite or history predicates.

### 5.11 Kernel-context event class

Separate rule type for events with no actor chain:

```yaml
id: unsigned_kernel_module_load
type: kernel_context_rule
require_context:
  - kernel.lockdown_state
  - module.path
  - module.signature_state
deny:
  - module.signature_state != valid_signed
```

Used for: module loads, lockdown transitions, kexec, /dev/mem access,
IMA appraisal failures, unexpected BPF program loads.

### 5.12 Ack ledger

Every operator suppression creates a ledger entry:

```yaml
ack_id: 421
rule: sensitive_file_read
actor.exe_sha: <sha256>
actor.uid: 0
actor.loginuid: 1000
origin.type: ssh
origin.ip: <ip>
target.inode: <inode>
ttl: 24h
reason: "operator inspected key manually"
created_by_uid: 1000
created_via: local_api_so_peercred
signed_at_chain_seq: <n>
```

Ledger entries are first-class records in the signed audit chain.

Each entry tracks:

- `matched_count` — increments every time the ack suppresses an alert
- `last_matched_at` — most recent suppression
- `context_shift_detected` — set true if a matching event has a
  Tier-2 field that differs from the original (e.g., new exe_sha
  because vim updated)

When `context_shift_detected`, the event surfaces as evidence with
tag `"matched by ack but context shifted"` so attackers can't
quietly use a similar pattern under cover of an old ack.

### 5.13 Maintenance window

```yaml
maintenance_window:
  id: 4421
  scope:
    user: <username>
    cgroup: <cgroup_path>      # optional
  duration: 15m                # max 15 minutes; never extends silently
  reason: "manual server inspection"
  created_by_uid: 1000
  created_via: local_api_so_peercred
```

Constraints:

- Max duration 15 minutes
- Reason text required
- Visible in UI banner while active
- Counted in alert metadata for events suppressed during the window
- Auto-expiry; no extension without a new explicit action
- Creation is itself a high-severity audit entry

### 5.14 Cold tier

Storage shape: append-only, daily-partitioned SQLite tables.

Tables:

- `events` — full enriched events, one row each, indexed by
  `(lineage_id, timestamp)`, `(actor_exe_sha, timestamp)`, `(target_inode, timestamp)`
- `evidence_buckets` — aggregated buckets keyed by
  `(rule_id, kind, actor_exe_sha, target_class, cgroup, origin_type, 1-min window)`
  with `first_seen`, `last_seen`, `count`, `sample_event_ids`
- `verified_alerts` — verified-alert metadata + foreign keys to chain events
- `acks` — ack ledger with match counters
- `lineage_index` — `(lineage_id, root_type, root_value)` for fast traversal

Write path:

- Bounded write-behind queue, default 256k events
- On overflow: drop oldest, increment `cold_write_drops` metric,
  emit a `health.cold_overflow` event
- Periodic checkpoint every 30 seconds; WAL mode; `synchronous=NORMAL`
- Daily rotation via partition table swap at 00:00 UTC

Scale ceiling: ~30k events/second sustained on commodity SSD.
Beyond that, the operator runs an optional ClickHouse sidecar
(not built-in; out-of-process; documented integration).

## 6. Data model

### 6.1 Process key

```go
type ProcKey struct {
    PID     uint32
    StartNS uint64   // /proc/PID/stat field 22
}
```

The only PID-reuse-safe actor identifier.

### 6.2 Enriched event

```go
type EnrichedEvent struct {
    EventID    uint64
    LineageIDs []uint64       // outermost to innermost
    TimeNS     uint64          // bpf_ktime_get_ns at capture
    Kind       EventKind

    Source     SourceMeta      // grade, lossy, partial
    Actor      ActorContext    // pid_start, exe, uid, cgroup, ns, ...
    Chain      []ActorRef      // full ancestry to root
    Target     TargetContext   // canonical path / inode / socket
    Origin     OriginContext   // ssh / web / cron / systemd / container / local
    Identity   IdentityContext // loginuid, pam_session, ssh_key_hash
    Integrity  IntegrityContext // exe_sha, ima_hash, package, signed
    Network    NetworkContext  // remote ip/port, sni, ja3
    Container  ContainerContext // container_id, pidns, mntns, netns
    Peers      []EventRef       // adjacent events ±60s by same actor

    Completeness CompletenessReport
    EvidenceClass EvidenceClass  // verified | candidate | evidence
}

type CompletenessReport struct {
    Tier1Complete bool
    MissingTier1  []string
    Tier2Present  []string
    RaceSuspected bool
    LossObserved  bool
    SourceGrade   string         // "A+", "A", "B", "C"
}
```

### 6.3 Verified alert

```go
type VerifiedAlert struct {
    AlertID     uint64
    RuleID      string
    FiredAt     time.Time
    LineageIDs  []uint64
    ChainEvents []uint64   // foreign keys into events
    Reasons     []Reason   // per-predicate match trace
    AckMatched  *uint64    // ack_id if suppressed
    Enforcement struct {
        Class    string    // sync | async | evidence | operator
        Action   string    // sigstop | nft_drop | none | pending
        AppliedAt time.Time
        Result   string    // applied | failed | not_armed
    }
}
```

## 7. Performance budget (committed targets)

| Metric                                | Target                          |
| ------------------------------------- | ------------------------------- |
| BPF program runtime per event         | < 1 µs                          |
| Ringbuf consumer wakeup latency       | < 1 ms                          |
| Reorder window                        | 50-200 ms (configurable)        |
| Tier-1 enrichment p99                 | < 500 µs                        |
| Tier-1 enrichment p99.9               | < 5 ms                          |
| Rule evaluation per event             | < 100 µs                        |
| Graph insert                          | < 10 µs                         |
| Lineage lookup                        | < 1 µs                          |
| Memory per live process               | < 4 KB                          |
| Memory for 50k live processes         | < 200 MB                        |
| Hot graph 30-min retention            | < 256 MB                        |
| Cold write sustained throughput       | 50k events/sec target           |
| Cold write SQLite practical ceiling   | ~30k events/sec                 |
| Daemon steady-state CPU               | < 5% of one core                |
| Daemon burst (10 s sustained)         | < 25% of one core               |
| Hard degrade trigger (ringbuf full)   | > 75% sustained 1 s             |

Workload-class expectations:

| Workload class                 | CPU       | Memory    | Disk/day    |
| ------------------------------ | --------- | --------- | ----------- |
| Personal / dev box             | 1-3%      | 100-200 MB | 100-500 MB  |
| Typical web/app server         | 3-7%      | 150-300 MB | 500 MB-2 GB |
| Busy DB / build farm / k8s node | 8-15%    | 300-600 MB | 2-5 GB      |
| Line-rate network appliance    | not target | not target | not target  |

Implementation strategies for meeting these targets are specified
in [ROADMAP.md](ROADMAP.md) under "Performance Implementation Spec."

## 8. Threat model

### 8.1 Trust assumptions

- The Linux kernel is trusted up to its CVE surface
- xhelix binary integrity is trusted (signed; optionally IMA-appraised)
- The audit chain Ed25519 key is protected (file mode, optionally TPM-sealed)
- The operator's identity is verified by OS authentication

### 8.2 Attackers in scope

- Unprivileged remote attacker exploiting an application bug
- Privileged remote attacker post-credential-theft (with operator's keys)
- Local malware running as user
- Local malware escalated to root (subject to lockdown limits, see 8.4)
- Compromised supply-chain package (npm, pip, apt postinstall)
- Insider abuse by legitimate operator

### 8.3 Detection guarantees

- Every event with Tier-1 complete is recorded in the signed chain
- Every verified alert is reproducible from its evidence
- The audit chain is append-only and tamper-evident (offline verifiable)
- Maintenance windows are explicit signed audit entries

### 8.4 Attackers not in scope

- Root-with-kernel-exploit who unloads xhelix BPF programs and rewrites
  the audit chain (requires hardened mode: `lockdown=integrity`,
  `module.sig_enforce=1`, IMA-appraise, Secure Boot, TPM-sealed key)
- Firmware / SMM / hypervisor-level attackers (require measured boot
  + remote attestation, outside xhelix scope)
- Physical access (disk extraction)
- Side-channel attacks (Spectre/Meltdown class)

### 8.5 Detection limits

- Patient attackers who break activity into chunks below correlation
  windows can defeat composite rules. Mitigation: deterministic
  allow-lists for sensitive readers; operator review of evidence stream.
- In-memory-only attacks (mining, in-memory data harvesting) that
  touch no file and make no novel network connection are visible
  only as resource anomalies, which xhelix does not gate alerts on.
- Operator-pattern attacks (legitimate-looking activity from stolen
  operator credentials) cannot be distinguished without second-factor
  authentication; xhelix records the chain, does not block it.

## 9. Competitive positioning (honest)

| Capability                                                  | xhelix | Tetragon | Falco | auditd | osquery | CamFlow | Portmaster | EDRs        |
| ----------------------------------------------------------- | :----: | :------: | :---: | :----: | :-----: | :-----: | :--------: | :---------: |
| Per-process egress firewall with verdict reasons            |   ✓    |    -     |   -   |   -    |    -    |    -    |     ✓      |     ~       |
| Chain-attributed verdicts (network origin → file → egress)  |   ✓    |    ~     |   -   |   -    |    -    |    ✓    |     -      |     ~       |
| Whole-system provenance graph                               |   ✓    |    -     |   -   |   -    |    -    |    ✓    |     -      |     -       |
| eBPF runtime detection                                      |   ✓    |    ✓     |   ✓   |   -    |    ✓    |    ~    |     -      |     ~       |
| Per-process policy editable in UI                           |   ✓    |    -     |   -   |   -    |    -    |    -    |     ✓      |     -       |
| Signed append-only audit chain                              |   ✓    |    -     |   -   |   ~    |    -    |    -    |     -      |     ~       |
| Operator-curated allow-lists for sensitive readers          |   ✓    |    -     |   ~   |   -    |    -    |    -    |     -      |     -       |
| TLS SNI extraction for app identity                         |   ✓    |    ✓     |   -   |   -    |    -    |    -    |     -      |     ~       |
| Single static binary, free, host-focused                    |   ✓    |    -     |   ~   |   ~    |    ~    |    -    |     ✓      |     -       |

The xhelix unique angle is the integration: per-process egress +
sensitive-file gating + auth-context lineage + signed audit chain
+ observability-grade evidence store, in one binary, free, with
deterministic rules.

## 10. References

Public standards and prior art referenced in this design:

- Linux Security Modules (LSM): `Documentation/security/lsm.rst`
- BPF LSM: `Documentation/bpf/prog_lsm.rst`
- IMA: `Documentation/ABI/testing/ima_policy`, `security/integrity/ima/`
- Kernel lockdown: `Documentation/admin-guide/lockdown.rst`
- Kernel module signing: `Documentation/admin-guide/module-signing.rst`
- fanotify: `man 7 fanotify`
- BPF cgroup_sock_addr: kernel selftests under `tools/testing/selftests/bpf/`
- TCP/IP RFC 793, TLS RFC 8446, SNI RFC 6066
- CamFlow whole-system provenance (academic prior art)
- MITRE ATT&CK for Linux (technique classification reference)
