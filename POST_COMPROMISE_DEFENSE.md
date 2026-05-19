# xhelix — Post-Compromise Defense Playbook

> Comprehensive defensive plan for the moment after an attacker is on
> the box. Documents the 40 most damaging post-compromise actions,
> ranked by realistic frequency, then specifies the hardening
> strategy, detection plan, and containment design for each phase.
>
> Design law: **assume the attacker is already inside.** Every
> control here is engineered to slow, isolate, and contain after a
> breach — not just to prevent one.
>
> Companions: [ARCHITECTURE.md](ARCHITECTURE.md),
> [DEFENSE_PRIORITIES.md](DEFENSE_PRIORITIES.md),
> [ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md),
> [ZERO_DAY_GUARDIAN.md](ZERO_DAY_GUARDIAN.md),
> [SUPPLY_CHAIN_DEFENSE.md](SUPPLY_CHAIN_DEFENSE.md),
> [CI_CD_GUARD.md](CI_CD_GUARD.md), [AUTO_ADVISOR.md](AUTO_ADVISOR.md).

---

## Contents

1. The fortress mindset
2. The 40-action attack playbook (the reality)
3. Six phases × layered hardening
   - Phase 1 — Reconnaissance
   - Phase 2 — Credential theft
   - Phase 3 — Privilege escalation
   - Phase 4 — Persistence
   - Phase 5 — Lateral movement
   - Phase 6 — Data exfiltration
4. Cross-cutting hardening primitives
5. The "you have been breached" containment playbook
6. Time-buying tactics — how to slow the attacker
7. Damage minimisation when prevention fails
8. Implementation plan inside xhelix
9. Honest scoring — attacker time-to-success at each hardening tier
10. Final positioning

---

## 1. The fortress mindset

Three operating principles drive this playbook:

1. **Assume breach.** Every defense is designed to function with the
   attacker already inside. Preventing initial access is a separate
   layer, mostly outside xhelix's scope.
2. **Make every step expensive.** Detection alone is not enough.
   Each attacker action should cost time, generate noise, hit a
   wall, or trigger forensic capture.
3. **Buy time, not just block.** Many real defenses are not "stop
   forever" — they are "delay by 30 seconds so the operator can
   respond." That's enough.

The single sentence:

> **xhelix turns every action an attacker would take after landing
> into either a wall, a noisy alert, or a deception that wastes their
> time.**

---

## 2. The 40-action attack playbook

Ordered by realistic frequency in incident reports, grouped by phase.
Damage and severity are calibrated against single-host server / dev
machine compromise. Containment shows what xhelix (full P1–P6 +
Auto Advisor) achieves.

### Phase 1 — Reconnaissance (first 5 minutes inside)

| # | Action | Intent | Damage | Severity | Containment |
|---:|---|---|---|---|---|
| 1 | `whoami`, `id`, `uname -a`, `hostname` | Identify the host | Minor | Low | Detect (evidence) |
| 2 | `ps auxf`, `ss -tlnp`, `netstat -tlnp` | Map services + open ports | Minor | Low | Detect (evidence) |
| 3 | Read `/etc/passwd`, `/etc/group`, `/etc/shadow` | Enumerate users | Moderate | Medium | ~95% block |
| 4 | Read `/etc/os-release`, kernel version | Pick exploit per platform | Minor | Low | Detect |
| 5 | `find / -perm -4000` (SUID hunt) | Find local privesc binaries | Moderate | Medium | ~70% detect via burst |
| 6 | Scan `~/.bash_history`, `~/.zsh_history` | Replay operator commands | Major | High | ~95% block |
| 7 | List kernel modules, capabilities | Find kernel exploit surface | Minor | Low | Detect |

### Phase 2 — Credential theft (next 10 minutes)

| # | Action | Intent | Damage | Severity | Containment |
|---:|---|---|---|---|---|
| 8 | Read `~/.ssh/id_*` (SSH keys) | Lateral movement | **Severe** | **Critical** | **~95% block** |
| 9 | Read `~/.aws/credentials`, `~/.aws/config` | Pivot to cloud | **Catastrophic** | **Critical** | **~95% block** |
| 10 | Read `.env`, `.envrc`, app configs | DB / API / JWT secrets | **Severe** | **Critical** | **~92% block** |
| 11 | Read `/etc/shadow`, `/etc/sudoers` | Offline crack + sudo path | Major | High | ~95% block |
| 12 | Read `~/.kube/config` | Pivot to k8s | **Severe** | **Critical** | ~92% block |
| 13 | Read `~/.docker/config.json` | Registry tokens | Major | High | ~90% block |
| 14 | Read `~/.gnupg/` | Sign artifacts, decrypt data | Major | High | ~92% block |
| 15 | Read browser profile dirs | Hijack live sessions | **Severe** | **Critical** | ~85% block |
| 16 | Dump `/proc/self/environ` and child env | Steal injected secrets (CI) | **Severe** | **Critical** | Cannot block read; **~90% block exfil** |
| 17 | Read CI runner workspace for tokens | NPM_TOKEN, GITHUB_TOKEN | **Catastrophic** | **Critical** | **~88% block** with CI-guard mode |

### Phase 3 — Privilege escalation

| # | Action | Intent | Damage | Severity | Containment |
|---:|---|---|---|---|---|
| 18 | Exploit local kernel CVE | uid > 0 → root | **Catastrophic** | **Critical** | ~5% normal; ~70% hardened mode |
| 19 | Abuse SUID binary | Escalate via misconfig | **Severe** | **Critical** | ~60% detect; cannot block kernel-side privesc |
| 20 | Container escape via runtime | Container → host root | **Catastrophic** | **Critical** | ~65% detect via setns/unshare/pivot_root |
| 21 | Add user to `wheel`/`sudo`, modify `/etc/sudoers.d/*` | Persistent privilege | Major | High | ~95% block |

### Phase 4 — Persistence

| # | Action | Intent | Damage | Severity | Containment |
|---:|---|---|---|---|---|
| 22 | Add entry to `~/.ssh/authorized_keys` | Backdoor SSH access | **Severe** | **Critical** | **~95% block** |
| 23 | Add cron entry | Scheduled re-execution | Major | High | **~95% block** |
| 24 | Install systemd unit | Survive reboot | Major | High | **~95% block** |
| 25 | Modify `~/.bashrc`, `/etc/profile.d/*` | Re-exec on next shell | Major | High | ~95% block |
| 26 | Write to `/etc/ld.so.preload` | Hook every dynamic exec | **Severe** | **Critical** | **~95% block** |
| 27 | Trojan a core binary (`ls`, `sshd`, `bash`) | Permanent backdoor | **Catastrophic** | **Critical** | ~90% detect; IMA-appraise blocks |
| 28 | Install rootkit kernel module | Hide processes / files | **Catastrophic** | **Critical** | ~5% normal; **~95% block** with module signing |
| 29 | Webshell in web root | HTTP-controlled backdoor | **Severe** | **Critical** | **~97% block** |
| 30 | Malicious systemd timer / anacron | Hidden scheduled exec | Major | High | ~95% block |

### Phase 5 — Lateral movement

| # | Action | Intent | Damage | Severity | Containment |
|---:|---|---|---|---|---|
| 31 | SSH to other hosts with stolen keys | Spread across infra | **Catastrophic** | **Critical** | ~90% block via egress + depends on host B's xhelix coverage |
| 32 | Scan internal network | Map adjacent services | Major | High | ~95% block + burst detector |
| 33 | Connect to cloud metadata service | Steal instance role | **Catastrophic** | **Critical** | **~98% block** |
| 34 | Abuse internal RPC (Redis, Memcached, ES) | Read internal data | **Severe** | **Critical** | ~85% block via per-cgroup egress |
| 35 | Move via shared NFS / SMB | Plant payload in adjacent FS | Major | High | ~80% block |

### Phase 6 — Data exfiltration

| # | Action | Intent | Damage | Severity | Containment |
|---:|---|---|---|---|---|
| 36 | Dump database (`mysqldump`, `pg_dump`, S3 export) | Steal user data, PII | **Catastrophic** | **Critical** | ~80% block via DB row-volume + egress |
| 37 | tar + curl upload to attacker domain | Bulk exfil | **Severe** | **Critical** | **~95% block** |
| 38 | DNS tunneling | Exfil through DNS | Major | High | ~70% detect via DGA + entropy |
| 39 | Slow-drip via legitimate channels (Slack, GitHub API, Telegram) | Hide in allowed traffic | Major | High | ~40% detect |
| 40 | Steganographic publish to package registry | Wormable + bypass egress | **Severe** | **Critical** | ~30% normal; **~90% block** with publish-mode separation |

---

## 3. Six phases × layered hardening

For each phase: what attackers do, the *current* xhelix coverage, and
the additional hardening that makes the phase materially harder.

### Phase 1 — Reconnaissance

Attackers want **information** above all else. Information about
users, services, kernel, network, ownership, history. Denying
information costs almost nothing operationally.

**Strict guardrails to add**:

1. **`/proc` masking via `hidepid=2`** in `/etc/fstab` — users see
   only their own processes. Kills `ps auxf` enumeration for
   unprivileged attackers.
2. **`/etc/passwd` minimal exposure** — most modern Linux systems
   leak service accounts here. Move service accounts to LDAP /
   sssd or use a chrooted view.
3. **Shell history disabled or sealed** for service accounts —
   `HISTFILE=/dev/null` in service-user profile.
4. **`/etc/os-release` rewrite to lie** — provide a misleading kernel
   / distro version. Exploit-picker tooling assumes the wrong target,
   tries the wrong payload, generates noise.
5. **Strip reconnaissance binaries** — minimal distros omit `find`,
   `nmap`, `dig`, `wget`, `curl`, `nc`, `python`, `perl`. Attacker
   has to drop their own, which is itself a `file_open` event xhelix
   catches.
6. **Read-only `/usr` and `/bin`** — even if the attacker drops a
   binary, they have to drop it in `/tmp` (where xhelix marks
   exec-from-`/tmp` as high-severity).
7. **Deception users / processes** — synthetic users with names like
   `admin`, `root2`, `oracle` that don't exist; logging any attempt
   to access them is high-confidence attacker activity.

**Detection layered on top**:

- Burst detection: 20+ `/proc` reads in 30 seconds from a non-root
  process → alert.
- Tool-drop detection: writing an ELF or script to `/tmp/`, `/dev/shm/`,
  `/var/tmp/` by a non-package-manager actor → alert.
- Shell-history read by a non-owner UID → alert.
- Decoy-account access → instant high-confidence alert.

**Containment when reconnaissance is detected**:

- SIGSTOP the offending process tree (reversible)
- Snapshot `/proc/<pid>/` state (open FDs, maps, environ, cmdline)
- Notify operator with full chain
- Disable interactive shells in the cgroup for 60 seconds (rate-limit
  re-exec attempts)

### Phase 2 — Credential theft

This is where attackers monetise. The credential is the prize.

**Strict guardrails to add**:

1. **Passphrase every SSH key**. xhelix can detect unencrypted keys
   via header inspection; Auto Advisor can recommend `ssh-keygen -p`.
2. **Hardware tokens for all human SSH access** (YubiKey, Nitrokey).
   Private key never leaves the device; reading the on-disk file
   yields nothing.
3. **No long-lived cloud credentials on disk**. AWS SSO + role
   assumption, GCP workload identity, OIDC tokens from CI. The static
   `~/.aws/credentials` file shouldn't exist in 2026.
4. **TPM-bound secrets**. `systemd-creds` + `clevis` + TPM sealing
   for application secrets. Reading the file yields ciphertext only
   decryptable on the same machine in the same boot state.
5. **In-process secret rotation**. Long-running app processes should
   fetch secrets at startup, scrub them from environment immediately
   after, and rotate every N minutes. Dumping `/proc/PID/environ` at
   minute 5 yields nothing useful.
6. **Browser profiles in a dedicated container or VM**. Even on dev
   workstations, browser cookies are crown-jewel session tokens; a
   compromised dev shell shouldn't see them.
7. **Locked-down `.env` policy** — refuse to start any service whose
   working dir contains a tracked-in-git `.env` file.

**Detection layered on top**:

- Every read of a sensitive-catalog path by a non-allow-listed actor
  is a verified alert (already designed in main xhelix).
- Cluster detection: same process reads 3+ sensitive paths within 60
  seconds → confidence boost to critical.
- Cross-reference: process that read `~/.aws/credentials` then made
  any outbound connect in the next 60s → composite critical alert.

**Containment when credential theft is detected**:

- SIGSTOP the offending process tree
- nft drop rule for any destination the process attempted to reach
- Optionally rotate the credentials that were touched (with operator
  confirmation) before unfreezing
- Forensic flight-recorder flush of the previous 120 seconds

### Phase 3 — Privilege escalation

This is where the attacker becomes "us." Hardest phase to fully
prevent if the kernel itself is exploited.

**Strict guardrails to add**:

1. **Hardened mode boot params** (per `ENTERPRISE_ARCHITECTURE.md`):
   - `lockdown=integrity`
   - `module.sig_enforce=1`
   - `ima_policy=appraise_tcb ima_appraise=enforce`
   - `mitigations=auto`
2. **No SUID binaries except the canonical short list**. Run `find /
   -perm -4000` and justify every remaining entry. Many can be replaced
   with `sudo` rules or capabilities.
3. **Capability-bounding everywhere**. Services should run with the
   minimum capability set; no service should keep `CAP_SYS_ADMIN`
   "just in case."
4. **`no_new_privs` for every service** via systemd `NoNewPrivileges=
   true`. Prevents SUID re-execution mid-chain.
5. **seccomp filter per service** allowing only the syscalls actually
   needed. Even a successful kernel exploit fails if the syscall is
   filtered.
6. **Secure Boot + signed kernel + signed initrd**. Closes the kexec
   bypass path.
7. **AppArmor / SELinux profile** on every internet-facing service.
   Defeats most local-privesc primitives once the attacker is inside
   the service.
8. **TPM-bound disk encryption with PCR sealing**. Tampering the
   boot chain renders the disk unreadable on next boot.

**Detection layered on top**:

- `setuid` / `setgid` / `capset` events by non-init processes are
  high-severity.
- `setns` / `unshare` / `pivot_root` by non-container-runtime
  processes are critical (container escape signature).
- `bpf()` syscall by non-xhelix actor → critical (instrumentation
  tampering).
- Module load events outside `apt`/`dnf` flow → critical.

**Containment when privesc is detected**:

- SIGSTOP the actor and *all* its children
- Refuse new exec from the actor's cgroup
- Page the operator immediately (this is a critical event)
- If the actor has already escalated to root: snapshot full process
  state before killing, because forensics here matters more than
  uptime

### Phase 4 — Persistence

This is what makes a 5-minute breach into a 6-month problem.
Persistence-write paths are a finite, well-known set.

**Strict guardrails to add**:

1. **Read-only root filesystem**. Mount `/` as `ro`; explicit tmpfs
   for known-writable areas. Attacker can't write `/etc/cron.d/*`
   if `/etc` is read-only.
2. **Immutable systemd unit files** via `chattr +i /etc/systemd/system/*`.
   Even root can't modify without `chattr -i` first, which itself is
   a watchable event.
3. **Explicit allowlist of writable paths** per service cgroup via
   `ReadWritePaths=` in systemd. Service can write `/var/lib/myapp/`
   and nothing else.
4. **Sensitive-write deny** for the full persistence-catalog at BPF
   LSM level — covers ~30 paths including ssh keys, cron, systemd,
   ld.so.preload, profile.d, bashrc, sudoers, passwd, shadow, web
   docroots.
5. **`/tmp` and `/dev/shm` as `noexec` mounts**. Attacker drops a
   binary; kernel refuses to exec it from there.
6. **Web-root no-exec policy**. Web server's writable dirs (`uploads/`)
   mounted `noexec`. Webshells dropped there cannot execute.
7. **Immutable bash / sh / system binaries** via IMA-appraise. Any
   Trojan replacement fails to exec.
8. **Append-only journald** — attacker can't simply delete log
   evidence.

**Detection layered on top**:

- Every write to the persistence-catalog by non-allow-listed actor is
  a verified alert.
- Burst detection: 3+ persistence writes in 60 seconds → critical
  (indicates active intrusion campaign).
- File-integrity monitoring for critical binaries on a 5-minute
  interval; any hash drift outside `apt`/`dnf` flow is a critical
  alert.

**Containment when persistence write is detected**:

- Block the write at LSM level (synchronous deny)
- SIGSTOP the actor
- Roll back the persistence file from the last signed snapshot
- Alert with full chain showing exactly what was attempted

### Phase 5 — Lateral movement

The attacker now wants out — to other hosts, the cloud, the rest of
the network.

**Strict guardrails to add**:

1. **Default-deny outbound** at the cgroup level. Every service has
   an explicit allow-list of destinations.
2. **No DNS resolver inside untrusted cgroups**. Web worker resolves
   only the destinations in its allow-list; everything else returns
   NXDOMAIN.
3. **No `nmap`, no `dig`, no `nc`** in the production image. Attacker
   drops their own → triggers tool-drop detection (Phase 1 #5).
4. **WireGuard / Tailscale for admin access**, never SSH on the
   public internet. Lateral SSH from a compromised box has nowhere
   public to go.
5. **Cloud metadata service explicitly denied** at network namespace
   level. `169.254.169.254` simply unreachable from non-system
   cgroups.
6. **No RFC1918 outbound** from web / app cgroups unless explicitly
   allow-listed (kills lateral move to internal Redis / ES / Mongo).
7. **Per-route external-API contracts** — the route that can talk to
   the payment API cannot talk to anything else.
8. **Egress at the host firewall + the cgroup level + the application
   level**. Three layers; attacker must defeat all three.

**Detection layered on top**:

- Connect to non-allow-listed destination → block + alert.
- DNS query for high-entropy name → DGA detector → alert (already in
  xhelix).
- Burst of connect attempts to many destinations → port-scan signature
  → alert.
- Connect to metadata service → critical alert + immediate egress
  block.

**Containment when lateral attempt detected**:

- nft drop rule on the destination IP immediately
- SIGSTOP the actor
- If the attempt was to a known-bad pattern (metadata, RFC1918 from
  web cgroup, etc.): elevate to critical, page operator
- Maintain the block until operator review

### Phase 6 — Data exfiltration

The final stage. Data leaves the box.

**Strict guardrails to add**:

1. **Per-cgroup egress allowlist** (already covered in Phase 5).
2. **Byte-rate limits per destination per cgroup**. Even allowed
   destinations have caps. Slack webhook upload of 10 GB in 10
   minutes is suspicious whether or not Slack is allow-listed.
3. **DB row-volume contracts**. Routes that legitimately return 1–10
   rows have a hard cap; a `SELECT * FROM users` returning 50k rows
   is blocked at the DB proxy.
4. **Response-size contracts** for HTTP responses. Login routes
   return < 4 KB. A login route suddenly returning 10 MB is blocked.
5. **DNS rate limiting and entropy gating** in the cgroup's DNS
   resolver. DNS tunneling becomes infeasible.
6. **Encrypted-at-rest for high-value data** with keys held outside
   the application process (TPM-bound). Even if exfiltrated, the
   bytes are ciphertext.
7. **Data classification labels** on sensitive datasets, enforced at
   the storage layer. Exfiltrated bytes carry their classification
   (via watermarking when feasible) so detection downstream remains
   possible.

**Detection layered on top**:

- Outbound byte rate exceeding cgroup contract → alert.
- DB query returning row count beyond contract → alert + block.
- Composite detection: sensitive-file read + outbound within 60s →
  critical (already designed in main xhelix).
- Repeated short connections to many destinations (slow-drip pattern)
  → alert.

**Containment when exfiltration detected**:

- Immediate nft drop on destination IP
- SIGSTOP all processes in the offending cgroup
- Optionally take a snapshot of bytes already transmitted (forensic
  reconstruction)
- Page operator; this is a verified data-loss event

---

## 4. Cross-cutting hardening primitives

These apply across all six phases.

### 4.1 Time-bound everything

- Every credential expires (max TTL configurable, default short)
- Every elevated-mode entry expires (default 15 min)
- Every operator ack expires (default 24 h)
- Every WireGuard / VPN session expires (default 1 h)
- Even SSH sessions have idle-timeout (default 30 min)

### 4.2 Two-person rule for destructive actions

- Production deploy requires two operator signatures
- Operator ack for a critical-rule suppression requires second-operator
  review within 24 h
- Maintenance-mode entry for > 15 min requires second-operator approval

### 4.3 Universal flight recorder

- Every action by every actor in xhelix's scope generates an event
- The previous 120 seconds is always in a ring buffer per actor
- On any verified alert, the buffer flushes to the signed audit chain
- Provides post-mortem evidence even when prevention failed

### 4.4 Air-gapped backups

- Backups pulled by an off-server agent, never pushed from production
- Air-gap or write-once-read-many destination
- Encrypted with a key not present on the production host
- Restore drills monthly

### 4.5 Patch cadence

- Kernel patched within 48h of CVE disclosure
- Application stack within 7d
- Dependencies via lockfile-pinned + automated PR + xhelix advisor
  flag
- Operator alerted when kernel > 90 days unpatched

### 4.6 Privileged Access Workstation

- Admin tasks from a dedicated, hardened machine
- That machine doesn't browse the web, run dev tools, or accept email
- Compromise of dev laptop → no path to production

---

## 5. The "you have been breached" containment playbook

Step-by-step. Designed to execute in < 60 seconds from first detection.

### 5.1 Immediate (0–10 seconds)

1. **SIGSTOP the offending process tree** — reversible, preserves
   forensics
2. **nft drop rule for all destinations the actor reached or tried to
   reach** in the last 60 seconds
3. **Flush flight recorder to signed audit chain** — preserve the
   sequence of events
4. **Page operator** — desktop notification, push, SMS depending on
   configured channel
5. **Snapshot `/proc/<pid>/` for all stopped processes** — open FDs,
   maps, environ, cmdline

### 5.2 Within first minute

1. **Cgroup-level freeze** — no new processes can enter the affected
   cgroup (`cgroup.kill` style)
2. **Disable affected service's listening sockets** — drop new
   connections at the source
3. **Audit chain export** — signed copy to off-host storage in case
   the host is compromised further
4. **Begin credential rotation pipeline** — any credentials the actor
   touched are flagged for rotation

### 5.3 Within first 10 minutes

1. **Operator inspects flight recorder** — what was the chain?
2. **Operator decides**:
   - Resume process (false positive)
   - Kill process tree (containment confirmed)
   - Quarantine the entire host (isolate from network)
3. **Forensic image** — if host is quarantined, take a memory + disk
   snapshot for IR
4. **Cross-host alert** — notify any other xhelix instances in the
   fleet about the source IP / credentials involved

### 5.4 Within first hour

1. **Determine blast radius** — what else might be affected?
2. **Rotate every credential the actor could have touched**
3. **Verify backups** are clean and recent
4. **Update detection rules** if the attack used a novel pattern

### 5.5 Within first 24 hours

1. **Full incident report** — chain, timeline, IOCs, blast radius
2. **Root cause** — how did they get in?
3. **Remediation** — patch, harden, update contracts
4. **Tabletop the next variant** — what would have happened with a
   slight variation?

---

## 6. Time-buying tactics — slow the attacker

These are not "block forever." They are "slow them down enough for the
operator to respond."

### 6.1 Rate-limit per actor

- A process attempting 50 sensitive-file opens per second is throttled
  to 1 per second
- Attacker gets the data eventually, but in minutes instead of
  milliseconds — operator has time to respond

### 6.2 Tarpit responses

- Connections to ports that don't exist hold the TCP handshake for
  30 seconds before resetting (slows port scanners)
- DNS queries for non-existent names answered slowly

### 6.3 Decoy resources

- Honey-token files: `~/.aws/credentials_OLD` containing canary AWS
  keys. Any process reading this file is, by construction, malicious.
- Honey-services on internal ports — anything connecting is malicious.
- Honey-users in `/etc/passwd` (with `*` shadow entries) — any
  attempt to ssh as them is malicious.

### 6.4 False-positive bait

- Tempt the attacker with a fake credential or fake exfil destination
- When they take the bait, you have high-confidence attribution and
  evidence

### 6.5 Per-cgroup CPU throttling under suspicion

- Once xhelix classifies a process as "candidate-malicious," its
  cgroup gets `cpu.weight=1` (lowest priority)
- The attacker's process now runs at 1% of normal speed
- Operator has minutes to confirm and SIGSTOP

### 6.6 Gradual response, not all-at-once

- First suspicious event: log + flight recorder
- Second within 60s: rate-limit
- Third: SIGSTOP + alert
- Operator confirmation: kill + rotate

This avoids false-positive over-reaction while still being fast on
real attacks.

---

## 7. Damage minimisation when prevention fails

If the attacker succeeds at one stage, the next stage should still be
hard. Defence in depth in practice:

| Failed prevention | Next-layer mitigation |
|---|---|
| Initial RCE in PHP | Process-lineage contract: cannot spawn shell |
| Shell spawned anyway | Sensitive-file gate: cannot read keys |
| Keys read in-process (env vars) | Egress contract: cannot exfil |
| Exfil succeeds to allow-listed destination | Byte-rate cap: only first KB leaves |
| Persistence written | Read-only root: write fails or rolls back on reboot |
| Persistence somehow holds | IMA-appraise: Trojaned binary fails to exec |
| Lateral SSH succeeds | Target host has its own xhelix |
| Stolen long-lived token reused | OIDC-only deployment: token isn't valuable |
| Kernel exploit gives root | Module signing blocks rootkit load |
| Rootkit somehow loads | Audit chain remains signed off-host |
| Audit chain tampered | Backup ledger off-host caught the divergence |

Each layer assumes the one above failed. That's defence in depth.

---

## 8. Implementation plan inside xhelix

Mapping the above hardening to xhelix code work, in priority order.

| # | Hardening item | Existing xhelix component | New work |
|---:|---|---|---|
| 1 | Sensitive-file BPF LSM gate | P3.1 | Expand catalog to ~50 paths |
| 2 | Persistence-write watchlist | P3.2 | Expand to ~30 paths |
| 3 | Per-cgroup egress allowlist | P4.6 | Already in plan |
| 4 | Composite sensitive-read + egress | P4.3 | Already in plan |
| 5 | Process-lineage contract | P4 | Already in plan |
| 6 | Hardened-mode boot params | P6 | Document playbook |
| 7 | Read-only root + tmpfs templates | New | systemd profile generator |
| 8 | seccomp + AppArmor per service | New (Phase 5.5) | Policy generator |
| 9 | Rate-limit per actor | New | Add to enforcement engine |
| 10 | Tarpit responses | New | nft rule template |
| 11 | Honey-tokens + honey-users | New | Canary infrastructure |
| 12 | CPU throttling on suspicion | New | cgroup integration |
| 13 | Flight recorder universal | Enterprise rev §3 | Promote to top-level component |
| 14 | Air-gapped backup integration | New | Out-of-scope; document |
| 15 | Cross-host alert fan-out | New | Phase 8 (distributed) |
| 16 | Operator workflow for breach | New | Phase 5 UI work |
| 17 | Two-person rule for ack/maint | New | Phase 5 UI work |
| 18 | Forensic snapshot on alert | New | Add to enforcement engine |
| 19 | DB row-volume contracts | P8 (DB-L1/L2) | In plan |
| 20 | Response-size contracts | Enterprise rev §8 | In plan |

**New work specific to this playbook**: items 7, 8, 9, 10, 11, 12, 13,
14, 16, 17, 18. Estimated total: ~20 days of focused engineering on
top of P1–P6.

---

## 9. Honest scoring — attacker time-to-success at each tier

For a single-host server with a typical web application, attacker
time-to-meaningful-damage at each defence tier:

| Tier | Hardening level | Time-to-credentials | Time-to-persistence | Time-to-exfil |
|---|---|---|---|---|
| **T0** | Default Linux, no xhelix | < 1 min | < 5 min | < 10 min |
| **T1** | Default Linux + xhelix observe-mode | < 1 min (detected) | < 5 min (detected) | < 10 min (detected) |
| **T2** | xhelix enforce-mode (default contracts) | ~5–15 min (most blocked) | ~10–30 min (most blocked) | ~15–60 min (most blocked) |
| **T3** | xhelix enforce + WordPress fortress + curated plugin profiles | ~30 min – 2 h (depends on contract precision) | ~1–4 h | ~2–8 h |
| **T4** | T3 + read-only root + AppArmor + seccomp + no SUID | ~2–8 h | ~4–24 h (often impossible) | ~8–24 h |
| **T5** | T4 + hardened-mode boot + IMA-appraise + TPM-sealed | hours-to-days | days (kernel exploit required) | days (often impossible without 0-day) |

The interpretation: every tier multiplies attacker cost by 5–10x. T5
deployment puts you in the "nation-state targeted attack only"
category for most damage outcomes.

T1 is free (just install xhelix). T2 is a week of operator tuning.
T3 is a month of policy curation. T4 is a quarter of architecture
work. T5 is a year of full-stack hardening.

---

## 10. Final positioning

xhelix's value proposition for the post-compromise threat:

> **xhelix does not promise no breach. It promises that once the
> attacker is inside, every action they take is either blocked,
> contained, or so noisy that the operator has time to respond.
> Every credential is encrypted or short-lived; every persistence
> path is locked or watched; every exfil destination is allow-listed
> or rate-capped; every elevated mode is time-bound and audited;
> every alert carries the full causal chain.**

The result: a single-host that goes from "automated attacks succeed
in 5 minutes" to "targeted attacks need hours and leave a forensic
trail." For the threat model most operators actually face, that's
the difference between productive defence and theatre.

This playbook should be revisited quarterly as attacker techniques
evolve. The structure (six phases × layered hardening × cross-cutting
primitives × containment playbook) is stable; the specific items
within each section will change as MITRE ATT&CK for Linux updates and
real incident reports surface new patterns.
