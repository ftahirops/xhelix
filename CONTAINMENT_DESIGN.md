# Active Containment — the attacker's jail + deception cell

xhelix's design for *actively containing* an attacker once full
takeover is detected. Not just alerting — actually preventing further
damage while preserving evidence and not destroying the operator's
ability to investigate.

> Status: design locked. Implementation tracked in `ROADMAP.md` Phase
> P-FT (containment layers) and P-FT.11-.13 (deception + bastion).
> Companion doc: `FULL_TAKEOVER_DETECTION.md` (the detection scorer
> that triggers this).

---

## 0. The principle

```
Detect → Slow → Freeze → Jail → Deceive
```

Every layer is reversible. The operator holds the key.

Two things this design refuses to do:
- **Destroy evidence** (no SIGKILL until snapshot, no reboot)
- **Lock out the operator** (one designated path is always
  reachable for investigation and clear)

Two things it embraces:
- **Graduated escalation** (cheap defenses first, aggressive last)
- **Deception over destruction** (make the attacker waste time
  thinking their tools are broken)

---

## 1. The 5-layer cell

Layers engage progressively as the takeover score (per
`FULL_TAKEOVER_DETECTION.md §4.1`) rises:

```
Score ≥ 50   Layer 1            soft block (delay + refuse passports)
Score ≥ 75   Layers 1+2+3       SIGSTOP + network jail + FS jail
Score ≥ 90   Layers 1-4         + capability strip + cgroup move
Score = 100  Layers 1-5         + host-wide lockdown
+ identified attacker IP   Layer 6  + deception cell (tarpit)
```

### Layer 1 — Soft block (score ≥ 50)

Cheapest, lowest collateral. Real users hit a small delay; attacker
hits a wall on every privileged action.

| Action | Mechanism |
|---|---|
| Insert 1-3s delay on sensitive actions by lineage | `pkg/policy` returns delay flag; bridge sleeps |
| Refuse new Data Passport issuance for the lineage | `passport.Store.lineageBlocklist` set |
| Mark all sessions `step_up_required` | `reqcontract.Lookup` returns flag |
| Reject new outbound from tainted lineage | Egress Valve (P7.1.6 — shipped) |

### Layer 2 — Process freeze (score ≥ 75) — the SIGSTOP cell

The actual jail. The attacker's processes are suspended in kernel
space. They cannot read memory, syscall, send packets, or fork.

| Action | Mechanism | Why |
|---|---|---|
| SIGSTOP every process in lineage tree | walk `hotgraph.Descendants`; `kill -STOP` each | SIGKILL is irreversible; SIGSTOP preserves memory state |
| Recursive on new spawns | eBPF exec hook re-SIGSTOPs any child of frozen set | Attacker `fork()` while frozen? Kernel doesn't schedule them. |
| Pin lineage in hotgraph as `state=Jailed` | Existing pin mechanism (P2.2) | Sweep can't evict; record preserved |
| Operator's SSH session exempt | Match by parent_comm=sshd + allow-list ASN (P-B.0b) | Operator needs to investigate |

**SIGSTOP, not SIGKILL.** Operator can SIGKILL later via explicit
command if the snapshot is complete.

### Layer 3 — Network jail (score ≥ 75)

Even if Layer 2 somehow leaks (attacker SIGCONT's their own
processes), outbound is dead.

| Action | Mechanism |
|---|---|
| nftables drop rule on lineage's cgroup | `pkg/netban` extension — per-cgroup chain |
| eBPF socket-level deny for lineage processes | Same socket-cookie correlation P-RC.3 builds for tagging |
| Drop existing connections from lineage | `ss -K dst <ip> dport <port>` (already in `pkg/netban` quarantine) |
| Allow operator monitoring + IR network | Allow-listed by operator ASN |

### Layer 4 — Filesystem jail + capability strip (score ≥ 90)

Even if SIGCONT'd, the attacker's processes can't write to crown
jewels and can't escalate.

| Action | Mechanism |
|---|---|
| LSM hook denies `open(O_WRONLY)`, `unlink`, `rename` on `credentials/backup/source_code` paths from jailed lineage | BPF LSM hook keyed on (cgroup, path-class) |
| Strip dangerous caps (CAP_NET_RAW, CAP_SYS_ADMIN, CAP_SYS_PTRACE) | eBPF override of capable() check OR userspace `setpriv` |
| Move processes into `xhelix-containment.slice` cgroup with: memory.max=128MB, cpu.max=10ms/100ms, devices.deny=all | systemd cgroup v2 |

**Non-root attackers (webshells as www-data)**: completely jailed.
**Root attackers**: each undo attempt fires another rule and
accelerates score. The race is now visible to the operator.

### Layer 5 — Host-wide lockdown (score = 100)

Only fires on zero-FP signals (canary touched / passport-required
action without passport / chain tampered). Aggressive global response.

| Action | Mechanism |
|---|---|
| Refuse new traffic to all routes catalog-flagged L4+ | `pkg/policy.Check` deny globally |
| Refuse Data Passport issuance host-wide | passport store enters lockdown |
| Force off-host chain flush every 1s | P-CJ.10 uploader accelerated |
| Snapshot `/proc` for all lineage PIDs immediately | P-FT.6 forensic snapshot |
| Page operator on every channel simultaneously | Slack + email + SMS + PagerDuty + OOB |
| Refuse exec from jailed cgroups | eBPF exec hook |

---

## 2. Layer 6 — Deception cell (tarpit + slowdown)

**Only engages when xhelix has high-confidence attribution of the
attacker's source IP/network (≥99%).** Activated by operator
opt-in.

Rather than blocking outright, this layer makes the attacker's
experience progressively degraded so they think their own system or
network is broken. They burn time debugging instead of attacking.

### 2.1 The tarpit (8 bit/s QoS)

The attacker's IP gets QoS-shaped to 8 bits per second (1 byte/s)
outbound and inbound. Their connections technically succeed —
TCP three-way handshake works, HTTP headers eventually arrive, the
session doesn't reset. But every operation takes minutes that
should take milliseconds.

| Tool | Use |
|---|---|
| `tc qdisc add dev eth0 ... htb rate 1byte` per source IP | Linux Traffic Control — established mechanism |
| `nftables ... limit rate 1 bytes/second` per IP | Alternative |
| eBPF tc filter | Cleanest — drop bytes above 1 B/s, no kernel rules to remove |

The psychological effect matters: a "blocked" attacker tries a
different attack vector. A "broken-feeling" attacker tries to fix
their network, restart their VPN, switch laptops — all while xhelix
preserves evidence and the operator investigates.

**Why 8 bit/s and not 0:**
- Connection stays open → attacker sees "responding"
- No reset → attacker doesn't know they were detected
- 1 byte per second renders any meaningful payload impossible
- TCP keepalives still flow — connection doesn't time out cleanly

### 2.2 Syscall latency injection

For attacker processes still able to run (Layer 2 not engaged or
Layer 6 chosen instead): inject latency on every syscall via eBPF.

| Syscall class | Injected latency |
|---|---|
| `read`/`write` | 1-3 s per call |
| `open` | 2-5 s |
| `execve` | 5-10 s |
| `connect` | 5-15 s |
| `getdents` (`ls`) | 1 s per directory entry |

`ls` of a 50-entry directory takes 50 seconds. `cat /etc/passwd`
takes 30 seconds. The attacker types commands and waits and waits.
They suspect hardware failure, kernel bug, anything but EDR.

eBPF mechanism: a kprobe / tracepoint that calls `bpf_ktime_ns()` to
spin or schedule. Honest limit: spinning a kernel-side eBPF program
isn't supportable; the right primitive is **return a slow-path
result by tail-calling into a delay-injection helper** or **delay
the wake-up of the caller's userspace continuation**. Either way:
~5 days of careful eBPF work.

### 2.3 Fake-success responses for exfil attempts

When the attacker's process tries to `connect()` outbound to a
non-allow-listed destination (catalog says it's untrusted):

- TCP handshake completes (against a local catcher socket)
- TLS handshake completes (xhelix-bridge presents a real-looking
  cert)
- HTTP/HTTPS request gets a 200 OK with body = `{}` or empty
- Attacker logs "exfil succeeded"
- xhelix logs: tried to exfil X bytes of [class Y] to [dest Z],
  caught and dropped

The attacker's tooling believes the exfil worked. They may even
proceed to delete local data assuming they have a remote copy. Now
the operator has:
- Full payload they tried to send (in xhelix's capture buffer)
- Proof of intent
- Time to investigate while attacker thinks they're done

### 2.4 DNS poisoning for tainted lineage

Any DNS query from a jailed lineage:

- Resolve to `127.0.0.1` (or to an xhelix-controlled catcher)
- Cache poison the resolver in their process if possible
- For `*.attacker-c2.example`: return a tarpit IP (Layer 6.1)

Combined with §2.3: attacker resolves their C2, gets a fake IP,
"connects" to xhelix-bridge which fake-200s their requests.
They have no way to know the data didn't leave.

### 2.5 Decoy filesystem overlay

When a process in the jailed cgroup tries to `readdir` or `open` on
catalog-flagged crown-jewel paths:

- Overlay returns a *decoy* directory tree (operator-prepared,
  containing pre-planted canary files)
- Real files are invisible to the attacker
- Any read of a canary file triggers maximum-confidence alert
- Any write to the overlay disappears into `/dev/null` (with capture)

Operator pre-creates the decoy at setup time (one-time prep). When
attacker `ls /etc/`, they see `passwd`/`shadow` but the entries are
fake. When they `cat wp-config.php`, they see a canary password.
When they use that password elsewhere — instant zero-FP signal.

---

## 3. The break-glass bastion IP

**The problem**: if xhelix Layer 5 host-lockdown engages, ALL new
sessions and shells are blocked. Operator can't even SSH in to
investigate.

**The solution**: one (or a small set of) operator-declared IP
addresses that bypass ALL containment layers. The fire-escape door —
one direction only, only for the human holding the master key.

### 3.1 Bastion IP requirements

The bastion is dangerous. Lock it down hard:

| Requirement | Why |
|---|---|
| Single IP or /32 (NOT a /24 or larger) | Limit the blast radius |
| Bound to an mTLS client certificate | IP spoofing alone can't bypass |
| Bound to an operator WebAuthn identity | Stolen cert + stolen IP still insufficient |
| Time-bounded (auto-expires in N hours, operator re-issues) | Forgotten-bastion-IP can't accumulate |
| Logged on every use to the signed chain | Operator's own actions are auditable |
| Two-person to add a NEW bastion | Solo operator can't expand the bypass list under stress |
| Bastion's actions still emit lineage events | Bastion isn't invisible; just not blocked |

### 3.2 Bastion config

```yaml
# /etc/xhelix/dlcf/bastion.yaml — signed config

bastion:
  enabled: true
  retention_hours: 24    # operator must re-confirm daily

  entries:
    - ip: 203.0.113.42      # operator's known-good source
      mtls_fingerprint: sha256:abc123...
      webauthn_id: yubikey-operator-1
      grants:
        - bypass_containment: true   # ALL 5 layers bypassed
        - bypass_admin_allowlist: true
        - bypass_passport_required: true   # operator can act without their own passport
        - bypass_route_tier: true            # any L1-L6 route reachable
      expires_at: 2026-05-21T12:00:00Z
      approved_by: ftahirops
      seconded_by: ops_partner_id   # two-person if grants include bypass_*
```

### 3.3 What the bastion is NOT

The bastion is the operator's "in case xhelix locks everything,
how do I get in" emergency hatch. It is NOT:

- A way to grant routine access to admins (use Data Passport for that)
- Long-lived (24h max — re-issue daily)
- Multi-user (one operator at a time per entry; add a second entry
  for a second operator)
- Silent (every action via bastion is signed and chained)
- A backdoor for "convenience" (every grant should be justified in
  the signed config)

### 3.4 Operator workflow with bastion

When containment engages and operator needs to investigate:

```
1. xhelix Layer 5 has locked down /admin/, /wp-admin/, ssh root, etc.
2. Operator SSHs from 203.0.113.42 with their YubiKey
3. xhelix's adminguard checks bastion list FIRST:
     203.0.113.42 + mTLS cert sha256:abc123 + WebAuthn yubikey-operator-1
     → match → bypass containment
4. Operator's SSH session lands as root
5. Operator runs xhelixctl containment list, identifies the
   jailed lineage, takes forensic snapshot, etc.
6. After investigation, operator runs:
     xhelixctl containment disengage <lineage_id>
   (which requires fresh WebAuthn + 2-person for score ≥ 90)
7. xhelix exits containment mode
8. Bastion entry auto-expires at the 24h mark; operator re-issues
   if still needed
```

---

## 4. Root-session global lockdown

When score = 100 with confirmed compromise:

| Action | Mechanism |
|---|---|
| Block all new SSH sessions to `root` user | PAM module + sshd config |
| Block `su -`, `sudo -i`, `sudo /bin/bash` | LSM hook on setuid + comm transition |
| Block any new exec by uid=0 (except from bastion) | eBPF exec hook with uid check |
| Block all new `nsenter`, `unshare`, container exec | LSM audit + capability deny |
| Existing root sessions stay alive (for forensics) | Don't kill the operator's current shell |

The only path that survives: the bastion's allow-listed connection.
Operator's existing session stays alive. The attacker who got root
through whatever means cannot open a new root anywhere.

---

## 5. Composition: how all of this fires together

For a concrete scenario — web→shell→credential read→outbound — at
the moment the score hits 100:

```
T+0      Egress Valve refuses the outbound connect
         (lineage was already tainted from the .env read)
T+0      Score crosses 100 (canary or passport-required-without-passport)
T+0+10ms Layer 1: passport blocklist set for lineage
T+0+15ms Layer 2: SIGSTOP every PID in lineage tree
                  (php-fpm worker, bash, curl — all frozen mid-syscall)
T+0+20ms Layer 3: nftables drop rule installed for the cgroup
T+0+25ms Layer 4: LSM hook denies new writes from cgroup
                  capabilities stripped from frozen processes
                  cgroup moved to containment.slice
T+0+30ms Layer 5: routes /wp-admin/, /admin/ enter host-lockdown
                  passport issuance globally disabled
                  off-host chain mirror flush triggered
T+0+50ms Layer 6 (if enabled + attacker IP known): tarpit on
                  attacker's source IP at 8 bit/s
                  (so even their L7 retry attempts go nowhere)
T+0+100ms Forensic snapshot triggered: /proc dump for lineage
T+0+200ms Operator paged on all channels with chain.takeover_confirmed
T+0+1s   Off-host chain mirror confirms last 1h batch durable
T+0+5s   Operator (presumably) SSHs in from bastion IP with YubiKey
T+0+30s  Operator inspects, decides, executes containment.disengage
         OR escalates to full forensic mode and rebuild
```

Total time from compromise event to attacker fully jailed: ~30 ms.
Total time to durable forensic evidence off-host: ~1 second. Total
time to operator notification: ~200 ms.

---

## 6. What this design EXPLICITLY does NOT do

Refused capabilities, with reason:

| Refused capability | Why xhelix won't do it |
|---|---|
| SIGKILL on detection | Loses memory state needed for forensics; SIGSTOP first |
| Reboot the host | Wipes all process memory + may lose unflushed chain batches |
| Auto-restore from backup | Backup may be poisoned; operator decision |
| Block ALL traffic (including operator) | Operator can't investigate; bastion IP exception is the right model |
| Notify "the user" of the compromised session | The user may be the attacker, or be socially-engineered |
| Wipe / shred files | Destruction of evidence; not the operator's intent |
| Permanently lock containment | 24h auto-clear; operator must affirmatively maintain |
| Take action without signed config | Containment rules are operator policy, not daemon convenience |
| Silently change anything | Every action chained + signed + emitted as event |

---

## 7. Honest limits (the things this CAN'T do)

Stated again because the temptation to oversell is real:

### 7.1 Same-host root with kernel exploit

If the attacker reaches kernel-mode (kernel exploit, signed
malicious kernel module loaded before xhelix's LSM hook), they can:

- Unload xhelix's BPF programs → Layer 4 collapses
- SIGKILL xhelix → every layer collapses
- Patch nftables directly → Layer 3 collapses
- Restore their own frozen processes → Layer 2 partially collapses

**What we have**: watchdog peer + remote heartbeat (P-CJ.5) detects
the daemon kill within ≤5 min. Off-host chain (P-CJ.10) captures
the attempt. Each undo is itself an alert.

**The fundamental limit**: same-host kernel root eventually wins.
xhelix raises the cost from "trivial" to "many minutes of focused
attacker effort while the operator is paged." That's the floor.

### 7.2 False-positive containment of a legitimate user

If the scorer false-positives a real user's lineage and engages
Layer 2 (SIGSTOP), that user sees their session frozen until the
operator clears.

Mitigation:
- Layers 2-4 require score ≥ 75, which by design needs multiple
  Tier-2 signals or one Tier-1 signal to reach
- Tier-1 signals (canary touch, passport missing) are zero-FP by
  construction
- First two weeks of deployment: run in "report-only" mode (alerts
  fire, containment doesn't) until tuning is dialed in
- Layer 1 (soft block: delay + step-up) is the only layer to
  engage at score 50-74 — affects user experience minimally

### 7.3 Deception layer's ethics + legality

The deception layer (Layer 6) involves:
- Returning fake responses (could be argued as deception)
- Showing decoy files (canaries — operator-planted)
- Tarpitting traffic from a specific IP

**This is defensive only.** xhelix never reaches out to the
attacker. The attacker initiated traffic to your infrastructure;
your infrastructure is free to respond slowly or with operator-
controlled fake content. The legal posture is the same as any
honeypot or tarpit operator's. Document operator opt-in for the
deception layer.

### 7.4 What about the attacker's lateral movement BEFORE detection?

If the attacker pivoted to another host before xhelix detected on
this one, xhelix on host A cannot retroactively contain on host B.
Cross-host containment requires xhub fleet correlation (already
exists in code; needs operator setup + soak test).

---

## 8. Implementation phases — what to build for each layer

| Layer | Status | Effort | Task |
|---|---|---:|---|
| 1 — Soft block | Substrate shipped (passport, policy, egress) | ~1 d wiring | P-FT.5 |
| 2 — Process freeze (SIGSTOP) | Hotgraph descendants shipped; needs lineage-scoped SIGSTOP impl | ~2 d | P-FT.5 |
| 3 — Network jail per cgroup | `pkg/netban` shipped for host-wide; needs cgroup-scoped | ~2 d | P-FT.5 |
| 4 — FS jail + cap strip + cgroup move | Requires new BPF LSM enforcement (existing audit only) | ~5 d (the hardest) | P-FT.5 |
| 5 — Host-wide lockdown at score 100 | Composition of layers + global policy flag | ~2 d | P-FT.5 |
| 6 — Tarpit (8 bit/s QoS) | tc/nftables shaping per IP, eBPF tc filter alternative | ~3 d | **P-FT.11 (new)** |
| 6 — Syscall latency injection | eBPF kprobe with bounded delay | ~5 d | **P-FT.11 (new)** |
| 6 — Fake-success outbound | xhelix-bridge catcher mode for jailed lineages | ~4 d | **P-FT.11 (new)** |
| 6 — DNS poison | resolver hook OR LD_PRELOAD overlay per cgroup | ~3 d | **P-FT.11 (new)** |
| 6 — Decoy filesystem overlay | overlayfs + operator pre-staged decoys + BPF LSM read redirect | ~5 d | **P-FT.11 (new)** |
| Break-glass bastion IP | Allow-list in `pkg/adminguard` + mTLS + WebAuthn + signed config | ~4 d | **P-FT.12 (new)** |
| Root-session global lockdown | PAM module + LSM exec deny for new uid=0 | ~3 d | **P-FT.13 (new)** |

**Layers 1-5 total**: ~12 days (within existing P-FT.5 task).
**Layer 6 (deception cell) total**: ~20 days (P-FT.11 — new task).
**Bastion + root lockdown total**: ~7 days (P-FT.12 + P-FT.13 — new tasks).

Total all containment + deception: ~39 days of focused work.

Recommended order:
1. Layer 2 (SIGSTOP) — biggest single value, cheapest, ~2 days
2. Layer 3 (network jail) — extends pkg/netban, ~2 days
3. Break-glass bastion (P-FT.12) — required *before* enabling Layer 5
4. Layer 5 (host lockdown) — needs bastion as safety net
5. Layer 1 (soft block) — refinement
6. Root-session lockdown (P-FT.13)
7. Layer 4 (BPF LSM FS + cap) — hardest
8. Layer 6 (deception cell P-FT.11) — most ambitious; opt-in

The bastion (P-FT.12) is in the critical path because Layer 5
without it can lock the operator out. **Never ship host-lockdown
without ship-bastion first.**

---

## 9. Configuration summary

The entire containment behavior is operator-tunable. Defaults exist
but every site has different tolerance.

```yaml
# /etc/xhelix/dlcf/containment.yaml — signed config

containment:
  enabled: true
  report_only: false   # set true for first 2 weeks of soak

  layers:
    soft_block_at:    50
    sigstop_at:       75
    network_jail_at:  75
    fs_jail_at:       90
    cap_strip_at:     90
    cgroup_move_at:   90
    host_lockdown_at: 100

  deception:
    enabled: false   # opt-in
    tarpit_bytes_per_sec: 1
    syscall_latency_ms: 1000
    fake_success: false   # most aggressive — needs operator approval
    decoy_filesystem: false
    dns_poison: false

  exemptions:
    - actor_comm: sshd
      source_asn_in: [AS64500]   # operator's ASN
    - cgroup_unit: xhelix.service

  reversal:
    require_webauthn: true
    require_2person_for_score_above: 90
    auto_clear_after_idle_hours: 24

bastion:
  retention_hours: 24
  entries:
    - ip: 203.0.113.42
      mtls_fingerprint: sha256:abc...
      webauthn_id: yubikey-operator-1
```

---

## 11. Design refinements (bake into v1)

Each refinement below is operator-tunable and addresses a known
failure mode of the basic 6-layer cell. None is optional; all must
ship together with the layer they refine.

### 11.1 Reputation / threat-intel weighting

The same score that engages containment for an unknown ASN should
engage one layer LATER than for a known-bad ASN. xhelix already has
`pkg/intel` with Spamhaus/Emerging-Threats feeds — add it as an
input to the containment-tier decision.

```yaml
containment:
  reputation_threshold_shift:
    intel_match_known_c2:        -25    # engage one tier earlier
    intel_match_residential_isp:  +25   # require one tier higher (NAT collateral)
    intel_match_corporate_proxy: +25
    intel_match_known_good_asn:  +999   # effectively never tarpit
  
  operator_allow_list:
    # IPs/ASNs that ONLY ever go through layer 1 (soft block) regardless of score
    - asn: AS64500   # operator's own ASN
    - ip:  203.0.113.42   # bastion (redundant with bastion config, defense in depth)
```

Effect at runtime: a score-75 event from a known datacenter abuse
ASN tarpits immediately; the same score from a residential ISP only
triggers Layer 1 (soft block) until score crosses 100.

**Builds on**: `pkg/intel` (shipped), `pkg/adminguard` (shipped).
**Effort**: ~2 days extension.

### 11.2 Per-cgroup tarpit (preferred over per-IP)

When the attacker can be isolated to one cgroup (typical for
webshells, container exec, single PHP-FPM worker), tarpit ONLY that
cgroup's outbound. Zero collateral on the shared IP.

```
Detection: lineage_root = web_app/cgroup_id=85013292
Containment choice:
  ✅ Per-cgroup tarpit  (no NAT collateral; precise)
  ⚠ Per-IP tarpit       (only when attacker session crosses cgroups
                          OR when source IP is on threat-intel allowlist
                          for known abuse)
```

Mechanism: eBPF tc filter keyed on `cgroup_id` (not source IP). The
cgroup id is already in every xhelix event; the BPF program just
maps `cgroup_id → tarpit_rate`.

**Effort**: ~2 days. Same eBPF skeleton as per-IP tarpit but different
key.

### 11.3 Graceful tarpit degradation

Do not snap from 1 Gb/s to 8 b/s instantly. Progressive ramp:

```
T+0     1 MB/s    (still fast enough that user retries work)
T+30s   1 KB/s    (sluggish — attacker starts to suspect)
T+5min  100 B/s   (clearly broken — attacker investigates network)
T+10min 8 B/s     (steady tarpit — attacker thinks system is dead)
```

Two benefits:

1. **FP recovery**: if attribution turns out wrong, the 30-second
   1 MB/s phase is barely noticeable to the legitimate user. By the
   time we're at 100 B/s the operator has had 5 minutes to clear
   the FP.

2. **Attacker psychology**: instant connection death = "blocked",
   triggers attacker counter-action. Progressive slowdown =
   "network issue", they call their ISP. Time spent debugging is
   time the operator has to investigate.

**Effort**: ~1 day on top of basic tarpit.

### 11.4 Auto-rollback on signal resolution

If a lineage emits NO new takeover signals for N minutes, containment
automatically de-escalates by one layer.

```
Layer 5 (host lockdown) → Layer 4 after 15 min of silence
Layer 4 → Layer 3 after 30 min
Layer 3 → Layer 2 after 60 min
Layer 2 → Layer 1 after 2 hr
Layer 1 → cleared after 4 hr
```

The "silence" check counts: no new alerts, no new exec by lineage,
no new outbound attempts. If ANY new signal fires, the de-escalation
timer resets and containment re-escalates.

**Why**: prevents permanent FP punishment of a benign user that
once tripped Tier-2 signals. Operator can manually accelerate or
reset; the auto-rollback is the safety valve.

**Effort**: ~2 days. State machine on top of the takeover scorer
(P-FT.1).

### 11.5 Bastion health check

A small operator-side script (`xhelixctl bastion test`) that:

- Validates the bastion IP is reachable
- Confirms the mTLS cert is still valid (expires_at > 24h away)
- Tests a no-op LocalAPI call through the bastion path
- Reports "bastion is healthy AND will still be valid in 24h"

Run as a daily cron from a trusted operator workstation. If the
test fails, alert via the same channels xhelix uses for takeover
notifications.

```bash
# /etc/cron.d/xhelix-bastion-check
0 9 * * * operator /usr/local/bin/xhelixctl bastion test \
            --alert-on-fail slack://#ops-emergency
```

**Why**: catches "I forgot to renew the bastion" BEFORE the incident
that needs it.

**Effort**: ~1 day client side + ~1 day server-side health endpoint.

### 11.6 Dual bastions minimum

Configuration requires AT LEAST TWO bastion entries:

```yaml
bastion:
  retention_hours: 24
  minimum_active_entries: 2   # NEW: refuse to start if < 2 entries
  
  entries:
    - name: primary
      ip: 203.0.113.42
      mtls_fingerprint: sha256:abc...
      webauthn_id: yubikey-operator-1
      
    - name: backup
      ip: 198.51.100.10
      mtls_fingerprint: sha256:def...
      webauthn_id: yubikey-operator-2   # MUST be a different key
      operator: ops_partner_id           # MUST be a different person
```

xhelix refuses to engage Layer 5 host-lockdown if fewer than 2
distinct (IP, operator, key) entries are configured. Single
bastion is a single point of failure.

**Why**: if the primary operator's IP changes unexpectedly (mobile,
ISP outage, key lost), the backup operator keeps the host
reachable. Defense in depth at the operator layer.

**Effort**: ~1 day enforcement + docs.

### 11.7 Tarpit's capture buffer IS the alert source

Do not just slow attacker traffic. Capture every byte they tried to
send. The tarpit's catcher socket becomes the forensic record of
intent:

```
attacker → tarpit → xhelix-catcher socket (accepts everything,
                    forwards nothing, captures up to 4MB per session)
                  → batched JSON event:
                      {
                        "kind": "tarpit_capture",
                        "lineage_id": ...,
                        "source_ip": ...,
                        "dst_was": "attacker-c2.example.com:443",
                        "tls_sni": "attacker-c2.example.com",
                        "first_bytes_hex": "16030100c0...",
                        "byte_count": 2847,
                        "session_duration_ms": 18234
                      }
                  → chain-signed
```

Operator gets a forensic record of:

- Where they tried to exfil to
- What they tried to send (first 4 MB)
- TLS SNI (often reveals their C2 domain even with cert pinning)
- How long they tried before giving up

This is more valuable than the tarpit slowdown alone. The slowdown
is the *containment*; the capture is the *intel*.

**Effort**: ~3 days (catcher socket + capture buffer + capture
event format + chain integration).

---

## 12. What to borrow from Tetragon (Isovalent)

Tetragon is Cilium/Isovalent's kernel-level security observability +
enforcement framework using eBPF. It shares ~40% of xhelix's design
space. Honest analysis of what's worth borrowing:

### 12.1 Worth borrowing

**`bpf_send_signal()` for in-kernel SIGSTOP/SIGKILL** — the killer
feature. Tetragon can SIGKILL a process from kernel space via this
helper, BEFORE the syscall that triggered the rule completes.

For xhelix's Layer 2 (SIGSTOP), this is transformative:
- Today's plan: userspace dispatch loop sees the event, sends
  SIGSTOP. Total latency: ~50 µs from syscall to suspended.
  In that 50 µs the attacker's process can do ONE more syscall.
- With `bpf_send_signal(SIGSTOP)`: kernel sends the signal in the
  same context as the triggering syscall. Total latency: <1 µs.
  The attacker's process never returns from the syscall that
  tripped detection.

Add to `sensors/ebpf/progs/all.bpf.c`: a new BPF program that
attaches to syscall enter for sensitive operations, checks the
containment-cell map, calls `bpf_send_signal(SIGSTOP)` if the
process is jailed.

**Effort**: ~4 days. Lifts Layer 2 from "fast" to "instantaneous."

**`bpf_override_return()` for fake-success outbound** — Tetragon
uses this to modify syscall return values. For xhelix's deception
layer §2.3 (fake-success), this is exactly the primitive needed:

- Attacker's `connect()` is intercepted in `socket_connect` LSM hook
- BPF program calls `bpf_override_return(0)` — connect "succeeds"
  with errno=0
- Subsequent `write()`s go to a kernel-side capture buffer
- Subsequent `read()`s return canned fake-success responses

This is more efficient and more deceptive than the userspace
catcher socket alternative. Attacker's tooling never sees the
proxy hop.

**Effort**: ~5 days. Requires careful BPF LSM work.

**Declarative-policy-generates-eBPF-hook pattern** — Tetragon's
`TracingPolicy` YAML is compiled into eBPF programs at load time.
xhelix's CEL rules are evaluated in userspace.

For xhelix's `pkg/invariants` (P-FT.3 — declarative
impossible-action loader), borrowing this pattern means:

```yaml
# ruleset/dlcf/invariants.yaml
- name: web_tier_no_shell
  scope: { actor_class: web_tier }
  forbid:
    syscall: execve
    arg0_basename_in: [bash, sh, zsh]
  action: bpf_send_signal_sigkill   # ← Tetragon-style enforcement
```

→ xhelix compiles this into an eBPF program at startup that hooks
`tracepoint:sched:sched_process_exec` with an inline filter and a
kernel-side `bpf_send_signal(SIGKILL)`.

Why borrow this for invariants specifically: invariants are
DETERMINISTIC. CEL evaluation in userspace is overkill — and slow
(userspace round-trip per event). Generating eBPF for invariants
means the rule never reaches userspace; the kernel enforces
in-place at sub-microsecond cost.

**Effort**: ~7 days. Significant lift but enables genuinely
zero-latency enforcement for invariants.

### 12.2 Don't borrow

**Tetragon's `TracingPolicy` schema for ALL rules** — xhelix's CEL
rule engine is more expressive for *behavioral* detection (multi-
event correlation, threshold tracking, etc.). Use Tetragon's
generated-eBPF model ONLY for invariants (deterministic
forbidden actions); keep CEL for everything else.

**Kubernetes-native metadata coupling** — Tetragon's heavy k8s
integration (pod labels, namespaces, k8s service objects) is wrong
for xhelix's SMB / solo-operator target. Stay Linux-host-focused.

**Hubble UI** — Cilium's observability UI is for cluster-scale
deployments. xhelix's operator UX is `xhelixctl` + LocalAPI;
graduate to web UI in P5, not now.

**Process credential tracking in BPF maps** — xhelix tracks
UID/GID/caps in userspace via ProcKey + Hotgraph already. Moving
it to BPF maps is a refactor with marginal benefit; defer.

### 12.3 The composite design

Combining the borrows above:

```
Tetragon-borrowed   xhelix-original          Combined result
─────────────────   ──────────────────       ────────────────────────
bpf_send_signal     pkg/lineage              In-kernel SIGSTOP of
+                   + hotgraph descendants   the lineage tree, sub-µs
TracingPolicy gen   pkg/invariants           Invariants compile to
                                              eBPF, no userspace hop
bpf_override_return pkg/policy + catalog     Fake-success outbound
                                              for jailed lineage,
                                              kernel-side capture
─                   pkg/takeover scorer      Userspace aggregation
                                              of probabilistic signals
                                              (Tetragon doesn't do)
─                   pkg/passport, nonce,     Cryptographic deterministic
                    chain, reqcontract       defenses Tetragon lacks
```

xhelix's CEL rules and behavioral scorer are the part Tetragon
doesn't have. Tetragon's `bpf_send_signal` and
`bpf_override_return` are the part xhelix's userspace pipeline
can't match for latency. Together: best of both.

### 12.4 Honest comparison

| Capability | Tetragon today | xhelix today | After borrowing |
|---|---|---|---|
| In-kernel kill of attacker process | ✅ Native | ⚠ Userspace ~50µs | ✅ Sub-µs |
| Declarative deny rules → eBPF | ✅ TracingPolicy | ⚠ CEL in userspace | ✅ Hybrid |
| Multi-event behavioral correlation | ❌ | ✅ Correlator + lineage | ✅ |
| Sensitivity budget / slow-drip detection | ❌ | ✅ pkg/budget | ✅ |
| Signed audit chain + offline verify | ❌ | ✅ pkg/chain | ✅ |
| Data Passport / signed action approval | ❌ | ✅ pkg/passport | ✅ |
| Canary classification + zero-FP signals | ❌ | ✅ catalog + canary rules | ✅ |
| Kubernetes-native | ✅ | ❌ (by design) | ❌ (kept) |
| Tarpit / deception cell | ❌ | Planned (P-FT.11) | ✅ enhanced by bpf_override_return |
| SMB-friendly | ❌ (k8s-tier complexity) | ✅ | ✅ (kept) |

The honest summary: **Tetragon and xhelix are complementary, not
competitive.** Tetragon is a kernel-level enforcement primitive that
EXCELS at fast, deterministic deny. xhelix is a causal-chain
behavioral correlator with cryptographic audit guarantees that
Tetragon doesn't have.

Borrowing `bpf_send_signal` and `bpf_override_return` into xhelix's
existing eBPF programs gives xhelix Tetragon's speed for the
deterministic deny cases (invariants, jailed-lineage syscalls)
without losing the behavioral / correlation / cryptographic strengths
that are xhelix's differentiation.

---

## 10. The TL;DR

xhelix should JAIL the attacker, not just detect them. The right
model is:

1. **5 graduated layers** that engage as confidence rises, each
   reversible
2. **Deception cell (Layer 6)** for high-confidence attribution —
   make them think their tools are broken instead of telling them
   they're caught
3. **Break-glass bastion IP** as the operator's emergency entry —
   one designated path that survives total lockdown
4. **Root-session global lockdown** when full takeover is confirmed
5. **Never destructive without operator approval** — SIGSTOP not
   SIGKILL, drain not reboot, decoy not delete

That's a real cell. The attacker is suspended in place, their
network is dead or sluggish, their writes go to /dev/null, their
exfil reports success to themselves but stays local for forensics.
The operator walks in from a known IP with a YubiKey, investigates,
and decides what to do next.

This is what an EDR is FOR.
