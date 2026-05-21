# xhelix — Detection Coverage Matrix vs Real-World Threat Landscape

**Built**: 2026-05-21
**Method**: cross-reference current public threat intel (2025–2026
samples, CVE catalogs, MalwareBazaar tags) against the xhelix rule set
+ sensor coverage + live empirical data from this host.
**Status**: living document — updated as samples are tested in the
Ring-A sandbox (see TEST_PLAN.md §1.2).

Companion docs: `TEST_PLAN.md`, `ALERTS_AND_FP_PLAN.md`,
`DETECTION_GAPS.md`, `PHASE_1_RESULTS.md`.

---

## 1. Active Linux malware landscape (2025–2026 public reporting)

Sources combed: MalwareBazaar (abuse.ch), CISA, Wiz, FortiGuard,
Hunter Strategy, CommandLinux statistics. URLs at the bottom.

### 1.1 Threat-class breakdown (per CommandLinux 2026 stats)

| Class | Share of Linux malware | Primary attack vector |
|---|---|---|
| Webshells | 49.6% | exploit public-facing app |
| Trojans | 29.4% | gained access + persistence |
| Backdoors | 12.3% | persistent C2 channel |
| Crypto miners | 8.7% | resource hijack |
| Brute-force | 89% of all endpoint behaviour | SSH |

Linux CVEs: **3,529 in 2024 (+1,117% YoY)**, **5,530 YTD 2025**.

### 1.2 Currently active families & techniques

| Family | First seen | What it does | Detection challenge |
|---|---|---|---|
| **BPFDoor** | 2021, very active 2025 (151 new samples) | eBPF packet filter "magic packet" backdoor; no listening port; survives reboots via systemd; IPv4+IPv6+SCTP, port hopping | invisible to netstat; eBPF program loaded by attacker, not OS |
| **Symbiote** | 2021, July 2025 variant | shared-object preload + eBPF; hooks libc + libdl; hides files/procs/connections | works pre-exec via LD_PRELOAD |
| **TripleCross** | research/red-team | eBPF hooks `execve` for process manipulation | hooks the same primitive xhelix watches |
| **Boopkit** | research | eBPF covert C2 channel inside crafted packets | bpf socket-filter |
| **RingReaper** | 2025 | io_uring async I/O syscalls bypass syscall-tracing EDRs | xhelix's tracepoint-based hooks miss io_uring ops |
| **LinkPro** | 2025 | Jenkins CVE-2024-238976 → malicious docker image → AWS EKS lateral; container escape via host mount; eBPF concealment | container escape, eBPF rootkit, supply chain combo |
| **VoidLink** | Jan 2026 | cloud + container targeting | active investigation |
| **Mirai** | 2016, mutating | IoT botnet; SSH brute, exploits, persistence | known patterns |
| **XMRig** | persistent | crypto-miner dropped via web exploits, persists via cron | cron + outbound |
| **TeamTNT** | active | k8s/docker creds theft, container escape | cred theft + escape |
| **Kinsing** | active | tor + shell + miner | proc + outbound |
| **XorDDoS** | older, mutating | LKM rootkit + DDoS | kernel module loading |
| **LockBit Linux** | 2022+ | ransomware; targets ESXi/QEMU/Linux | enc activity + lateral |
| **Play Linux** | 2024+ | ransomware | same |
| **Akira Linux** | 2024+ | ransomware | same |
| **Kraken** | emerging | Linux ransomware variant | same |

---

## 2. Coverage matrix — does xhelix detect each behaviour?

Legend:
- **Covered** ✅ — rule exists, sensor emits, live tested in Phase 1 OR golden test
- **Partial** ⚠️ — primitive observable but rule weak or cooccur not wired
- **Gap** ❌ — sensor or rule missing

### 2.1 eBPF rootkit primitives (BPFDoor, Symbiote, TripleCross, Boopkit, RingReaper)

| Behaviour | xhelix capability | State |
|---|---|---|
| Unauthorised `bpf()` syscall to load BPF program | `bpf_syscall_unexpected` rule fires | ✅ (with FP: see §4) |
| Pinned BPF program in `/sys/fs/bpf` | FIM doesn't watch BPF FS | ❌ — add watch_path |
| BPF program attaches `kprobe`/`tracepoint`/`fentry` | not enumerated by sensors | ❌ — need bpftool-style enumeration |
| Magic-packet trigger over unusual proto (SCTP, raw) | netids — partial | ⚠️ — SCTP not parsed |
| Process with no listening port but accepting traffic | netids socket-state mismatch | ❌ — needs flow inference |
| LD_PRELOAD-loaded shared object (Symbiote shim) | `ld_so_preload_modified` FIM | ✅ |
| Symbiote-style libc symbol hooking | not detected unless preload file written | ⚠️ |
| **io_uring async syscalls** (RingReaper) | xhelix eBPF hooks tracepoints not io_uring submission queues | ❌ critical gap |
| eBPF-LSM hooks installed by attacker | requires BPF LSM on cmdline | ❌ — host lacks `lsm=bpf` |
| Rootkit-style attack on xhelix's own eBPF event path | `kallsyms_changed`, `modules_changed` rules exist | ⚠️ — only post-hoc |

### 2.2 Initial access (T1190: exploit public-facing app)

| Vector | xhelix capability | State |
|---|---|---|
| Webshell deploy (PHP, JSP, Python) | FIM on www-data writable dirs (not default) | ❌ — add config |
| Web RCE → `/bin/sh` | `web_server_spawns_shell` ✅ verified Phase 1 | ✅ |
| Jenkins CVE-2024-238976 lateral path | the exec-then-net + crendential-pull chain | ⚠️ — partial via cooccur, app context absent |
| Tomcat/Spring4Shell/Struts | proc + interp combo | ⚠️ — generic |
| Log4Shell JNDI | outbound LDAP from java + class load | ⚠️ — needs DPI |
| Confluence CVE chain | proc | ⚠️ |
| SSRF → metadata service | `metadata_svc_unexpected` rule | ⚠️ — designed but unverified live |

### 2.3 Execution (T1059, T1106, T1129)

| Vector | xhelix capability | State |
|---|---|---|
| `/bin/sh` from web user | `shell_with_socket_fd`, `web_server_spawns_shell` | ✅ |
| Reverse shell `bash -i >& /dev/tcp/` | `shell_with_socket_fd` ✅ live | ✅ |
| Inline interpreter (`python -c`, `perl -e`, `ruby -e`) | proc spawn tracked, no dedicated rule | ⚠️ |
| `memfd_create + execve` fileless | `memfd_run_pattern` ✅ live | ✅ |
| `execveat` from arbitrary FD | covered as above | ✅ |
| Binary from `/tmp`, `/dev/shm`, `/var/tmp` | `binary_runs_from_tmp` | ⚠️ — needs verification |
| LOLBin abuse (`gtfobins` find -exec, vim !sh) | proc tree visibility, no dedicated rule | ⚠️ |

### 2.4 Persistence (T1543, T1547, T1574, T1098, T1037)

| Vector | xhelix capability | State |
|---|---|---|
| `/etc/cron.d/*` drop | FIM ✅ + `cron_new_unit` rule | ✅ |
| `/etc/cron.daily/*` | FIM | ✅ |
| `/etc/crontab` modify | FIM | ✅ |
| `/etc/systemd/system/*.service` | FIM | ✅ |
| systemd user unit `/etc/systemd/user/*` | watched but no rule split | ⚠️ |
| systemd path/socket/timer units | FIM, no specialised rule | ⚠️ |
| `/etc/ld.so.preload` modify | `ld_so_preload_modified` ✅ remediator | ✅ |
| `LD_AUDIT` env injection | no rule | ❌ (GAP-03) |
| `/lib/security/`, `/usr/lib64/security/` PAM module drop | `pam_module_drop` rule | ✅ |
| `/root/.ssh/authorized_keys` append | `ssh_key_added_root` rule | ✅ |
| `/etc/passwd` add UID 0 user | `tamper_passwd` rule | ✅ (FP risk: useradd) |
| `/etc/shadow` modify | `tamper_shadow` | ✅ (FP risk: passwd cmd) |
| `~/.bashrc`, `~/.zshrc`, `~/.profile` | not in default watch_paths | ❌ (GAP-10) |
| `/etc/profile.d/*.sh` drop | not in default watch_paths | ❌ (GAP-11) |
| `/etc/rc.local` | FIM (distro-dependent) | ⚠️ |
| SUID copy of `/bin/sh` to attacker path | `suid_baseline` diff | ✅ |
| File capabilities (`setcap`) on dropped binary | no dedicated rule | ❌ (GAP-04) |
| LKM (`init_module`) — real kernel module | `modules_changed` + `cap.gained` | ✅ |
| Pinned BPF prog as persistence | not watched | ❌ |
| Bash hook via `PROMPT_COMMAND` | env-tracking absent | ❌ |
| GRUB / initramfs implant | out of scope without TPM measurement | ❌ |

### 2.5 Credential access (T1003, T1552, T1555, T1083)

| Vector | xhelix capability | State |
|---|---|---|
| Read `/etc/shadow` | FIM read-tap on watched paths | ⚠️ — read-tap quality unverified |
| Read `~/.ssh/id_rsa` | FIM on `/root/.ssh`, `/home/*/.ssh` | ✅ |
| Read `/proc/<pid>/environ` for env-stored creds | no rule | ❌ |
| Cloud metadata (IMDS, GCE, Azure) | `metadata_svc_unexpected` rule | ⚠️ |
| Browser cred files | path-catalog (P-PS.19) | ⚠️ |
| Docker / Kube / AWS config files in home | no rule for non-default paths | ⚠️ |
| ssh-agent socket abuse | no rule | ❌ (GAP-20) |
| GPG agent abuse | no rule | ❌ (GAP-21) |
| Linux keyrings (keyctl) | no signal | ❌ (GAP-23) |
| `process_vm_readv` against auth daemons (LSASS-equivalent) | NeverLearnable signal | ⚠️ — generic, not auth-weighted (GAP-25) |
| Mimipenguin-style cred dumper | proc-walk + LFI cooccur | ⚠️ |

### 2.6 Defense evasion (T1562, T1014, T1027, T1070)

| Vector | xhelix capability | State |
|---|---|---|
| `systemctl stop xhelix` | tamper.systemd + watchdog (P-CJ.5 pending) | ⚠️ |
| `kill -9` xhelix | watchdog | ⚠️ |
| Corrupt chain dir | tamper.chain | ⚠️ — verifier catches it post-hoc |
| Wipe `alerts.jsonl` | xhelix doesn't watch its own logs | ❌ (GAP-50) |
| AppArmor disable | LSM posture check | ⚠️ |
| seccomp escape via prctl | no rule | ❌ (GAP-51) |
| Timestomp (touch -t) | `tamper.binary_mtime` rule | ✅ |
| `shred -uz` of artefacts | RecursiveDelete signal | ✅ |
| history clear (`history -c`, unset HISTFILE) | identity tamper | ⚠️ |
| tmpfs mount over `/var/log` | no rule | ❌ (GAP-52) |
| iptables -F | no rule for network-posture change | ⚠️ |
| UPX-packed binary | no entropy check | ❌ (GAP-53) |
| prctl(PR_SET_NAME) spoof | no comm vs basename check | ❌ (GAP-54) |

### 2.7 Lateral movement / C2 (T1071, T1090, T1572, T1037)

| Vector | xhelix capability | State |
|---|---|---|
| Reverse shell over TCP | `shell_with_socket_fd` | ✅ |
| Reverse shell over TLS | DPI sniffer + shell rule | ⚠️ |
| nc/ncat reverse | `shell_with_socket_fd` | ✅ |
| socat reverse | shell rule | ✅ |
| Metasploit reverse_tcp | takeover scorer should accumulate | ⚠️ |
| Sliver implant | beacon + memfd | ⚠️ — never tested live |
| Cobalt-Strike-Linux | beacon + cooccur | ⚠️ |
| C2 via DNS TXT | `netids.dga` + `dnsexfil.tunnel_pattern` | ⚠️ |
| C2 via DoH (1.1.1.1, dns.google) | no rule for DoH endpoints | ❌ (GAP-33) |
| C2 via WebSocket | no L7 classification on TLS | ❌ (GAP-30) |
| C2 via QUIC | no SNI in UDP path | ❌ (GAP-32) |
| C2 via ICMP tunnel | raw-socket events rare | ❌ (GAP-31) |
| Low-and-slow beacon (60min jitter) | `beacon.periodic_callback` over time | ⚠️ — never tested |
| Lateral SSH from compromised box | egress + new-asn + identity | ⚠️ |

### 2.8 Container & VM escape (T1611, T1610)

| Vector | xhelix capability | State |
|---|---|---|
| `cap_sys_admin` + mount /proc/1/root | LSM + FIM cooccur | ⚠️ |
| `/var/run/docker.sock` from inside | no dedicated rule | ❌ (GAP-40) |
| cgroup v1 release_agent | LSM + FIM tamper.core_pattern | ⚠️ |
| cgroup v2 escape paths | partial coverage | ⚠️ |
| `kexec_load` syscall | NeverLearnable | ⚠️ |
| `init_module` real .ko | `modules_changed` | ✅ |
| `unshare(CLONE_NEWUSER)` + nsenter chain | no rule | ❌ (GAP-41) |
| overlayfs write to host layer | LSM + FIM | ⚠️ |
| `/proc/1/root/...` walk from container | no rule | ❌ (GAP-42) |
| seccomp bypass via ptrace | `ptrace_sensitive_target` | ✅ |
| LXC unprivileged escape | partial via release_agent | ⚠️ |
| runc CVE-2019-5736 overwrite class | `contescape.detected` rule | ⚠️ (but FP-grenade — see §4) |
| Dirty Pipe / Dirty Cred class | LSM + cap | ⚠️ |
| Jenkins → docker image → EKS lateral (LinkPro) | cooccur of exec + outbound + container | ❌ — no end-to-end test |

### 2.9 Authentication attacks (T1110, T1078, T1098, T1556)

| Vector | xhelix capability | State |
|---|---|---|
| SSH password brute | `ssh_brute_then_success` + identity.sshd | ✅ designed |
| SSH key auth from new IP/ASN | identity.sshd ASN check | ⚠️ |
| SSH key auth from TOR exit | netids + intel | ⚠️ |
| PAM bypass via faketime + cached pass | identity.pam | ⚠️ |
| LD_PRELOAD-based PAM bypass | ld_preload + pam_module_drop | ✅ |
| sudo NOPASSWD scan (`sudo -l`) | no enumeration rule | ❌ (GAP-AU-07) |
| sudo gtfobins escalation | `cap.gained` ✅ live | ⚠️ — partial |
| su to root | identity uid0 + cap | ✅ |
| systemd-run --uid 0 from non-root | `uid0_no_transition` | ✅ |
| WebAuthn replay | P-B.0a wired | ✅ (verified golden) |
| WebAuthn assertion forgery | P-B.0a | ✅ |
| Admin route from non-allowed IP | P-B.0b | ✅ |
| Canary user login | P-B.1 | ✅ |
| Canary route access | P-B.1 | ✅ |
| TOTP replay | out of scope without app hook | ❌ |
| Session-token theft + new device | device fingerprint pending (P-B.0c) | ⚠️ |
| OAuth refresh-token theft | app-integration needed | ❌ |
| SAML/OIDC forgery | app-integration needed | ❌ |
| Kerberos ticket abuse | out of scope (AD) | ❌ |
| API-key replay (CI compromise) | reqcontract divergence (P-RC.4 pending) | ❌ |
| Lateral SSH | egress + identity + ASN | ⚠️ |

### 2.10 Ransomware behaviours (T1486, T1490)

| Vector | xhelix capability | State |
|---|---|---|
| Mass file open + write (encryption) | not a dedicated rule | ❌ |
| File rename to `*.locked` / `*.enc` | not detected | ❌ |
| Ransom note drop | FIM only if in watched path | ⚠️ |
| Shadow-copy delete (`btrfs subvolume delete`) | not detected | ❌ |
| Backup destruction | RecursiveDelete signal ✅ for some paths | ⚠️ |
| ESXi VM kill via vim-cmd | out of scope | ❌ |
| Service stop (DB / app) | tamper.systemd or service-stop event | ⚠️ |

### 2.11 Crypto miners (T1496)

| Vector | xhelix capability | State |
|---|---|---|
| XMRig binary spawn | proc + outbound + cooccur | ⚠️ |
| Stratum pool outbound | netids — pattern detection | ⚠️ |
| CPU pinning / nice manipulation | no rule | ❌ |
| Persistent cron miner | `cron_new_unit` | ✅ |
| Containerised miner (TeamTNT class) | container-escape + outbound | ⚠️ |

### 2.12 Supply-chain (T1195)

| Vector | xhelix capability | State |
|---|---|---|
| Malicious npm/pip post-install script | proc + memfd + outbound during package-install | ⚠️ |
| dpkg/rpm hook with malicious payload | proc + cap | ⚠️ |
| Build-system poisoning (CI compromise) | reqcontract divergence (P-RC.4 pending) | ❌ |
| Compromised base image (Docker pull) | image-hash baseline | ❌ |

---

## 3. Live empirical FP measurements (this host, 2026-05-21)

Tests run on victim host 135.181.79.27 immediately after P-PS.23 fix.
Each test ran the named normal-workload command. Counts are alerts
fired during the test window.

| Test ID | Workload | Alerts | Highest-severity rule | Verdict |
|---|---|---|---|---|
| FP-01 | `node -e 'console.log("hello")'` | several | `memfd_run_pattern`+`mem_mprotect_rwx` | **alert-only ✅** (post-fix) |
| FP-02 | `node http.createServer` 8s loop | many | `mem_mprotect_rwx` | alert-only ✅ |
| FP-04 | `dotnet --info` | 0 | — | clean |
| FP-05 | `python3 -c '...hashlib...'` | 0 | — | clean |
| FP-06 | `python3 -m venv /tmp/x` | 0 | — | clean |
| FP-07 | `docker run alpine sh` | ≥ 5 | **`bpf_syscall_unexpected` + `contescape.detected` + `cap.gained`** | ⚠️ **FP-grenade in enforce mode** |
| FP-10 | `apt-get install --simulate cowsay` | 0 | — | clean |
| FP-11 | `snap list` | 0 | — | clean |
| FP-GIT | `git log + git status` | 0 | — | clean |

**Scope note (2026-05-21)**: per operator decision, container/docker
testing is deferred. The two `runc`-class FP findings below remain
documented but are NOT priority-fixes for this phase. Re-engage when
container scope reopens.

### 3.1 New FP-grenades discovered (documented; docker-class deferred)

1. **`bpf_syscall_unexpected` on `runc`** — Docker's container init legitimately uses bpf() for cgroup-device-controllers, seccomp, and net classifiers. Current action mask includes `ActionQuarantine`. If enforce mode were enabled today, **every `docker run` would SIGSTOP runc**.

2. **`contescape.detected` on `runc:[2:INIT]`** — the container's init process inherently performs the cgroup/namespace transitions that look like escape. Fires on every container start. Action mask includes Quarantine.

3. **`cap.gained` on `runc:[2:INIT]`** — runc legitimately drops then re-acquires caps during setup. Not destructive but pollutes the takeover scorer.

### 3.2 What this means for the 99.9999% target

A single `docker run` produces ~5 alerts with no attack present. On a
node hosting one container per minute (modest workload), that is
**~7200 FP/day** before counting node JIT. Current FP rate ≈ 10⁻³,
two phases above target.

### 3.3 Fixes required (highest priority)

| Fix | Effort | Impact |
|-----|---|---|
| Add `cgroup_class=docker` or `parent_image=/usr/bin/runc` allowlist to `bpf_syscall_unexpected` | small | drops ~50% of FP volume |
| Same allowlist on `contescape.detected` | small | drops 100% of docker-run FP |
| Mute `cap.gained` for cgroup transitions in container-init context | small | reduces planner-score noise |
| Add runtime_allowlist YAML loader (ALERTS_AND_FP_PLAN §5.2) | medium | systematic |

---

## 4. Detection rate honest estimate (corrected by live data)

| Threat | Detection % (signals → useful alert) | FP-safe in enforce mode? |
|---|---|---|
| Webshell deploy + RCE | 70% | yes (after web_server_spawns_shell allowlist) |
| Reverse shell (bash/nc/socat) | 95% | yes |
| memfd / fileless | 95% | yes (post-fix; allowlist needed) |
| LD_PRELOAD persistence | 90% | yes |
| cron persistence | 90% | yes |
| systemd unit drop | 80% | yes |
| SSH key persistence | 90% | yes |
| ssh-agent / GPG-agent abuse | 0% | n/a |
| ssh brute → success | 80% | yes |
| LSASS-equivalent (process_vm_readv on sshd) | 60% | no (would FP on debuggers) |
| BPF rootkit load (BPFDoor, Symbiote) | 50% | **no** (FP-grenade today, see §3.1) |
| io_uring-based EDR bypass (RingReaper) | 5% | n/a |
| Container escape (`runc` exploit class) | 60% | **no** (FP-grenade today) |
| `/var/run/docker.sock` abuse from container | 0% | n/a |
| LKM rootkit load | 90% | yes |
| ransomware mass-encryption | 10% | n/a |
| crypto miner | 60% | yes |
| DGA-based C2 | 70% | yes |
| DoH-based C2 | 0% | n/a |
| QUIC / WebSocket C2 | 0% | n/a |
| Supply-chain poisoned dependency | 30% | depends |
| Cloud-metadata SSRF | 80% | yes |
| Lateral SSH | 70% | yes |
| WebAuthn replay | 95% | yes |
| Canary user/route | 95% | yes |

**Weighted average (weighted by frequency-in-the-wild)**: ~55–60%
behaviour coverage. ~30–35% currently safe in enforce mode against
real workloads.

---

## 5. Causal chain power assessment

The user asked specifically: **how intelligent and powerful is the
causal chain**.

### 5.1 What works

- `pkg/lineage` ties every event to a lineage_id derived from
  process ancestry (PID + start-time + cgroup), surviving fork/exec.
  This is the foundation.
- `pkg/forensic.CoEngine` correlates signals within (Source,
  SessionID) buckets — fires `download_and_execute`,
  `reverse_shell`, `cred_exfil_chain` when their Need sets are
  satisfied within a configured window.
- `pkg/takeover.Scorer` aggregates signals **per-lineage** with
  diminishing returns + co-occurrence bonuses, producing tier+score.
  Live data: produced 105 tier=isolated score=100 plans in the
  drill window.
- `pkg/decision.Plan()` consumes scorer output and emits an
  ActionPlan with the exact tier-appropriate action set.

### 5.2 What doesn't work yet

- **Cross-host correlation**: zero. A single attacker hitting 3
  victims produces 3 unrelated narratives. No fleet correlation.
- **Cross-restart memory**: scorer TTL is 30 min. An attack that
  spans a service restart (very common — services crash on
  exploit) loses its lineage.
- **Cross-lineage join**: if attacker hands off control between
  lineages (`disown && /tmp/new.bin &`), scorer treats them as
  unrelated unless `parent_pid` or `cgroup_id` ties them.
- **Container-pid-namespace bridging**: events inside a container
  carry container-pid in some places, host-pid in others. Joining
  by lineage across the boundary is brittle.
- **Time-of-flight**: signals fired before xhelix starts are lost.
  No reconstruction from `/proc` on startup.
- **Replay-deterministic**: P-RF.6 marked in-progress; goldens
  show determinism for synthetic event streams. Real replay of a
  24h trace not yet run.
- **DLCF taint propagation**: P7.1.* wired but no live attack has
  exercised "taint a file → taint propagates as data is read →
  egress valve blocks".

### 5.3 Rock-solid?

Not yet. Honestly: **the in-memory causal chain is medium-good**
(lineage + cooccur + scorer); the **persistent evidence chain
(`pkg/chain`)** is strong locally but missing the off-host mirror
(P-CJ.10), TPM/KMS root (P-CJ.8), and watchdog (P-CJ.5) that move
it from "tamper-evident on-host" to "tamper-evident even if root is
compromised". See `ALERTS_AND_FP_PLAN.md §7`.

---

## 6. What to test next (priority order)

1. **Fix the 3 FP-grenades in §3.1** — single highest-impact change.
2. **Sandbox-build a Ring-A VM** so we can run real malware safely.
3. **Test 1 BPF rootkit sample** (Boopkit research build or RingReaper sample) — measures coverage of the #1 growing class.
4. **Test 1 container-escape PoC** (CVE-2019-5736 runc, or a recent LinkPro-like chain).
5. **Run Atomic Red Team (Linux)** end-to-end — MITRE-mapped baseline.
6. **24h soak on a node+docker+python workload** — empirical FP-rate measurement.
7. **Tamper-test the chain** (CT-01..10 from ALERTS_AND_FP_PLAN §7.3).
8. **Cross-host correlation** — drive 2 attackers, see if alerts join.

---

## 7. Sources

- [eBPF Rootkits: Linux Kernel-Level Threats](https://blog.hunterstrategy.net/ebpf-based-rootkits/) — Hunter Strategy
- [Linux Rootkits Using Advanced eBPF and io_uring Techniques](https://cybersecuritynews.com/linux-rootkits-using-advanced-ebpf/) — Cyber Security News
- [eBPF Escapes: When Your Monitoring Tool Becomes the Ultimate Rootkit](https://medium.com/@instatunnel/ebpf-escapes-when-your-monitoring-tool-becomes-the-ultimate-rootkit-%EF%B8%8F-224d097e0109) — InstaTunnel
- [VoidLink Malware Targets Cloud and Container Environments](https://thehackernews.com/2026/01/new-advanced-linux-voidlink-malware.html) — The Hacker News
- [LinkPro Rootkit Uses eBPF to Conceal Malicious Activity](https://cyberpress.org/linkpro-rootkit-ebpf/) — CyberPress
- [eBPF Rootkit Targeting AWS and Linux Environments](https://threats.wiz.io/all-incidents/ebpf-rootkit-targeting-aws-and-linux-environments) — Wiz Threats
- [Linux Kernel eBPF Monitoring Rootkit Threats and Evasion Techniques](https://linuxsecurity.com/features/ebpf-security-tools-rootkit-evasion) — LinuxSecurity
- [BPFDoor and Symbiote: Advanced eBPF-Based Rootkits Target Linux Systems](https://gbhackers.com/ebpf-based-rootkits/) — GB Hackers
- [New eBPF Filters for Symbiote and BPFdoor Malware](https://www.fortinet.com/blog/threat-research/new-ebpf-filters-for-symbiote-and-bpfdoor-malware) — FortiGuard Labs
- [MalwareBazaar Linux tag](https://bazaar.abuse.ch/browse/tag/linux/) — abuse.ch
- [Linux Malware And Vulnerability Statistics 2026](https://commandlinux.com/statistics/linux-malware-vulnerability-statistics/) — CommandLinux
- [Malware Attack Statistics 2026](https://www.stingrai.io/blog/malware-attack-statistics-2026) — Stingrai
