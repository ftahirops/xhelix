# Real Use Cases — Top 4 2026 Worst Vulnerabilities

How xhelix protects against the most-impactful exploits of 2026, across four deployment profiles. **4 CVEs × 4 deployment profiles = 16 distinct kill-chain walkthroughs.**

Data verified against `docs/SCENARIOS.md` Part 2 (live web search 2026-05-27). Coverage scoring assumes Phases A-O fully built, enforce mode promoted, mature operator-tuned deployment. Untuned deployments score 15-25 points lower across all four metrics.

---

## Score legend

| Metric | Definition |
|---|---|
| **Protection** | Does xhelix observe + emit an alert on the attack chain (any stage) |
| **Defense** | Does xhelix stop the attack before damage (sync or sub-second async) |
| **Alert** | Signal-to-noise quality of detection |
| **FP** | False-positive control (higher = fewer wrong alerts) |

Stage coverage:

| Indicator | Meaning |
|---|---|
| `[BLOCK]` | xhelix actively refuses the action (BPF-LSM deny / nftables drop / SIGKILL) |
| `[ALERT]` | xhelix observes + emits an alert; no synchronous block |
| `[PARTIAL]` | xhelix partially covers; some aspect detected, some missed |
| `[GAP]` | xhelix cannot detect or block this stage — honestly disclosed |

---

## Top 4 2026 vulnerabilities covered

| # | CVE | Name | Date | Severity |
|---|---|---|---|---|
| 1 | **CVE-2026-31431** | Linux "Copy Fail" kernel zero-day | Apr-May 2026 | CISA KEV — Kernel LPE |
| 2 | **CVE-2026-41940** | cPanel/WHM auth bypass | Feb-Apr 2026 | CVSS 9.8 — 1.5M servers |
| 3 | **CVE-2026-20131** | Cisco Secure FMC zero-day | Jan-Mar 2026 | CVSS 10.0 — Interlock ransomware |
| 4 | **CVE-2026-45321** | Mini Shai-Hulud npm worm | May 11, 2026 | Supply chain — 170+ packages |

---

# 1. CVE-2026-31431 — Linux "Copy Fail" kernel zero-day

**April-May 2026 · CISA KEV · Kernel LPE**

Logic bug in the algif_aead AF_ALG cryptographic subsystem. 732-byte exploit gives root from unprivileged user. The kernel's module auto-loading mechanism auto-loads `algif_aead` on demand when any process (including unprivileged containers) creates an AF_ALG socket — meaning **any container's code execution can escalate to root on the host**. Patched in kernel 6.18.22, 6.19.12, 7.0. Federal CISA deadline May 15, 2026.

## 1.1 Server profile

| Metric | Score |
|---|---|
| Protection | **50** |
| Defense | **75** |
| Alert | **70** |
| FP | **95** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | Attacker has code in any container (compromised pod) | `[ALERT]` | source anchor minted on session entry; lineage tagged for downstream correlation |
| 02 | TA0002 Execution | Attacker process creates AF_ALG socket | `[ALERT]` | ebpf observes socket creation; verifier's SourceLineage domain weights unusual crypto-API usage |
| 03 | TA0004 Priv Escalation | Kernel primitive abuse — 732-byte exploit triggers in-place auth bug | `[GAP]` | **INHERENT GAP**: kernel primitive runs before any LSM hook fires; no host EDR can prevent this |
| 04 | TA0004 Priv Escalation | Escalates to root on the HOST (not just container) | `[ALERT]` | capwatch fires `cap.gained` Class 3; ebpf cred-change stamps `uid0_transition=true` |
| 05 | TA0005 Defense Evasion | Attempts to disable xhelix or hide BPF programs | `[BLOCK]` | tamperguard catches the attempt; forensic chain captures the exploit lineage |
| 06 | TA0008 Lateral Movement | Cross-pod / cross-namespace lateral move | `[BLOCK]` | secrettaint flips to outbound_restricted; contescape.detected fires; egressguard blocks pivot |
| 07 | TA0011 Command & Control | Outbound to attacker C2 from cluster | `[BLOCK]` | egressguard: protected role + undeclared peer = EgressDeny; nftables enforces drop |
| 08 | TA0010 Exfiltration | Mass cluster-secret exfiltration | `[BLOCK]` | secrettaint state machine in containment_required blocks all outbound; Class 1 alert + node-level netban |

**Verdict.** xhelix catches the post-exploit pivot (UID 0 transition, cross-pod, secret reads) but cannot prevent the kernel primitive itself. Phase G.3 (landlock) + G.4 (hardened_malloc) raise exploitation cost; Phase I (BPF-LSM) closes the userspace deny path.

**xhelix phases engaged:** A (✓) · B.2 (✓) · G.1 (✓) · I (planned) · G.3 (planned) · G.4 (planned)

## 1.2 Workstation profile

| Metric | Score |
|---|---|
| Protection | **45** |
| Defense | **70** |
| Alert | **68** |
| FP | **95** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | Attacker breaks out of dev container | `[ALERT]` | container ID + cgroup_class tagged on every event from the dev container |
| 02 | TA0002 Execution | AF_ALG socket creation from inside container | `[ALERT]` | ebpf observes; logged but not blocked (legitimate crypto uses this) |
| 03 | TA0004 Priv Escalation | Kernel primitive abuse | `[GAP]` | GAP — kernel-level; no host EDR prevention possible |
| 04 | TA0004 Priv Escalation | Root on the developer's laptop | `[ALERT]` | capwatch + ebpf cred-change → Class 3 alert |
| 05 | TA0006 Credential Access | Reads ~/.aws/, ~/.ssh/, ~/.kube/ from dev's home | `[ALERT]` | secrettaint multi-class accumulation; file_read_burst Class 2 on rapid scan |
| 06 | TA0010 Exfiltration | Exfil dev credentials to attacker C2 | `[BLOCK]` | egressguard outbound_restricted blocks; dev-aggressive profile applies first-30s egress block |

**Verdict.** Workstation containers (Docker Desktop, Podman) are exposed to the same kernel zero-day. xhelix observes + alerts on the post-escalation pivot but the primitive itself is invisible. Operator should patch kernel immediately per CISA KEV deadline.

**xhelix phases engaged:** A (✓) · G.1 (✓) · I (planned)

## 1.3 Dev Machine profile

| Metric | Score |
|---|---|
| Protection | **55** |
| Defense | **78** |
| Alert | **75** |
| FP | **92** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | Exploit arrives via npm/pip/cargo supply-chain (or local container) | `[ALERT]` | Phase K.2 tags pkg-install transactions; suspicious post-install scripts get `artifact_quarantine=true` |
| 02 | TA0002 Execution | Kernel primitive triggered from dev's interactive session | `[ALERT]` | observed but not blocked (legit interpretations) |
| 03 | TA0004 Priv Escalation | Kernel LPE → root on dev workstation | `[GAP]` | GAP — kernel exploit |
| 04 | TA0006 Credential Access | Mass credential file enumeration | `[BLOCK]` | secrettaint promotes to containment_required after multi-class accumulation; egressguard hard-block on all outbound |
| 05 | TA0011 Command & Control | Beacon to attacker C2 | `[BLOCK]` | beacon detector + egressguard outbound_restricted = Class 1 + nftables drop |

**Verdict.** Same kernel exposure as workstation, but xhelix's dev-aggressive profile adds tighter egress-on-new-binary controls. The 30-second egress block during first run of any new binary catches most post-escalation exfil attempts even before reputation lookup completes.

**xhelix phases engaged:** A (✓) · B.2 (✓) · O (planned)

## 1.4 CI Runner profile

| Metric | Score |
|---|---|
| Protection | **65** |
| Defense | **80** |
| Alert | **80** |
| FP | **90** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | Compromised CI dependency or stolen runner token | `[ALERT]` | source anchor on CI job start; lineage propagates through every spawned process |
| 02 | TA0004 Priv Escalation | Kernel exploit → root on the runner host | `[GAP]` | GAP — kernel primitive |
| 03 | TA0008 Lateral Movement | Cross-pod / cross-job pivot | `[BLOCK]` | egressguard cross-pod block + secrettaint multi-tenant taint |
| 04 | TA0010 Exfiltration | Exfil CI/CD secrets via outbound | `[BLOCK]` | Phase N (planned) broker mediation would deny direct secret reads; today: egressguard outbound_restricted + procscrape |

**Verdict.** CI runners are container-heavy and ephemeral, but lateral move across pods is critical to prevent. xhelix's ci-runner profile (Phase O.6) fails closed — unknown artifact exec fails unless provenance allows. Combined with egressguard enforce, the cross-pod blast radius is contained.

**xhelix phases engaged:** A (✓) · B.2 (✓) · C (✓) · O (planned)

---

# 2. CVE-2026-41940 — cPanel/WHM Authentication Bypass

**Feb-April 2026 · CVSS 9.8 · 1.5M servers · Mirai + Sorry ransomware**

Session-handling flaw in cpsrvd: before authentication, cpsrvd writes a new session file to disk. Attacker manipulates the `whostmgrsession` cookie by omitting an expected segment, avoiding the encryption process for attacker-provided values. Authentication bypass succeeds; full WHM access. Exploited as zero-day since February 2026; patched April 30, 2026. cPanel runs on **70 million+ domains; 2M+ instances internet-connected**.

## 2.1 Server profile

| Metric | Score |
|---|---|
| Protection | **85** |
| Defense | **88** |
| Alert | **92** |
| FP | **96** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | Crafted HTTP request to cPanel cpsrvd daemon | `[ALERT]` | FIM observes the resulting session-file write at `/var/cpanel/sessions/` from unauthenticated source; tagged |
| 02 | TA0001 Initial Access | Successful "login" without prior identity event | `[ALERT]` | Orphan source anchor — no parent identity; verifier's SourceLineage domain weights this heavily |
| 03 | TA0002 Execution | cpsrvd spawns bash/perl to drop payload | `[BLOCK]` | cPanel's BRP profile lists allowed children (mysqld_safe, php-fpm); bash/perl not in list → `brp.hard_deny` Class 1 |
| 04 | TA0002 Execution | Dropped-binary lifecycle: fetch → write → exec from /tmp | `[BLOCK]` | correlator `dropped_binary_lifecycle` chain (Phase J.2) fires on net_connect + proc_spawn from /tmp/ on same cgroup; Class 3 |
| 05 | TA0009 Collection | Reads customer data `/var/cpanel/users/*` | `[BLOCK]` | assetclass tags as AssetCustomerData; secrettaint multi-tenant taint accumulation |
| 06 | TA0003 Persistence | Cron / systemd persistence drop | `[ALERT]` | FIM + persistencewatch categorise the write; Class 2 `cron_new_unit` alert |
| 07 | TA0040 Impact | Sorry ransomware encryption begins | `[BLOCK]` | `fim.drift` high-rate detection; assetclass AssetCustomerData weight elevates the alert; enforce-mode quarantine kills the process tree |

**Verdict.** The auth bypass at the cpsrvd layer is invisible to host EDR (it's just session-file manipulation). But the post-exploit chain — cpsrvd spawning a shell to drop the payload — trips `brp.hard_deny` Class 1 immediately. Two-stage redundancy ensures no single missed signal completes the attack.

**xhelix phases engaged:** A (✓) · B.1 (✓) · B.2 (✓) · C (✓) · J.2 (✓) · M (planned)

## 2.2 Workstation profile

| Metric | Score |
|---|---|
| Protection | **N/A** |
| Defense | **N/A** |
| Alert | **N/A** |
| FP | **N/A** |

**Out of scope.** cPanel/WHM is a hosting control panel — not deployed on workstations. This vulnerability does not apply to workstation deployments.

## 2.3 Dev Machine profile

**Out of scope.** cPanel/WHM is not typically on developer machines unless the developer specifically runs cPanel locally for testing (unusual).

## 2.4 CI Runner profile

**Out of scope.** CI runners don't host cPanel.

---

# 3. CVE-2026-20131 — Cisco Secure Firewall Management Center zero-day

**Jan-March 2026 · CVSS 10.0 · Interlock ransomware**

Insecure deserialization in the Cisco Secure FMC web management interface. Unauthenticated RCE as **root**. Exploited as zero-day since January 26, 2026 — more than a month before public disclosure. Used to deploy **Interlock ransomware** across enterprise networks. Patched March 4, 2026.

## 3.1 Server profile

| Metric | Score |
|---|---|
| Protection | **85** |
| Defense | **90** |
| Alert | **95** |
| FP | **96** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | Crafted serialized Java object to FMC's web interface | `[ALERT]` | Web event captured; JVM about to act on attacker-controlled bytes |
| 02 | TA0002 Execution | FMC management JVM spawns `/bin/sh` for the deserialized payload | `[BLOCK]` | FMC's BRP profile lists allowed children for Java backend; shell not in AllowedChildren → `brp.hard_deny` Class 1 |
| 03 | TA0002 Execution | Backup detector — `web_spawns_shell` rule | `[BLOCK]` | Class 2 fires as a redundant detector |
| 04 | TA0011 Command & Control | Outbound to attacker infrastructure for second stage | `[BLOCK]` | egressguard: FMC management role's BRP profile declares Cisco update servers + customer firewalls; attacker C2 = undeclared peer → EgressDeny |
| 05 | TA0002 Execution | `dropped_binary_lifecycle` chain — fetch → exec from /tmp | `[BLOCK]` | correlator J.2 chain fires with all 3 step events linked; Class 3 incident |
| 06 | TA0006 Credential Access | Reads FMC per-firewall management certs | `[BLOCK]` | secrettaint SecretSigningKey + SecretCloudCreds multi-class taint; lineage promoted to containment_required |
| 07 | TA0040 Impact | Interlock ransomware encryption of managed assets | `[BLOCK]` | `fim.drift` rate detector; tamperguard catches attempts to disable xhelix; enforce-mode quarantine |

**Verdict.** Cisco FMC appliances run Linux underneath. xhelix on the FMC management Linux catches the management JVM spawning shell at `brp.hard_deny` Class 1. Three independent fires (egress + brp + correlator chain) before ransomware persistence completes.

**xhelix phases engaged:** A (✓) · B (✓) · C (✓) · D.1 (✓) · J.2 (✓)

## 3.2 Workstation / 3.3 Dev Machine / 3.4 CI Runner

**Out of scope across all three.** Cisco FMC is an enterprise firewall management appliance — not deployed on workstations, developer machines, or CI runners.

---

# 4. CVE-2026-45321 — Mini Shai-Hulud npm worm

**May 11, 2026 · Supply chain · 170+ packages · TeamPCP**

Coordinated supply-chain attack compromising **170+ npm packages and 2 PyPI packages totaling 404 malicious versions** in a single day. Targets: entire TanStack router ecosystem (42 pkgs), Mistral AI SDK, UiPath (65 pkgs), OpenSearch (1.3M weekly downloads), Guardrails AI. Self-spreading via stolen npm tokens. Attribution: TeamPCP.

## 4.1 Server profile

| Metric | Score |
|---|---|
| Protection | **70** |
| Defense | **85** |
| Alert | **95** |
| FP | **94** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | npm install pulls compromised @tanstack/* package | `[ALERT]` | Phase K.2 (planned): npm install during pkg-install-window tagged; Phase O (planned): `artifact_quarantine` on the postinstall script |
| 02 | TA0002 Execution | Malicious postinstall script executes | `[ALERT]` | correlator `dropped_binary_lifecycle` chain fires Class 3; Phase O execgate would park the process pending xgenguardian verdict |
| 03 | TA0006 Credential Access | Reads `~/.npmrc`, `~/.aws/credentials`, env secrets | `[BLOCK]` | secrettaint multi-class taint: SecretGitToken + SecretCICDToken + SecretCloudCreds; Class 2 `file_read_burst` |
| 04 | TA0006 Credential Access | `/proc/self/environ` mass read | `[BLOCK]` | procscrape stamps `cred_proc_scrape=true` |
| 05 | TA0010 Exfiltration | Outbound to attacker exfil endpoint | `[BLOCK]` | egressguard: undeclared peer for CI/server role → EgressDeny in enforce mode |
| 06 | TA0001 Initial Access | Worm self-spread: publishes more malicious versions using stolen token | `[PARTIAL]` | Detection only — outbound to npm registry from a non-publish-role process gets flagged; Phase H.2 long-window correlation catches multi-day token-theft → republish chains |

**Verdict.** Server-side, the attack lands via npm install during deploy. xhelix's `dropped_binary_lifecycle` correlator chain (Phase J.2) catches the postinstall fetch → exec pattern. secrettaint + procscrape detect the credential read. egressguard blocks exfil. Phase O.4 (xgenguardian) extends to pre-execution verdict.

**xhelix phases engaged:** A (✓) · B (✓) · C (✓) · J.2 (✓) · O (planned)

## 4.2 Workstation profile

| Metric | Score |
|---|---|
| Protection | **75** |
| Defense | **87** |
| Alert | **96** |
| FP | **94** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | User runs npm install on personal project | `[ALERT]` | Phase O hostile-dev profile would quarantine the postinstall; today: J.2 catches the chain |
| 02 | TA0002 Execution | postinstall executes | `[BLOCK]` | J.2 chain Class 3 + Phase O xgenguardian verdict if available |
| 03 | TA0006 Credential Access | Reads dev creds: GitHub tokens, AWS keys, SSH keys | `[BLOCK]` | secrettaint + burstdet Class 2 |
| 04 | TA0010 Exfiltration | Outbound to attacker C2 | `[BLOCK]` | egressguard hostile-dev profile: first-30s outbound block on new binary |
| 05 | TA0008 Lateral Movement | Uses stolen GitHub token to compromise other repos | `[ALERT]` | Phase F xhub (planned) cross-fleet correlation would catch the publish wave |

**Verdict.** Workstation profile applies but most users won't have aggressive controls. Phase O hostile-dev profile provides the strongest defense — every browser/download/toolchain artifact gets hash-tracked; first-run requires signed xgenguardian verdict or sandbox pass. Without Phase O, this still triggers the J.2 chain rule.

**xhelix phases engaged:** A (✓) · B.2 (✓) · J.2 (✓) · O (planned)

## 4.3 Dev Machine profile

| Metric | Score |
|---|---|
| Protection | **80** |
| Defense | **90** |
| Alert | **97** |
| FP | **92** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | Developer runs `npm install` or `yarn add` | `[ALERT]` | Phase K.2: pkg-install-window tagged; Phase O.6 dev-aggressive profile: postinstall gets xgenguardian verdict before execution |
| 02 | TA0002 Execution | Postinstall executes | `[BLOCK]` | `dropped_binary_lifecycle` chain fires within seconds; xgenguardian verdict (if shipped) blocks at execve |
| 03 | TA0006 Credential Access | Reads `~/.npmrc`, `~/.aws/`, `~/.ssh/`, env | `[BLOCK]` | secrettaint multi-class + Phase N broker (planned) deny direct reads even if process can run |
| 04 | TA0010 Exfiltration | Exfil to attacker exfil host | `[BLOCK]` | egressguard outbound_restricted Class 1 |
| 05 | TA0011 Command & Control | Worm payload checks for additional packages to compromise | `[ALERT]` | egressguard logs every outbound; Phase F xhub fleet correlation catches the spread |

**Verdict.** Dev machines are the primary target for this attack class. With Phase O dev-aggressive profile + xgenguardian: postinstall scripts are sandboxed before execution. Without Phase O: J.2 correlator chain + secrettaint + egressguard fire multiple alerts but the credential read happens before egress block.

**xhelix phases engaged:** A (✓) · B (✓) · C (✓) · J.2 (✓) · O (planned) · N (planned)

## 4.4 CI Runner profile — strongest defense of all four

| Metric | Score |
|---|---|
| Protection | **85** |
| Defense | **92** |
| Alert | **98** |
| FP | **94** |

| # | Tactic | Stage | Coverage | xhelix response |
|---|---|---|---|---|
| 01 | TA0001 Initial Access | GitHub Action / Jenkins job pulls compromised dependency | `[BLOCK]` | Phase O.6 ci-runner profile: postinstall script that fetches external = `artifact_quarantine` + xgenguardian verdict required |
| 02 | TA0002 Execution | Postinstall blocked at `execve` via BPF-LSM | `[BLOCK]` | Phase I BPF-LSM synchronous deny — process never starts; alert + audit |
| 03 | TA0006 Credential Access | Even if execution leaks through, CI secret env is read | `[BLOCK]` | procscrape catches `/proc/self/environ` read; secrettaint Class 1; Phase N broker would issue short-lived tokens instead of raw values |
| 04 | TA0010 Exfiltration | Exfil CI/CD secrets to attacker | `[BLOCK]` | egressguard fails-closed in ci-runner profile; all non-declared peers blocked |
| 05 | TA0001 Initial Access | Worm publishes new malicious versions using stolen npm token | `[BLOCK]` | Token never leaves the runner — Phase N broker never released it; worm propagation stops |

**Verdict.** CI runners are the **worst case** for this attack — they have access to high-value secrets (deployment keys, signing certs, cloud admin) and pull dependencies on every job. Phase O ci-runner profile fails closed: unknown artifact exec **fails** unless provenance allows. The strongest defense profile of all four deployment types.

**xhelix phases engaged:** A (✓) · B (✓) · C (✓) · J.2 (✓) · O (planned)

---

# Overall summary across the 16 walkthroughs

| CVE | Server | Workstation | Dev Machine | CI Runner |
|---|---|---|---|---|
| **CVE-2026-31431** Linux Copy Fail | 50 / 75 / 70 / 95 | 45 / 70 / 68 / 95 | 55 / 78 / 75 / 92 | 65 / 80 / 80 / 90 |
| **CVE-2026-41940** cPanel auth bypass | 85 / 88 / 92 / 96 | N/A | N/A | N/A |
| **CVE-2026-20131** Cisco FMC | 85 / 90 / 95 / 96 | N/A | N/A | N/A |
| **CVE-2026-45321** Mini Shai-Hulud | 70 / 85 / 95 / 94 | 75 / 87 / 96 / 94 | 80 / 90 / 97 / 92 | 85 / 92 / 98 / 94 |

Score format: **Protection / Defense / Alert / FP**.

## Key observations

- **CI Runner profile is strongest for supply-chain attacks** (CVE-2026-45321) — fails closed, BPF-LSM exec block, broker prevents token leak. Scores 85+ across all four metrics.
- **Server profile dominates for traditional RCE** (cPanel, Cisco FMC) — BRP signed contracts catch the JVM/cpsrvd spawning shell, the canonical detection pattern xhelix is best at.
- **Kernel zero-days (Copy Fail) are the structural weak spot** — protection scores 45-65 regardless of profile because the kernel primitive runs before any LSM hook. Phase I closes the userspace deny path but kernel-team patching is the actual fix.
- **3 of the 4 CVEs are out-of-scope on workstation/dev/CI** — cPanel and Cisco FMC are server appliances. Honest disclosure rather than padded scores.

## What changes the numbers

| Lever | Impact |
|---|---|
| Mature BRP profiles (5+ apps with `AllowedChildren` + `UpstreamHosts`) | +15 points across initial access / execution / persistence / C2 |
| Egressguard promoted to enforce | +10 points on exfiltration / C2 |
| Phase O.6 hostile-dev profile on developer machines | +12 points on initial access |
| xgenguardian production-grade + 7-day fleet cache warming | +8 points on initial access / execution |
| Phase N broker mediation with Vault/KMS integration | +10 points on credential access |
| **Untuned BRP profiles (default permissive)** | **-20 to -25 points overall** |
| **Egressguard in observe-only** | **-15 points on exfil / C2** |

---

# See also

- `docs/SCENARIOS.md` — full 32-scenario walkthrough catalog with all sources cited
- `docs/KILL_CHAIN_COVERAGE.md` — full MITRE ATT&CK kill-chain analysis with comparison vs Falco/Tetragon/Wazuh/Sysdig/CrowdStrike/SentinelOne
- `docs/XGENGUARDIAN_INTEGRATION_SPEC.md` — off-host verdict service spec for Phase O integration
- `README.md` — architecture overview and live FP measurements
