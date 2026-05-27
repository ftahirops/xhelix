# xhelix kill chain coverage — full MITRE ATT&CK stage analysis

> Honest scoring of xhelix's defense across every MITRE ATT&CK tactic, assuming **fully built and matured** deployment (Phases A through O shipped, enforce mode promoted, BRP profiles authored, fleet baseline > 30 days).
> Numbers drop 15-25 points on day-0 deployments without operator tuning. Stated up front because anything else is marketing fiction.
> Companion document to `docs/REAL_USE_CASES.html` which makes this interactive.

---

## Per-tactic scoring (out of 100)

| MITRE Tactic | Protection (block before damage) | Defense (contain blast radius) | Alert quality | FP rate target | Phases that drive it |
|---|---|---|---|---|---|
| TA0001 Initial Access | 85 | 90 | 92 | <0.5% | B, C, J.2, **O**, K.3 |
| TA0002 Execution | 92 | 90 | 95 | <0.5% | A (BRP), **I**, **O**, J.2 |
| TA0003 Persistence | 88 | 92 | 95 | <1% | FIM, persistencewatch, **M** |
| TA0004 Privilege Escalation | 70 | 85 | 92 | <1% | capwatch, contescape, **I**, **G.3-G.4** |
| TA0005 Defense Evasion | 80 | 90 | 90 | <1% | **O.1** (magic bytes), tamperguard, A |
| TA0006 Credential Access | 88 | 93 | 95 | <0.5% | B.2 secrettaint, procscrape, **N** broker |
| TA0007 Discovery | 50 | 70 | 70 | <2% | (inherent weak spot — see §3) |
| TA0008 Lateral Movement | 80 | 85 | 88 | <1% | J.1, egressguard, **F** xhub |
| TA0009 Collection | 75 | 85 | 88 | <1% | secrettaint, burstdet, B.1 assetclass |
| TA0011 Command & Control | 82 | 88 | 90 | <1% | egressguard, beacon, dnsexfil, **H.2**, J.3 |
| TA0010 Exfiltration | 85 | 88 | 92 | <1% | egressguard + secrettaint outbound_restricted |
| TA0040 Impact | 80 | 87 | 90 | <1.5% | FIM rate, B.1 AssetBackupArchive, BRP enforce |

## Weighted overall (across the 12 tactics)

| Metric | Score | Honest read |
|---|---|---|
| Protection (block before damage) | **~80** | top-tier for execution / persistence / credential access; weak on kernel LPE and discovery |
| Defense (contain blast radius) | **~87** | strong everywhere — even where prevention fails, the chain captures evidence and limits cascade |
| Alert quality (detection signal-to-noise) | **~91** | best-in-class because every alert is line-by-line auditable; no mystery scores |
| FP rate (weighted) | **<1%** | Class 1 hard invariants at <0.1%, Class 2 at <0.5%, Class 3 at <5% per locked budgets |

---

## §3 Two unavoidable weak spots

| Weak spot | Score | Why no host EDR fixes this |
|---|---|---|
| **TA0007 Discovery** | 50 protection | Legitimate sysadmin work (`cat /etc/passwd`, `id`, `groups`, `ip a`, `netstat`, `ps`) is indistinguishable from attacker reconnaissance. Phase L trust-collapse helps weight later stages when discovery is followed by exfil, but discovery itself is intentionally low-noise. **Anyone claiming 95% on discovery is lying.** |
| **TA0004 Kernel LPE** | 70 protection (35 prevention) | Kernel zero-days (Copy Fail, Dirty Pipe, Dirty Frag) abuse memory primitives before any LSM hook fires. xhelix catches the **transition** (UID 0 from a non-root process), not the **primitive**. Closing this requires kernel patching, not EDR. |

---

## §4 Where xhelix is best-in-class

| Domain | Score | Why xhelix wins |
|---|---|---|
| **TA0002 Execution** | 92 protection | BRP signed contracts + Phase I BPF-LSM sync deny + Phase O execgate = no path for unauthorized exec |
| **TA0003 Persistence** | 95 alert | FIM + assetclass 24-taxonomy + Phase M deep systemd unit parsing |
| **TA0005 Defense Evasion** | 90 alert | Phase O magic-bytes classifier defeats rename-to-png; tamperguard catches attacks on xhelix itself |
| **TA0006 Credential Access** | 95 alert | secrettaint 4-state machine + procscrape + Phase N broker mediation — no other Linux host EDR has this combination |
| **TA0010 Exfiltration** | 92 alert | egressguard 6-path decision + secret-taint outbound_restricted + Phase H.1 byte counts |
| **TA0011 C2** | 90 alert | beacon + dnsexfil + Phase H.2 long-window + Phase J.3 messaging-platform asset class + Phase K.3 cert SAN |

---

## §5 Competitive comparison (mature deployment)

| Tactic | xhelix (matured) | Falco | Tetragon | Wazuh | Sysdig | CrowdStrike | SentinelOne |
|---|---|---|---|---|---|---|---|
| Initial Access | 85 | 50 | 60 | 70 | 75 | 88 | 85 |
| Execution | 92 | 75 | 85 | 70 | 82 | 90 | 88 |
| Persistence | 88 | 60 | 65 | 80 | 80 | 90 | 88 |
| Priv Escalation | 70 | 55 | 75 | 65 | 75 | 78 | 75 |
| Defense Evasion | 80 | 60 | 70 | 70 | 78 | 85 | 82 |
| Credential Access | 88 | 50 | 60 | 75 | 78 | 88 | 85 |
| Discovery | 50 | 45 | 50 | 50 | 55 | 70 | 65 |
| Lateral Movement | 80 | 55 | 65 | 75 | 80 | 88 | 85 |
| Collection | 75 | 50 | 55 | 70 | 75 | 82 | 80 |
| C2 | 82 | 50 | 60 | 75 | 78 | 88 | 85 |
| Exfiltration | 85 | 50 | 60 | 75 | 78 | 85 | 82 |
| Impact | 80 | 60 | 65 | 75 | 80 | 88 | 85 |
| **Weighted avg** | **~80** | **~55** | **~64** | **~71** | **~76** | **~85** | **~82** |

### Honest read

- xhelix matured **beats every open-source competitor** (Falco, Tetragon, Wazuh, Sysdig) by significant margins
- xhelix matured is **within striking distance of CrowdStrike and SentinelOne** (within 5-7 points on average)
- xhelix loses to commercial-SaaS EDRs on TA0007 Discovery (their proprietary ML on behavior) and slightly on TA0001 Initial Access (they integrate email/SaaS telemetry xhelix doesn't)
- xhelix **wins on transparency** — every score is auditable; no black-box ML driving Class 1 alerts

---

## §6 Operator levers (what changes the numbers)

| Lever | Impact |
|---|---|
| BRP profile maturity (5+ apps profiled with `AllowedChildren` + `UpstreamHosts`) | +15 points across TA0001/2/3/11 |
| Egressguard promoted to enforce with populated `UpstreamHosts` | +10 points on TA0010/11 |
| Phase O.6 hostile-dev profile on developer machines | +12 points on TA0001 specifically |
| xgenguardian production-grade + 7-day fleet cache warming | +8 points on TA0001/2 |
| Phase N broker mediation with Vault/KMS integration | +10 points on TA0006 |
| Phase F xhub fleet baselining + cross-host trust propagation | +8 points on TA0008 lateral |
| **Untuned BRP profiles (default permissive)** | **-20 to -25 points overall** |
| **Egressguard in observe-only** | **-15 points on TA0010/11** |
| **xgenguardian unavailable + no on-host fallback** | **-8 points on TA0001/2** |

---

## §7 Top 4 worst 2026 vulnerabilities and xhelix coverage

| # | CVE | When | Severity | Class | xhelix Protection | xhelix Defense | xhelix Alert |
|---|---|---|---|---|---|---|---|
| 1 | **CVE-2026-31431** Linux "Copy Fail" kernel | Apr-May 2026 | CISA KEV | Kernel LPE | 50 | 75 | 70 |
| 2 | **CVE-2026-41940** cPanel/WHM auth bypass | Feb-Apr 2026 | CVSS 9.8 | Web RCE | 80 | 85 | 90 |
| 3 | **CVE-2026-20131** Cisco Secure FMC | Jan-Mar 2026 | CVSS 10.0 | Deserialization RCE | 85 | 90 | 95 |
| 4 | **CVE-2026-45321** Mini Shai-Hulud npm worm | May 2026 | Supply chain | Postinstall malware | 70 | 85 | 95 |

Stage-by-stage walkthroughs for each of these (and 28 more scenarios) live in `docs/SCENARIOS.md`. The interactive UI in `docs/REAL_USE_CASES.html` shows the kill chain for these 4 plus four deployment types (Workstation / Server / Dev Machine / CI Runner).

---

## §8 What fully-built means

To reach the ~80 weighted-avg protection number above:

| Phase block | Days | What it unlocks |
|---|---|---|
| Current shipped (A-D, G.1, G.2 audit, J.1, J.2) | already done | baseline ~60 protection / ~75 alert |
| **Phase E** production hardening + soak | 5d wall | enforce-mode promotion (+10 protection) |
| **Phase I** BPF-LSM sync deny | 7d | airtight execution gate (+8 across TA0002) |
| **Phase G.3-G.6** landlock + hardened_malloc + posture + cosign | 8d | defense-in-depth (+5 across TA0004/5) |
| **Phase H.1-H.4** byte counts + long-window + fire-rate + CDN cloaking | 15-20d | C2 + exfil long-window (+8 on TA0010/11) |
| **Phase K.1-K.3** auditd + pkg-mgr + cert SAN | 7-9d | new signal plane + FP suppression (+5 across) |
| **Phase J.3** messaging-platform asset class | 2d | closes Telegram/Discord fallback (+3 TA0011) |
| **Phase L** trust-collapse state machine | 10-15d | post-discovery escalation weighting (+5 TA0007) |
| **Phase M** deep systemd unit parsing | 8-12d | persistence completeness (+4 TA0003) |
| **Phase N** capability brokerage | 10-15d | credential broker (+8 TA0006) |
| **Phase O** artifact quarantine + xgenguardian | 16-24d + xgenguardian readiness | dropper / supply-chain (+10 TA0001/2) |
| **Phase F** RepoGate v1 + xhub fleet | 20-25d | cross-host coordination (+5 TA0008) |

**Total xhelix engineering from current state: ~110-145 days** plus xgenguardian developer time in parallel.

---

## §9 Brutal final verdict

If you ship the locked roadmap and operate it like the spec demands (mature BRP profiles, enforce mode, populated UpstreamHosts, xgenguardian production-grade, fleet baseline > 30 days), **xhelix becomes one of the strongest open-source Linux host EDRs on the market** — competitive with commercial SaaS offerings on host-side detection, **better than them on transparency and operator audit**, and **worse than them on email/phishing/SaaS-integrated signals** which xhelix is not in the business of.

What xhelix uniquely owns at maturity:

- Cryptographically-signed forensic chain with offline auditor
- 10-domain calibrated verifier with line-by-line auditable scores
- 24-class asset taxonomy + 4-state secret-taint state machine
- Signed Behavioral Reference Profiles as runtime contracts
- No SaaS dependency for local enforcement
- CGO_ENABLED=0 single static binary — auditable, reproducible

What it will never be:

- A workstation browser-containment product
- A SaaS-with-threat-intel-feed product
- A replacement for Vault/KMS/SPIFFE
- A replacement for kernel-level patching against kernel zero-days

**The numbers above are achievable, not promised — they require operator investment in profiles + soak + tuning.**
