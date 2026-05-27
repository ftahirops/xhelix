# xhelix

**A single-binary Linux server EDR built on signed capability contracts, not signatures.**

```
                          ┌──────────────────────────────────────┐
                          │              xhelix daemon            │
                          │   one static binary, zero CGo deps    │
                          └────────┬─────────────────────────────┘
                                   │
       ┌───────────────────────────┼─────────────────────────────┐
       │                           │                              │
       ▼                           ▼                              ▼
   xhelixctl                  xhelix-verify                    xhub (opt)
   operator CLI              offline chain                  fleet baseline
                              auditor                           hub
```

No agent/manager split. No kernel module. No SaaS dependency for local enforcement. Statically linked, `CGO_ENABLED=0`, pure-Go SQLite, Apache-2.0 (Go) + GPL-2.0 (eBPF programs).

Detects post-compromise behavior — credential theft, C2 beaconing, dropped-binary execution, container escape, persistence implantation, capability gains, kernel rootkit attempts, SSH brute-force, DNS exfiltration — using eBPF process/file/network telemetry, file-integrity monitoring, identity correlation, a sequence correlator, signed Behavioral Reference Profiles, and a per-event verifier across 10 calibrated evidence domains.

> **See [docs/SCENARIOS.md](docs/SCENARIOS.md) for 12 stage-by-stage walkthroughs** showing how xhelix handles real-world attacks: XZ Utils backdoor, SolarWinds Sunburst, 3CX trojan, Log4Shell, MOVEit CL0P, Capital One IMDS SSRF, cortex-c2, TeamTNT cryptominer, SSH brute + key implant, container escape, memory implants, PAM module replacement.

---

## Why xhelix exists

Modern Linux EDRs fall into two failure patterns:

**Signature-driven** (yara, IOC lookup, hash blocklists).
Fails as soon as the attacker uses legitimate tools, custom payloads, or living-off-the-land binaries. The fundamental problem: the attacker chooses the surface; defense chases.

**Anomaly-driven** (ML on syscalls, behavioral baselines, "novel destination" scoring).
Produces a noise floor that operators eventually mute. False-positive storms destroy operator trust. The fundamental problem: anomalous ≠ malicious.

xhelix takes a different bet: **deterministic facts and signed contracts first; anomaly scoring only as a tie-breaker.**

```
┌────────────────────────────────────────────────────────────────┐
│  Layer 1 (always honest)   eBPF + FIM + identity ground truth  │
│  Layer 2 (signed contract) Behavioral Reference Profiles       │
│  Layer 3 (calibrated)      10-domain verifier scoring          │
│  Layer 4 (correlation)     sequence chains + incident graph    │
│  Layer 5 (enforcement)     egressguard nftables / quarantine   │
└────────────────────────────────────────────────────────────────┘
```

Each layer is independently auditable. The verifier never produces a mystery number — every domain logs its contribution and an operator can trace any alert back to ground truth. **No black-box detection.**

---

## What it stops, in plain language

| Attack pattern | How xhelix sees it | Action |
|---|---|---|
| Dropper writes `/tmp/loader` then execs it after fetching from C2 | `dropped_binary_lifecycle` correlator chain ties three events on one lineage | Class 1 — block + quarantine |
| Reverse shell from compromised nginx worker | nginx's signed BRP profile lists allowed children; bash is not in it | `brp.hard_deny` Class 1 |
| Credential file read by a process that has no business reading it | `secrettaint` flips lineage to `secret_touched`; verifier's `SecretContext` domain weights subsequent outbound +5.0 | escalate to verify-tier |
| SSH brute force from a single source IP | `sshbrute` sliding-window counter; 20 fails / 60s → cooldown-gated alert | Class 2 + nftables drop |
| Container escape via `CAP_SYS_ADMIN` mounting host fs | `contescape` classifier + `cap.gained` | Class 1 |
| Memory implant: memfd-execve, RWX mprotect, ptrace injection | `memfd_run_pattern`, `mem_mprotect_rwx`, `process_injection_ptrace` | Class 2 |
| C2 beacon — periodic callback, small fixed payload, single destination | `beacon.detector` callback-rhythm scoring | Class 2 |
| DNS tunneling — high TXT fraction, label entropy, query rate | `dnsexfil` rate + entropy + TXT fraction | Class 2 |
| Persistence drop — new `.service` unit, cron file, `authorized_keys` line | `persistencewatch` + FIM on canonical paths | Class 2/3 |
| Cloud metadata abuse — IMDS access by non-cloud-role | `metadata.access_by_unexpected` | Class 1 |
| Tampering with xhelix itself | `tamperguard` — ptrace detect, binary integrity, watchdog | Class 1 |

---

## Architecture

```
                 ┌─────────────────────────────────────────────────────────────┐
                 │                       Sensors                                │
                 │  eBPF  •  FIM  •  Decoy  •  NetIDS  •  Identity  •  Memory   │
                 │           LSM audit  •  Procscrape  •  SNI check             │
                 └────────────────────────────┬────────────────────────────────┘
                                              │ model.Event
                 ┌────────────────────────────▼────────────────────────────────┐
                 │                       Pipeline                               │
                 │  ProcTree  →  ImageCache  →  cgroupClass  →  AppIdent       │
                 │  AssetClass  →  SecretTaint  →  EgressGuard.Decide          │
                 │  Rules (CEL)  →  Correlator (sequence)  →  Verifier (10D)   │
                 │  BRP runtime  →  IncidentGraph  (enrich-only)               │
                 └────────────────────────────┬────────────────────────────────┘
                                              │ model.Alert
                 ┌────────────────────────────▼────────────────────────────────┐
                 │           Response / Persistence / Operator Surface         │
                 │  Response engine  •  Enforce (Soak, Panic, Quarantine)      │
                 │  NetBan (nftables)  •  Remediate  •  Forensic chain         │
                 │  Hot store (SQLite)  •  Cold store  •  Alert bus            │
                 │  xhelixctl (CLI)  •  Auth-guarded Web UI  •  /api/incidents │
                 └─────────────────────────────────────────────────────────────┘
```

Self-protection wraps the daemon:

```
         ┌──────────────────────────────────────────────────────┐
         │            Daemon Self-Protection                     │
         │   PR_SET_NO_NEW_PRIVS + PR_SET_DUMPABLE=0             │
         │   mlockall(MCL_CURRENT|MCL_FUTURE)                    │
         │   selfseccomp 195-syscall allowlist (audit mode)      │
         │   Tamper guard (ptrace + binary integrity)            │
         │   Forensic chain (Ed25519 + MaxBatches rotation)      │
         └──────────────────────────────────────────────────────┘
```

The pipeline runs **31 ordered stages** per event. Same order on every event so replay is deterministic. Full stage listing in `ARCHITECTURE.md` §5.2.

### Four choke points, all enforced

Every attack must usually pass through at least two of these. xhelix instruments all four:

| Choke point | xhelix component | Mode |
|---|---|---|
| **Execution** | BRP runtime + allowed-children + correlator chains | observe → shadow → enforce |
| **Identity / lineage** | Source anchors (5 ingress types) + AppIdent + proctree | always-on |
| **Data access** | AssetClass 24 taxonomy + SecretTaint 4-state machine | observe + verify-tier |
| **Egress** | EgressGuard 6-path decision + nftables backend | observe → shadow → enforce |

This is the "narrow but deep" model from modern Linux security thinking, applied as concrete code.

---

## How it compares

Honest comparison — strengths and gaps, not marketing claims.

### Feature matrix vs major Linux EDRs

| Capability | xhelix | Falco | Tetragon | Tracee | Wazuh | Sysdig | CrowdStrike |
|---|---|---|---|---|---|---|---|
| eBPF kernel telemetry | ✅ 8 programs | ✅ | ✅ | ✅ | partial | ✅ | ✅ |
| File integrity monitoring | ✅ inotify + fanotify | ❌ | ❌ | ❌ | ✅ | partial | ✅ |
| Identity / auth correlation | ✅ sshd / sudo / PAM | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Signed runtime contracts (BRP) | ✅ Ed25519-signed | ❌ | partial (TracingPolicy) | ❌ | ❌ | ❌ | proprietary |
| Per-event verifier with N domains | ✅ 10 domains | ❌ (single rule) | ❌ | ❌ | ❌ | ❌ | proprietary |
| Source-anchor lineage | ✅ 5 ingress types | ❌ | partial | ❌ | partial | partial | ✅ |
| Asset class taxonomy | ✅ 24 classes | ❌ | ❌ | ❌ | partial | partial | ✅ |
| Secret-taint state machine | ✅ 4-state monotonic | ❌ | ❌ | ❌ | ❌ | ❌ | partial |
| Sequence correlator (CEL chains) | ✅ YAML-loaded | ❌ (single-event) | ❌ | partial | ✅ (server-side) | ✅ (server-side) | ✅ |
| Incident-graph correlation | ✅ enrich-only engine | ❌ | ❌ | ❌ | partial | ✅ | ✅ |
| Per-process egress allow/deny | ✅ 6-path + nftables | partial | ✅ (sync deny via BPF-LSM) | ❌ | ❌ | partial | ✅ |
| Synchronous BPF-LSM deny | planned (Phase I) | ❌ | ✅ | ❌ | ❌ | ❌ | proprietary |
| Forensic chain — signed + offline-verifiable | ✅ Ed25519 + standalone verifier | ❌ | ❌ | ❌ | partial | partial | ✅ |
| SSH brute-force detection | ✅ J.1 sliding window | partial | ❌ | ❌ | ✅ | partial | ✅ |
| Dropped-binary lifecycle chain | ✅ J.2 correlator | ❌ | partial | ❌ | ❌ | ✅ | ✅ |
| Daemon self-hardening (prctl + seccomp) | ✅ G.1 + G.2 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Static-linked binary, no CGo | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | proprietary |
| Operator-readable FP budget | ✅ per-class | ❌ | ❌ | ❌ | partial | ✅ | partial |
| Offline operation (no SaaS required) | ✅ | ✅ | ✅ | ✅ | ✅ | partial | ❌ |
| Open source | ✅ Apache-2.0 + GPL-2.0 (eBPF) | ✅ Apache-2.0 | ✅ Apache-2.0 | ✅ Apache-2.0 | ✅ GPL-2.0 | mixed | ❌ |

### Where xhelix is strictly better

- **vs Falco** — Falco is single-event match. xhelix has sequence correlator + incident graph + verifier with calibrated weights. Falco has no FIM, no identity correlation, no signed contracts, no daemon self-hardening. xhelix wins for single-host operators who want detection + response + audit in one binary.

- **vs Tetragon** — Tetragon has synchronous BPF-LSM deny (xhelix is planned for Phase I). xhelix has signed BRP profiles, asset class taxonomy, secret-taint state machine, 10-domain verifier, FIM, identity correlation, incident graph, offline forensic chain verifier. Roughly equivalent on detection breadth; xhelix is stronger on FIM + decoys + correlation + audit trail.

- **vs Tracee** — Tracee is research-oriented threat-hunting. xhelix is an operational EDR with response, enforcement, and an audit trail. Different products with different goals.

- **vs Wazuh** — Wazuh is a SIEM with HIDS plugins. xhelix is a real-time host agent. They are complementary: Wazuh aggregates many hosts; xhelix is the real-time decision layer on each host. xhelix's signed forensic chain is something Wazuh doesn't have.

- **vs Sysdig** — Sysdig is a heavier-weight commercial-and-open product. xhelix is single-binary, static-linked, no SaaS dep. Sysdig has a broader cloud-config-audit angle xhelix doesn't.

- **vs CrowdStrike** — CrowdStrike's threat-intel feeds, 24/7 SOC, and behavioral ML are things xhelix cannot match without becoming a SaaS company. xhelix is the on-host enforcement and audit layer; if you have CrowdStrike, run xhelix as the deterministic-fact backstop and chain-of-custody layer.

### Where xhelix is honestly weaker (and what we're doing about it)

| Gap | Status |
|---|---|
| Synchronous BPF-LSM deny path | Phase I planned (~7d) |
| Per-flow byte counts | Phase H.1 planned (3-5d) |
| Long-window low-and-slow C2 detection | Phase H.2 planned (5-7d) |
| CDN-cloaked C2 (sharing SAN with legit) | Phase H.4 planned (3-5d) |
| auditd as a parallel signal plane | Phase K.1 planned (3d) |
| Cert SAN / endpoint identity validation | Phase K.3 planned (3-5d) |
| Deep systemd unit semantic parsing | Phase M planned (8-12d) |
| Trust-collapse state machine | Phase L planned (10-15d) |

Every gap above has a concrete plan entry in `docs/BRP_IMPLEMENTATION_PLAN_2026-05-24.md` with budget, merge gate, risk register, and rollback. **No hand-waving roadmap.**

---

## Current state — live measured (not theoretical)

Continuously running on the development host. The numbers below are from `xhelixctl rules fp` + `xhelixctl rules soak` on the live daemon as of last sample.

### False-positive budget (locked targets per FP-architecture spec §12)

```
CLASS  NAME            RULES  FIRES     FPS  FP_RATE  TARGET   OK
1      hard_invariant  1      497       0    0.0000   0.0010   yes
2      strong_signal   1      5,393     0    0.0000   0.0050   yes
3      soft_drift      21     928,347   0    0.0000   0.0500   yes
```

**0 confirmed false positives across 934,237 rule fires.** All three FP classes well under their locked targets.

### Per-rule clean-day tally

| Rule | Fires | FP | Clean days | Promotable to enforce |
|---|---|---|---|---|
| `brp.hard_deny` | 497 | 0 | 3 | not yet (need 7) |
| `process_spawn_burst` | 5,393 | 0 | 3 | not yet |
| `memfd_run_pattern` | 72,211 | 0 | 3 | not yet |
| `bpf_syscall_unexpected` | 93,529 | 0 | 3 | not yet |
| `cap.gained` | 17,417 | 0 | 3 | not yet |
| `contescape.detected` | 14,085 | 0 | 3 | not yet |
| `shell_with_socket_fd` | 3,587 | 0 | 3 | not yet |
| `binary_runs_from_tmp` | 5,385 | 0 | 3 | not yet |
| `mem_mprotect_rwx` | 671 | 0 | 3 | not yet |
| `fim.drift` | 5,617 | 0 | 3 | not yet |
| `metadata.access_by_unexpected` | 26 | 0 | 3 | not yet |
| `lolbin.suspicious` | 117 | 0 | 3 | not yet |
| `ssh_key_added_root` | 7 | 0 | 3 | not yet |
| `cron_new_unit` | 11 | 0 | 2 | not yet |
| `revshell.detected` | 16 | 0 | 1 | not yet |
| `dropped_binary_lifecycle` (J.2, new) | 167 | 0 | 0 | not yet (just shipped) |
| `ssh_bruteforce` (J.1, new) | 1 | 0 | 0 | not yet (just shipped) |

### Build + test health

- **163 packages PASS, 0 FAIL** under `go test -race -count=1`
- **229 test files, 1,934 test functions**
- `make vet` clean, `make build` clean, `make static-check` clean (statically linked, CGO_ENABLED=0)
- Static binary footprint: ~25 MB for `xhelix`, ~18 MB for `xhelixctl`, ~2 MB for `xhelix-verify`

### Live runtime cost

| Resource | Measured | Target | OK |
|---|---|---|---|
| RSS | 506 MB | < 1 GB | ✅ |
| CPU steady-state | ~3-5 % single-core | < 10 % | ✅ |
| Event throughput | ~200/s sustained; peaks to 1 K/s under attack-sim | unbounded | ✅ |
| Hot store size | 211 MB | < 500 MB | ✅ |
| Cold store size | 1.6 GB | < 8 GB cap | ✅ |
| Incident store | 94 KB | grows with alert rate, not event rate | ✅ |

### Self-protection state (verified live)

```
NoNewPrivs:       1
CoreDumping:      0
Seccomp:          2 (filter mode)
Seccomp_filters:  8 (xhelix + systemd-inherited)
/proc/$PID/maps:  444 owner=root:root (DUMPABLE=0 in effect)
```

### Current testing phase

xhelix is in **multi-phase staged validation** on the development host. Production canary is gated on explicit operator decision.

| Phase | Status |
|---|---|
| Phase A — substrate (anchors, BRP runtime) | shipped + 3 clean days |
| Phase B.1 — asset class taxonomy | shipped + 3 clean days |
| Phase B.2 — secret-taint state machine | shipped + 3 clean days |
| Phase B.3 — verifier 10-domain wiring | shipped + 3 clean days |
| Phase B.4 — Phase B integration soak | **in-flight** on dev (24-48h wall clock) |
| Phase C.1 + C.2 — egressguard backends + core | shipped |
| Phase C.3 — egressguard canary soak | **in-flight** in shadow mode on dev |
| Phase D.1 — incident graph | shipped |
| Phase D.2 — incidents CLI + HTTP API | shipped |
| Phase E.1 — quick-pass attack-sim regression | passed against realistic-harvester (12-stage credential harvester) |
| Phase E.full — mega_battery 300+ corpus | needs port from SSH-prod to local subprocess |
| Phase G.1 — daemon prctl hardening | shipped + verified live (`NoNewPrivs:1 CoreDumping:0`) |
| Phase G.2 — seccomp allowlist | **audit-mode live** on dev; enforce-mode gated on 24-48h soak |
| Phase J.1 — SSH brute-force | shipped + smoke-tested |
| Phase J.2 — dropped-binary lifecycle chain | shipped + verified live |

**Engineering-validated. Operator-gated for prod canary.**

---

## Real-world attack walkthroughs

For 12 concrete stage-by-stage analyses of how xhelix handles named attacks — XZ Utils backdoor, SolarWinds Sunburst, 3CX trojan, Log4Shell, MOVEit, Capital One IMDS SSRF, cortex-c2, TeamTNT, SSH brute + key implant, container escape, memory implants, PAM replacement — see **[docs/SCENARIOS.md](docs/SCENARIOS.md)**.

Each scenario covers: attack flow, what signature/anomaly EDRs miss, exact xhelix components that catch each stage, MITRE technique IDs, FP suppression notes, and the Class verdict.

## Where xhelix shines (ideal threat scenarios)

xhelix is built for the threat classes where signature-driven and anomaly-driven tools struggle the most.

### Tier-1 — xhelix is best-in-class on these

1. **Dropper / loader / stager families that fetch then execute.**
   The `dropped_binary_lifecycle` correlator chain (Phase J.2) ties outbound + exec-from-tmp on one lineage. Catches cortex-c2, Megalodon, TeamTNT-style droppers, generic webshell-deployed loaders.

2. **Insider misuse of legitimate credentials.**
   Source-anchor lineage tags every event back to the SSH session / sudo / cron / systemd unit that started the chain. `xhelixctl source lineage <anchor_id>` reconstructs the entire causal tree from one accept-connection.

3. **Container escape and privilege drift.**
   `contescape.detected` + `cap.gained` + `bpf_syscall_unexpected` + `mem_mprotect_rwx`. All Class 2 or higher.

4. **Reverse shells via legitimate parent processes.**
   nginx spawning bash is caught by `brp.hard_deny` Class 1 — nginx's signed profile lists allowed children; bash isn't one of them. Same for php-fpm, mysqld, sshd, postgres.

5. **Persistence implantation.**
   FIM watches `/etc/systemd/system/`, `/etc/cron.d/`, `/root/.ssh/authorized_keys`, `/etc/ld.so.preload`, `/etc/pam.d/`. The 24-class `assetclass` taxonomy tags writes to these as `AssetPersistence` automatically; verifier weights them heavily.

6. **Tamper attempts against the agent itself.**
   `tamperguard` catches ptrace attach, binary swap, pid file rewrite, auditd kill. Combined with `selfprotect` (prctl + selfseccomp + mlockall) the daemon is hard to silently disable.

7. **Forensic chain integrity for audit / compliance.**
   Every event is Ed25519-signed and chained. `xhelix-verify` runs offline and names the **exact tampered batch** if any signature breaks. Suitable for regulated environments where audit trail tamper-evidence is required.

8. **Linux server estates without SaaS dependency.**
   xhelix runs offline. Optional `xhub` is a fleet baseline aggregator, not a SaaS plane. No phone-home, no required telemetry pipeline to a vendor.

### Tier-2 — xhelix is strong, with improvements in flight

- C2 beacon detection (callback rhythm) — strong now, Phase H.2 long-window correlation extends to days/weeks
- DNS exfiltration — strong via rate + entropy + TXT fraction
- SSH brute-force — strong via Phase J.1 sliding-window counter
- IMDS abuse — strong via `metadata.access_by_unexpected` Class 1

### Tier-3 — known limits

- **Long-window low-and-slow C2** — Phase H.2 not yet shipped
- **CDN-cloaked C2** sharing TLS SAN with legitimate traffic — Phase H.4 not yet shipped
- **Token theft via inheritance** — Phase N broker not yet shipped
- **Workstation browser containment** — out of scope (server EDR; workstation is a different product)
- **Insider with root + signing key** — no separation-of-duties enforced beyond BRP edge signing

---

## Ideal use cases

xhelix is built for:

- **Linux server fleets** — web tier, database tier, container hosts, gateways
- **Single-host operators** who want detection + response + audit in one binary
- **Regulated environments** that need cryptographically-signed forensic chains and offline-verifiable evidence
- **Hosts that cannot phone home** — air-gapped, sovereign-cloud, GovCloud-style deployments
- **Defense-in-depth alongside CrowdStrike / SentinelOne / Sysdig** — xhelix is the deterministic-fact backstop and chain-of-custody layer; the SaaS EDR is the threat-intel + ML layer
- **Operators who do not trust black-box ML detections** — every xhelix verdict is line-by-line explicable

xhelix is **not** built for:

- Workstations needing browser/cookie/session containment
- Windows-only environments
- Replacing your SIEM (Wazuh, Splunk, Elastic — xhelix is the real-time agent, not the aggregator)
- Replacing Vault / AWS IAM / SPIFFE — xhelix integrates, doesn't rebuild

---

## Quick start

### Build

```bash
make build          # CGO_ENABLED=0, produces ./xhelix, ./xhelixctl, ./xhelix-verify
make test           # go test -race -count=1 ./...
make vet            # go vet ./...
make static-check   # asserts ./xhelix and ./xhelix-verify are statically linked
make deb            # build dist/xhelix_*.deb
make ebpf           # compile sensors/ebpf/progs/all.bpf.c → xhelix-progs.o (needs clang + libbpf-dev)
make vmlinux        # regenerate vmlinux.h from running kernel BTF (rerun after kernel upgrades)
```

CI: `go vet → go test -race → go build → static-check`.

### Run

Without root (local dev only — no privileged paths):

```bash
./xhelix version
./xhelix tui
./xhelixctl rules lint
./xhelixctl posture lsm
./xhelix-verify --chain DIR --pub KEY
```

Full agent (needs root + `/var/lib/xhelix`, `/var/log/xhelix`, `/run/xhelix`):

```bash
sudo ./xhelix run --config examples/config-server.yaml
```

The Debian package creates those dirs + installs the systemd unit:

```bash
sudo dpkg -i dist/xhelix_*.deb
sudo systemctl enable --now xhelix
```

### Configuration

Single YAML merged over `Default()`. Missing config file is **not** an error. Presets (`desktop` / `server` / `container-host`) applied post-load. See `examples/`.

Key knobs for the runtime hardening substrate:

```yaml
hardening:
  egressguard:
    mode: observe        # observe | shadow | enforce
    protected_roles:
      - nginx-reverse-proxy
      - mysql-data-node
  seccomp:
    mode: off            # off | audit | enforce
                         # audit-mode first; promote to enforce only after 24-48h clean audit-log tail
```

### Operator surface

```bash
xhelixctl status                       # daemon state + alert volume + storage
xhelixctl rules fp                     # per-class FP budget table
xhelixctl rules soak                   # per-rule clean-day tally
xhelixctl incidents list               # currently-open correlated incidents
xhelixctl incidents show <id>          # full causal chain + MITRE + TTP tags
xhelixctl egress guard decide          # dry-run egressguard decision for a (role, dst) pair
xhelixctl source lineage <anchor_id>   # reconstruct causal tree from source anchor
xhelixctl secrettaint show             # per-lineage secret-taint state
xhelixctl brp generate /etc/nginx/nginx.conf > draft.json   # author BRP profile from production config
xhelix-verify --chain /var/lib/xhelix/chain --pub /etc/xhelix/chain.pub
```

---

## Project layout

```
cmd/xhelix/              daemon binary entrypoint (cobra: run, tui, version)
cmd/xhelixctl/           operator CLI entrypoint
cmd/xhelix-verify/       standalone Ed25519 chain verifier
cmd/xhelix-graph-server/ optional HTTP graph server for source-lineage debugging
cmd/xhelix-honeysh/      honeypot ssh shell (deception layer; opt-in)
cmd/xhelix-dnspoison/    decoy DNS responder (deception; opt-in)
cmd/xhelix-sinkhole/     decoy TCP sink (deception; opt-in)
cmd/xhelix-watchdog/     supervisor for daemon restart protection
cmd/xhub/                optional fleet baseline hub

pkg/                     shared libraries (config, model, version, alert, store, rules, …)
  brp/                   BRP runtime + parsers (nginx, apache, sshd, mysql, php-fpm)
  source/                source anchors + minter + SQLite store + lineage
  assetclass/            24-class taxonomy
  secrettaint/           4-state secret-touch tracker
  verify/                10-domain verifier engine
  egressguard/           per-event Allow/Verify/Deny + nftables backend
  incidentgraph/         correlated incident assembly + SQLite audit store
  correlator/            CEL-based sequence chain rules + YAML loader
  sshbrute/              SSH brute-force counter
  selfprotect/           daemon self-defence (prctls, mlockall, immutable, integrity)
  selfseccomp/           daemon self-seccomp allowlist (pure-Go cBPF gen)
  pipeline/              dispatch + per-event enrichment chain
  chain/                 Ed25519-signed forensic chain with rotation
  coldstore/             3-day retention + 8 GB size cap
  rules/                 CEL rule engine
  enforce/               Soak gate + PanicSwitch + Quarantine
  netban/                nftables drop-list manager
  …                      (~80 other packages)

sensors/                 observation plugins implementing sensors.Sensor
  ebpf/                  kernel telemetry (programs in ebpf/progs/, GPL-2.0)
  fim/                   inotify + fanotify watchers
  decoy/                 atime canaries
  identity/              auth-log tailer (sshd, sudo, su, pam, cron)
  netids/                Suricata-format consumer
  memory/                /proc/PID/maps poller
  procscrape/            proc environ/cmdline reader
  lsmaudit/              LSM denial event consumer

ruleset/core/            bundled YAML detection rules (33+ CEL match rules)
ruleset/correlator/      bundled correlator chain rules (cortex_c2.yaml + more coming)
examples/                sample config YAML (desktop, server, container-host)
packaging/deb/           Debian packaging templates
tests/attack-sim/        comprehensive attack-simulation corpus + harness
```

---

## Hard constraints

Non-negotiable design rules:

- **CGO_ENABLED=0 always.** Statically linked, pure-Go SQLite (`modernc.org/sqlite`). Enforced by `make static-check`.
- **Linux-only runtime.** Non-Linux code paths exist only to keep `go build` green on dev machines; gate Linux-specific code with `//go:build linux` and provide a `_other.go` stub.
- **Module path** `github.com/xhelix/xhelix`. `go.mod` is Go 1.23; CI builds on Go 1.22 — avoid 1.23-only stdlib APIs.
- **Apache-2.0** for Go code; **eBPF C programs under `sensors/ebpf/progs/` are GPL-2.0** (kernel ABI requirement).
- **Kernel ≥ 5.15** at runtime for eBPF. **BPF LSM** needs `lsm=...,bpf` on kernel cmdline.
- **Production canary requires explicit operator decision.** No automation.
- **No mystery scores.** Every verifier domain is independently auditable.

---

## How it works — concrete end-to-end example

A reverse shell from a compromised nginx worker, traced stage by stage:

1. **eBPF** sees `proc_spawn`: nginx → bash. Stamps `kind=proc_spawn, path=/bin/bash, parent_image=/usr/sbin/nginx, cgroup_id=12345, outbound=false`.
2. **Pipeline** enriches: ProcTree adds the bash node under nginx; AppIdent stamps `app_id=nginx-reverse-proxy`.
3. **AssetClass** classifies `/bin/bash` → `AssetSystemBinary`. No taint bump.
4. **AppIdent** + **BRP matcher** load the `nginx-reverse-proxy` profile. The signed profile lists allowed children: `[nginx-worker, certbot, logrotate]`. bash is not in the list.
5. **BRP runtime** fires `brp.hard_deny` Class 1 with reason `"nginx-reverse-proxy spawning /bin/bash — not in allowed-children list"`.
6. **Alert bus** emits the alert → response engine evaluates → `Soak` gate checks clean-day count → alert logged, no enforcement yet (rule not yet promotable).
7. **IncidentSink** fan-out writes the alert into **IncidentGraph** as a new Incident under source-anchor 100 (the sshd-accept that started the nginx worker hours earlier).
8. **eBPF** then sees `net_connect`: bash → 203.0.113.99:443. Same cgroup_id 12345.
9. **Pipeline** stamps `outbound=true, dst_ip=203.0.113.99, kind=net_connect, cgroup_id=12345`.
10. **EgressGuard.Decide**: actor role is `nginx-reverse-proxy` (protected); destination is a raw IP with no SNI → returns `EgressDeny`. Mode is shadow on dev → emits `egressguard.shadow_deny` Class 2 (would-be-denied; not yet pushed to kernel).
11. **Correlator** opens the `dropped_binary_lifecycle` session on cgroup_id 12345 at step 0.
12. **eBPF** sees `proc_spawn`: `/tmp/.attack/payload`. Same cgroup. Path starts with `/tmp/`.
13. **Correlator** advances the chain to step 1 → fires `dropped_binary_lifecycle` Class 3 alert with all evidence event IDs linked.
14. **IncidentGraph** observes the three alerts under the same source anchor; sets `intent=c2`, bumps confidence to 0.85, adds MITRE tags `T1071` + `T1059.004`, accumulates TTPs `[reverse_shell, egress_policy_violation, c2_beacon]`.
15. **`xhelixctl incidents show <id>`** displays the full causal chain — 3 alerts + 5+ event refs + intent + MITRE — for the operator.
16. **`xhelix-verify --chain /var/lib/xhelix/chain --pub /etc/xhelix/chain.pub`** can independently verify, offline, that the events leading up to this incident were not tampered with.

**Crucially:** FP suppression at every stage. If nginx-reverse-proxy legitimately has `certbot` as a child, the BRP profile lists it explicitly and no `hard_deny` fires. If the egress target is in the profile's `UpstreamHosts` list, egressguard returns `EgressAllow`. If `/tmp` exec belongs to a package-install transaction (Phase K.2 — planned), the `pkg_install_window=true` tag suppresses the chain rule. Every stage has a calibrated escape hatch.

---

## Limitations + non-goals (honest)

xhelix is opinionated about what it is **not**:

- **Not a workstation EDR.** Browser/session/cookie containment is a different product class. xhelix is server-side.
- **Not a SaaS.** No phone-home requirement; no required vendor-side analytics. `xhub` is a self-hosted fleet aggregator, not a control plane.
- **Not a Vault replacement.** xhelix integrates with KMS / Vault / SPIFFE; it does not rebuild secret storage.
- **Not a SIEM.** Wazuh, Splunk, Elastic do aggregation. xhelix is the real-time agent.
- **Not an egress proxy.** Envoy / Istio / Cilium are complementary. xhelix's egressguard is host-local enforcement.
- **No default-deny daemon-wide execution.** Would require BRP profiles for thousands of binaries; current direction is targeted enforcement on protected roles.
- **No ML-first detection.** Anomaly scoring is a tie-breaker, not the primary signal.
- **No IOC / threat-intel-first.** Threat intel enriches alerts; it does not drive them.

If a phase is marked `spec only` in the roadmap, it does not yet protect anything in production. Read the plan, not just the README.

---

## License

Apache-2.0 (Go code). eBPF C programs under `sensors/ebpf/progs/` are GPL-2.0 as required by the kernel ABI.
