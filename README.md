# xhelix

A single static-binary Linux server EDR. One daemon (`xhelix`), one operator CLI (`xhelixctl`), one standalone forensic chain verifier (`xhelix-verify`). No agent/manager split. No CGo. Optional fleet baseline hub (`xhub`) for cross-host rare-endpoint detection.

Detects post-compromise behavior — credential theft, C2 beaconing, dropped-binary execution, container escape, persistence implantation, capability gains, kernel rootkit attempts — using eBPF process/file/network telemetry, file-integrity monitoring, identity correlation, an in-process correlator, signed behavioral reference profiles (BRP), and a per-event verifier across 10 evidence domains.

**License:** Apache-2.0 (Go code); GPL-2.0 (eBPF C programs under `sensors/ebpf/progs/` — kernel ABI requirement).
**Runtime:** Linux ≥ 5.15. BPF LSM features need `lsm=...,bpf` on the kernel cmdline.
**Build:** `CGO_ENABLED=0`, statically linked, pure-Go SQLite (`modernc.org/sqlite`).

---

## What problem this solves

Most host EDRs fall into two camps:

1. **Signature-driven** (yara on disk, IOC lookup) — fails against attackers who use legitimate tools and benign-looking traffic.
2. **Anomaly-driven** (ML on syscalls, behavioral baselines) — produces noise; operators eventually mute alerts; FP storms kill operator trust.

xhelix is built on a different premise: **deterministic facts and signed contracts first; anomaly scoring only as a tie-breaker**. Each detection pillar is independently auditable. The verifier's 10 evidence domains produce calibrated scores an operator can read line by line; nothing fires from a single mystery model output.

---

## Architecture

Three layers in one daemon. Started + wired in `cmd/xhelix/run.go`.

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

### Sensors (`sensors/`)

Each implements `sensors.Sensor` (Name/Start/Stop/Health). Linux-only code is split via `//go:build linux` + `_other.go` stubs.

- **`sensors/ebpf/`** — 8 BPF programs: process spawn/exec/exit, file_open, net_connect/bind, modload, BPF syscall use, ptrace, mount, mprotect RWX, canary fail, inode_perm, setxattr, ICMP, raw socket, capset, pivot_root, unshare, memory inspect. Compiled separately via `make ebpf`; deb installs `xhelix-progs.o` to `/usr/lib/xhelix/`.
- **`sensors/fim/`** — inotify-based watcher over canonical persistence + secret + config paths; emits file_open / file_drift; new `fanotify_linux.go` backend for higher-granularity write-on-close + exec-from-tmp coverage.
- **`sensors/decoy/`** — atime canaries on bait paths (SSH keys, AWS creds, kube tokens).
- **`sensors/identity/`** — tail of `/var/log/auth.log` for sshd / sudo / su / pam; emits `identity.sshd` with `outcome=success|failure` + `src_ip` + `user`. Captures PID for proctree propagation (Phase A fix).
- **`sensors/netids/`** — Suricata-format DNS + flow consumer.
- **`sensors/memory/`** — `/proc/PID/maps` poller for RWX regions, memfd-execve patterns.
- **`sensors/lsmaudit/`** — observation-only consumer of LSM denial events (AppArmor/SELinux/BPF-LSM).
- **`sensors/procscrape/`** — proc-environ + `/proc/PID/cmdline` reads tagged with a credentials allowlist.

### Pipeline (`pkg/pipeline/pipeline.go`)

Single-goroutine event handler. Same order on every event so replay is deterministic. Per-event chain:

1. RuntimeAllow tag (well-known JIT runtimes get `jit_allowlisted=true`)
2. AutoBaseline observe/detect tagging
3. ProcTree update (spawn / exit / touch)
4. cgroup classifier + container ID stamp
5. ConnState updates on net events
6. ImageCache SHA-256 enrichment on spawns
7. Cold store persist (filter drops `ebpf.net`, `heartbeat`, `ebpf.self` to prevent the cold.db flood — see `ERRORS.md`)
8. Hot store insert
9. Forensic chain Add (Ed25519-signed batch)
10. **Asset class tag** (path / socket / host → 24-class taxonomy)
11. **Secret taint observation** (file_open of credential paths → 4-state machine)
12. **Egressguard decision** (net_connect → Allow / Verify / Deny per BRP profile + raw-IP-by-protected-role + secret-taint promotion)
13. **cgroup_id tag stamping** (so correlator group_by:cgroup_id works)
14. Rules engine (CEL match)
15. **Correlator ingest** (sequence chain rules)
16. YARA scan on exec
17. Argv-shape detectors (LOLBin, revshell, shm exec, webshell)
18. Capability escalation classifier
19. Container-escape classifier
20. ptrace classifier
21. Cloud-metadata-abuse detector on outbound connect
22. Brand-lookalike on DNS
23. Threat-intel IP match
24. Beacon detector
25. DNS exfil / tunneling detector
26. NetIDS DGA scoring
27. ML anomaly detector
28. Ungated critical-severity emit
29. **SSH brute-force counter** (Phase J.1 — `pkg/sshbrute`)
30. **BRP runtime evaluation** (signed profile match → hard_deny or verify)
31. **IncidentGraph observe** (enrich-only — events update existing incidents; alerts create new ones)

### Detection pillars

| Pillar | Package | Status |
|---|---|---|
| **Behavioral Reference Profiles (BRP)** — signed JSON envelopes per app role; runtime matcher; phase-aware (init/serve/admin/shutdown); writer-cache | `pkg/brp/` | shipped |
| **Source anchor minting + propagation** — every event roots to one of 5 ingress types (sshd accept, PAM session, sudo, cron, systemd unit-start) | `pkg/source/` | shipped |
| **Asset class taxonomy** — 24 classes covering secret/credential/persistence/metadata/CDN paths and sockets; operator override; sensitive classes operator-locked | `pkg/assetclass/` | shipped |
| **Secret-taint state machine** — 4 states (clean → touched → outbound_restricted → containment_required); 12 secret classes; monotonic promotion; 24h TTL with audit ring | `pkg/secrettaint/` | shipped |
| **Verifier — 10 evidence domains:** PathClassifier, PhaseCorrelation, SourceLineage, IntegrityHash, BehaviorHistory, NetworkNovelty, JITAttenuation, CrossApp, SecretContext, AssetContext | `pkg/verify/` | shipped |
| **Egress guard** — per-event Allow/Verify/Deny; nftables backend functional, eBPF cgroup/connect scaffold; observe / shadow / enforce modes; 6-path decision logic | `pkg/egressguard/` | shipped (shadow mode on dev) |
| **Incident graph** — correlated multi-source incident assembler; SQLite audit store with crash-recovery; enrich-only semantics (alerts create, events only enrich) | `pkg/incidentgraph/` | shipped |
| **Correlator** — sequence chain rules over CEL, YAML-loaded from `/usr/share/xhelix/correlator.d/`; group-by enforcement (per-session group scoping) | `pkg/correlator/` | shipped |
| **SSH brute-force detector** | `pkg/sshbrute/` | shipped |
| **Forensic chain** — Ed25519-signed batched event chain; standalone offline verifier; MaxBatches rotation prevents the disk-flood class of bug | `pkg/chain/` + `cmd/xhelix-verify/` | shipped |
| **Hot store / Cold store** — SQLite hot store; 3-day cold retention with 8 GB cap (`DropDaysOverSize`); event-kind filter excludes `ebpf.net` / `heartbeat` / `ebpf.self` | `pkg/store/` + `pkg/coldstore/` | shipped |
| **Process hardening** — `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE=0`, `mlockall`; verified live (`/proc/$PID/status NoNewPrivs:1 CoreDumping:0`) | `pkg/selfprotect/prctl_linux.go` | shipped |
| **Self-seccomp allowlist** — Phase G.2; 195-syscall baseline; three modes (off / audit / enforce); pure-Go cBPF generator + amd64/arm64 NR tables; CGO-free | `pkg/selfseccomp/` | audit-mode live; enforce gated on 24-48h soak |
| **AppIdent** — runtime app-name identification from cgroup / exe / argv; stamps `app_id` + `app_name` tags | `pkg/appident/` | shipped |
| **Tamper guard** — detects attacks against xhelix itself (ptrace, binary swap, pid file rewrite, auditd kill) | `pkg/tamperguard/` | shipped |
| **Beacon detector** — callback-rhythm detection for Cobalt Strike / Sliver / Mythic / custom implants; protocol-agnostic | `pkg/beacon/` | shipped |
| **Baseline + auto-baseline** — per-binary feature aggregates (syscalls, children, endpoints, file_writes); set-diff + EWMA scoring | `pkg/baseline/` + `pkg/autobaseline/` | shipped |
| **Threat-intel feeds** — Spamhaus DROP, Tor exits, FireHOL — alert enrichment on src/dst IP match | `pkg/intel/` | shipped |
| **DNS exfiltration detector** — rate + label entropy + TXT fraction; catches dnscat2, iodine, custom DNS implants | `pkg/dnsexfil/` | shipped |
| **Kernel integrity** — kallsyms hash, /proc/modules diff, syscall-table address tracking; catches LKM rootkits | `pkg/kintegrity/` | shipped |

### Response & enforcement (`pkg/response/`, `pkg/enforce/`)

- **Soak gate** — rules can only auto-quarantine after N clean days of fires with zero FPs
- **PanicSwitch** — operator kill of auto-enforcement
- **Quarantine** — SIGSTOP pause + forensic snapshot
- **NetBan** — nftables drop list keyed by lineage
- **Remediate** — undo persistence drops, restore `/etc/shadow`, revoke session

### Operator surface

- **`xhelixctl`** — `version`, `events tail`, `rules lint|fp|soak`, `posture lsm`, `history`, `passport`, `wizard`, `protect`, `forensic`, `alerts`, `takeover`, `status`, `report`, `credbroker history`, `egress guard {modes,backends,decide}`, `integrity`, `source`, `brp {keygen,generate}`, `appident`, `secrettaint {show,classes}`, `top`, `incidents {list,show,close}`
- **Web UI** — auth-guarded (bearer token + IP allowlist + rate limit + audit log); enterprise pages for sessions, bans, rules, doctor; loopback-only legacy mode also available
- **HTTP API** — `GET /api/incidents`, `GET /api/incidents/{id}` (read-only; close mutations via CLI)
- **Forensic chain CLI** — `xhelix-verify --chain DIR --pub KEY` re-walks the chain offline and names the exact tampered batch

---

## Detection coverage (live, 23 active rules)

Live FP budget from `xhelixctl rules fp` on dev box after multi-day continuous operation:

```
CLASS  NAME            RULES  FIRES   FPS  FP_RATE  TARGET   OK
1      hard_invariant  1      497     0    0.0000   0.0010   yes
2      strong_signal   1      5,393   0    0.0000   0.0050   yes
3      soft_drift      21     928,347 0    0.0000   0.0500   yes
```

**0 confirmed FPs across 934 K total rule fires.** Class targets are documented in the FP architecture spec and locked: 0.1 % / 0.5 % / 5 %.

Detections that fired against `tests/attack-sim/run-all.sh` (12-stage realistic credential harvester):

- `brp.hard_deny` × 9 — Class 1 hard invariants on tmpfs exec
- `memfd_run_pattern`, `mem_mprotect_rwx`, `process_injection_ptrace` — memory-implant patterns
- `shell_with_socket_fd`, `revshell.detected` — reverse-shell families
- `binary_runs_from_tmp`, `cron_new_unit`, `ssh_key_added_root`, `pam_module_modified` — persistence
- `metadata.access_by_unexpected`, `metadata_svc_unexpected` — IMDS abuse by non-cloud role
- `cap.gained`, `bpf_syscall_unexpected`, `contescape.detected` — privilege / container escape
- `dns_exfil.detected`, `beacon.detected` — C2 patterns
- `process_spawn_burst`, `file_read_burst` — credential-scan + malware spawn fan-out
- `dropped_binary_lifecycle` (Phase J.2 chain) — outbound + exec-from-tmp in same lineage
- `ssh_bruteforce` (Phase J.1) — N failed auths per source IP per window

Test suite: **163 packages PASS, 0 FAIL** under `go test -race -count=1`. 229 test files, 1,934 test functions.

---

## Roadmap status

Plan is committed but the canonical execution doc lives on disk (intentionally not tracked in git). Phase status snapshot:

| Phase | Scope | Status |
|---|---|---|
| **A** — substrate (anchors, BRP runtime, SSH PID fix) | 3 d | ✅ done |
| **B.1** — `pkg/assetclass` (24-class taxonomy) | 2 d | ✅ done |
| **B.2** — `pkg/secrettaint` (4-state machine) | 3 d | ✅ done |
| **B.3** — verifier 10-domain wiring | 3 d | ✅ done |
| **B.4** — Phase B integration soak | 2 d | ⏳ in-flight on dev |
| **C.1+C.2** — egressguard backends + core | 5 d | ✅ done |
| **C.3** — egressguard canary soak | 2 d + 48 h wall | ⏳ shadow mode on dev |
| **D.1** — `pkg/incidentgraph` | 3 d | ✅ done |
| **D.2** — incidents CLI + HTTP API | 2 d | ✅ done |
| **E** — production hardening + soak | 5 d wall | partial — realistic-harvester subset done |
| **F** — RepoGate v1 (signed CI runtime contract) | 20-25 d | not started |
| **G.1** — daemon prctl hardening | 2 d | ✅ done |
| **G.2** — seccomp allowlist | 3 d | ✅ audit-mode live; enforce gated on 24-48 h soak |
| **G.3** — landlock policy | 2 d | not started |
| **G.4** — hardened_malloc integration | 2 d | not started |
| **G.5** — host posture checks | 3 d | not started |
| **G.6** — cosign + reproducible build | 1 d | not started |
| **H.1** — per-flow byte counts | 3-5 d | not started |
| **H.2** — long-window correlation | 5-7 d | not started |
| **H.3** — per-rule fire-rate + TTL suppression | 2-3 d | not started |
| **H.4** — CDN cloaking resistance | 3-5 d | not started |
| **I** — BPF-LSM synchronous deny | 7 d | spec only |
| **J.1** — SSH brute-force | 1 d | ✅ done |
| **J.2** — dropped-binary lifecycle correlator chain | 2-3 d | ✅ done |
| **J.3** — messaging-platform asset class | 2 d | not started |
| **K.1** — auditd consumer | 3 d | spec only |
| **K.2** — package-manager log monitor (FP suppression) | 1 d | spec only |
| **K.3** — cert SAN cross-validation | 3-5 d | spec only |
| **L** — trust-collapse state machine | 10-15 d | spec only |
| **M.1-M.4** — deep systemd persistence coverage | 8-12 d | spec only |

---

## Hard constraints

- **CGO_ENABLED=0 always.** Binary must stay statically linked (`make static-check` enforces). SQLite is `modernc.org/sqlite`, not `mattn/go-sqlite3`.
- **Linux-only runtime.** Non-Linux code paths exist only to keep `go build` green on dev machines; gate Linux-specific code with `//go:build linux` and provide a `_other.go` stub.
- **Module path** `github.com/xhelix/xhelix`. `go.mod` is Go 1.23; CI builds on Go 1.22 — avoid 1.23-only stdlib APIs.
- **Apache-2.0** for Go code; **eBPF C programs under `sensors/ebpf/progs/` are GPL-2.0** (kernel ABI requirement) — don't relicense.
- **Kernel ≥ 5.15** at runtime for eBPF. **BPF LSM** needs `lsm=...,bpf` on kernel cmdline.
- **Production canary requires explicit operator decision.** No auto-deploy.

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

Without root (local dev only):

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

Key knobs for the runtime hardening substrate (Phase C + G):

```yaml
hardening:
  egressguard:
    mode: observe   # observe | shadow | enforce
    protected_roles:
      - nginx-reverse-proxy
      - mysql-data-node
  seccomp:
    mode: off       # off | audit | enforce  (G.2 — audit-mode first; enforce only after 24-48h clean soak)
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
cmd/xhub/                optional fleet baseline hub (cross-host rare-endpoint detection)

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
  selfseccomp/           daemon self-seccomp allowlist (Phase G.2 — pure-Go cBPF gen)
  pipeline/              dispatch + per-event enrichment chain
  chain/                 Ed25519-signed forensic chain with rotation
  coldstore/             3-day retention + size cap
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

ruleset/core/            bundled YAML detection rules
ruleset/correlator/      bundled correlator chain rules
examples/                sample config YAML (desktop, server, container-host)
packaging/deb/           Debian packaging templates
tests/attack-sim/        comprehensive attack-simulation corpus + harness
```

---

## How it works — a concrete example

A reverse shell from a compromised nginx worker, end-to-end:

1. **eBPF** sees `proc_spawn` (nginx → bash). Stamps `kind=proc_spawn, path=/bin/bash, parent_image=/usr/sbin/nginx, cgroup_id=12345, outbound=false`.
2. **Pipeline** enriches: ProcTree adds the bash node under the nginx process tree; AppIdent stamps `app_id=nginx-reverse-proxy`.
3. **AssetClass** classifies `/bin/bash` → `AssetSystemBinary` (not sensitive). No tag bump.
4. **AppIdent** + **BRP matcher** load the `nginx-reverse-proxy` profile. The profile lists allowed children: `[nginx-worker, certbot, logrotate]`. bash is NOT in the list.
5. **BRP runtime** fires `brp.hard_deny` Class 1 with reason `"nginx-reverse-proxy spawning /bin/bash — not in allowed-children list"`.
6. **Alert bus** emits → response engine evaluates → `Soak` gate checks clean-day count → alert logged, no enforcement yet.
7. **incidentSink** fan-out writes the alert into **IncidentGraph** as a new Incident under source-anchor 100 (the originating sshd accept that spawned the nginx worker hours earlier).
8. **eBPF** then sees `net_connect` (bash → 203.0.113.99:443). Same cgroup_id 12345.
9. **Pipeline** stamps `outbound=true, dst_ip=203.0.113.99, kind=net_connect, cgroup_id=12345`.
10. **EgressGuard.Decide**: actor role is `nginx-reverse-proxy` (a protected role) and dst is a raw IP with no SNI → returns `EgressDeny`. Mode is `shadow` on dev → emits `egressguard.shadow_deny` Class 2 (not yet enforced).
11. **Correlator** opens a session for `dropped_binary_lifecycle` (Phase J.2) on cgroup_id 12345 at step 0.
12. **eBPF** sees `proc_spawn` again — `/tmp/.attack/payload`. Same cgroup. Path starts with `/tmp/`.
13. **Correlator** advances the chain to step 1 → fires `dropped_binary_lifecycle` Class 3 alert with all evidence event IDs linked.
14. **IncidentGraph** observes all three alerts under the same source anchor; sets `intent=c2`, bumps confidence to 0.85, adds MITRE tags `T1071` + `T1059.004`, accumulates TTPs `[reverse_shell, egress_policy_violation, c2_beacon]`.
15. **`xhelixctl incidents show <id>`** displays the full causal chain — 3 alerts + 5+ event refs + intent + MITRE — for the operator.
16. **`xhelix-verify --chain /var/lib/xhelix/chain --pub /etc/xhelix/chain.pub`** can independently verify, offline, that the events leading up to this incident were not tampered with.

**FP-suppression at every stage:** if nginx-reverse-proxy legitimately has `certbot` as a child, the BRP profile lists it explicitly and no hard_deny fires. If egress target is in the profile's `UpstreamHosts` list, egressguard returns `Allow`.

---

## Where xhelix sits vs alternatives

- **Better than Falco** for single-host operators who want detection + response + audit in one binary.
- **Roughly equivalent to Tetragon** on detection breadth, weaker on synchronous enforcement (no real BPF-LSM deny path yet — Phase I), stronger on FIM/decoys/forensics/correlation/verifier.
- **Useful complement to Wazuh**, not a replacement — Wazuh is your SIEM, xhelix is your real-time response + signed runtime contract layer.
- **Not a CrowdStrike replacement** for enterprise. CrowdStrike's threat intel + behavioral ML + 24/7 SOC are not things xhelix can match without becoming a SaaS company.

---

## Limitations + non-goals (honest gaps)

- **eBPF backend** of egressguard is scaffold-only; nftables is the actual enforcement plane. Per-cgroup eBPF connect-deny is documented Phase I follow-on.
- **Production canary deferred** — production host stays untouched until you explicitly run the deployment. Even after Phase G.6 (cosign + reproducible build), the canary is a human decision.
- **Phase E.1 attack-sim** has been run on a subset (realistic-harvester); the 300+ corpus from `tests/attack-sim/comprehensive_2026-05-22/` is SSH-bound to a prod-shape host and needs porting to local subprocess before it runs against the current build.
- **Phase G.2 seccomp** is in audit-mode as of last deploy. Enforce-mode requires 24-48h clean tail in `/var/log/audit/audit.log` for `type=SECCOMP comm=xhelix`. The audit-mode soak already found one missing syscall (`open(2)`) before it could cause an enforce-mode crash — exactly what audit-mode is for.
- **APM / OpenTelemetry / database query audit** are out-of-scope — xhelix is a host EDR, it consumes those signals from upstream tools, it doesn't generate them.
- **Egress proxy** (Envoy / Istio / Cilium) is complementary, not replaced. xhelix's egressguard is host-local.
- **Trust-collapse state machine** (Phase L) is designed but unbuilt.
- **Phases K, L, I, M** are spec-only as of now.

If a phase is marked `spec only` in the roadmap, it does not yet protect anything in production. Read the plan, not just the README.

---

## License

Apache-2.0. eBPF C programs are GPL-2.0 as required by the kernel ABI.
