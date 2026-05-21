# Roadmap

What's done, in progress, and planned. Every entry has a realistic
cost estimate so future-you can budget honestly.

> Snapshot reflects v0.0.11.

## Done (and live on the development VM)

| Version | Feature | Status |
|---|---|---|
| v0.0.5 | Foundation: eBPF, FIM, decoys, rules engine, alert bus | shipped |
| v0.0.6 | Active response engine + enterprise UI + session tracker + netban + remediate + webhook | shipped |
| v0.0.7 | Forensic snapshot + memscan + lockout + execguard + host quarantine | shipped |
| v0.0.8 | `xhelix doctor` (60-check security audit + interactive remediation) | shipped |
| v0.0.9 | Beacon detector + tamperguard + kintegrity + threatfeed + dnsexfil | shipped |
| v0.0.10 | Phase 1 baseline aggregator + systemd watchdog fix | shipped |
| v0.0.11 | Phase 2 baseline scoring + Phase 3 fleet hub MVP | shipped |

## In progress / immediate-next

These are <1 week each and would land in v0.0.12.

- **Scorer.BinaryNames() accessor + auto-pull rare list loop** (~2-3
  days). Closes the Phase 3 gap: agent automatically pulls
  cross-fleet rare lists for every learned binary on a 30-min ticker
  and feeds them via `SetFleetRare`. Plumbing is in place; just
  needs the enumeration accessor and the loop.

- **Universal FIM with writer attribution** (~1-2 weeks). Extend FIM
  from 18 watched paths → fanotify `FAN_MARK_FILESYSTEM` on `/`.
  Capture writer pid/comm/exe + ancestry + dpkg/rpm package owner
  per change. Write a legitimacy decision tree in `pkg/fimverify/`.
  Turns "watching 18 paths" into "watching every file with full
  forensic context".

- **`lsmaudit` sensor on by default** + 10 escalation rules. Instant
  AppArmor/SELinux integration: every MAC denial becomes a high-
  signal event. ~3-5 days.

## Short term — within 1-2 months

- **Real eBPF LSM enforcement** (~2-3 weeks). Closes the gap with
  Tetragon. `bprm_check_security`, `file_open`, `socket_connect`
  hooks. Requires the eBPF C build pipeline and kernel ≥5.7 with
  `CONFIG_BPF_LSM=y` (default on Ubuntu 22.04+).

- **Per-binary endpoint set-diff cross-fleet**. Build on Phase 3:
  agent pulls rare lists, scorer combines local-new + fleet-rare for
  a doubly-suspicious signal class. Promote `FleetRareEndpoints` to
  its own alert RuleID with higher severity than plain
  behavioural_deviation.

- **Container/k8s tags**. Detect `/proc/<pid>/cgroup`, label alerts
  with namespace/pod/container. Doesn't make xhelix k8s-native (still
  no DaemonSet / CRD), but at least makes alerts useful in
  containerised environments. ~3-5 days.

- **CVE scanner integration**. Hook into Trivy or Grype binary; run
  `xhelix doctor --cve` to enrich the patches category with per-
  package CVE data. ~3-5 days.

## Medium term — Phase 4 (months)

- **Real ML on top of baseline data** (~4-8 weeks).
  - K-means clustering of binaries by feature vector (per role).
  - Per-cluster Isolation Forest scoring.
  - Wasserstein distance for temporal drift.
  - Optional LSTM autoencoder for sequence anomalies.

  **Why not first**: simple statistics get 80% of the value at 5%
  of the complexity. Without first proving features are predictive
  (Phase 2 set-diff), throwing ML at them is cargo culting.

- **Process behavior baselining (statistical, not ML)** (~2-3 weeks).
  Per-binary process tree fingerprint: parents, children, exec
  args, environment variables. Build over 7 days, alert on
  deviation. Catches living-off-the-land patterns that pure rule
  engines miss.

## Phase 5 — operating at scale (1000+ hosts)

Things that matter when fleet > 1000:

- **Kafka ingest** instead of direct HTTP POST.
- **Spark/Dask training** instead of in-process Go.
- **Postgres + S3** instead of JSONL.
- **Multi-region hub federation** for global fleets.
- **Per-tenant data segregation** for self-hosted SaaS.

Cost gradient (informational):

| Fleet | Hub VMs | Storage | Eng cost |
|---|---|---|---|
| 10 hosts | 1× $5/mo VPS | 100 MB | weekend project |
| 100 hosts | 1× medium VM | 10 GB | what v0.0.11 targets |
| 1,000 hosts | 2-3 VMs + DB | 1 TB | small team |
| 10,000+ hosts | dedicated cluster | 10+ TB | full data eng team |

## Phase 6 — long term

- **eBPF kernel-rooted threat hunting**: complex multi-event
  correlations entirely in-kernel, decision in BPF maps.
- **Hardware-rooted integrity**: TPM-anchored measured boot + IMA +
  EVM, with xhelix consuming the IMA log.
- **Compliance reporting** (SOC2 Type II evidence, CIS-blessed
  output formats, PCI-DSS).
- **Marketplace of ruleset packs** for verticals (web, k8s, fintech,
  ICS).

## Explicitly NOT planned

- **Vendor SaaS / MDR service**. xhelix is a tool, not a service.
- **Windows or macOS support**. Linux server focus.
- **Replacing your existing SIEM**. xhelix integrates via webhook /
  syslog / file sink — operators bring their own SIEM.
- **Anti-malware signature engine**. ClamAV / commercial AV exist;
  xhelix's memscan covers the in-memory niche, not on-disk AV.

## Decision points

If we ever build:

- **A SaaS hub** → likely as a separate product, not bundled with
  xhelix; agent stays open-source either way.
- **Windows agent** → only if there's a clear self-hosted use case
  not served by Defender / Sysmon.
- **GUI installer / one-click deploy** → maybe, if user feedback
  pushes for it. The deb path is currently good enough.

## How to influence the roadmap

- File issues with concrete attack scenarios xhelix misses (with FP
  vs TP characterisation).
- Submit patches for ruleset additions — `ruleset/core/` is open.
- Run xhelix on hardware xhelix doesn't already run on (kernel
  versions, container runtimes); report compatibility gaps.
