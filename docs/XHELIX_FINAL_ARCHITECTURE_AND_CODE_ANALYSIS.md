# xhelix — Final Architecture, Scope, and Code Analysis

| | |
|---|---|
| **Status** | Authoritative synthesis (scope docs + live code audit) |
| **Date** | 2026-07-02 |
| **Branch** | verdict-foundation |
| **Basis** | `docs/2026-06-21-XHELIX_APP_CAUSAL_BRP_SCOPE_LOCK.md` (locked scope) + `docs/BEHAVIORAL_COMPILER_ARCHITECTURE.md` + `docs/CAUSAL_CHAIN_INCIDENT_ENGINE_ARCHITECTURE_2026-05-23.md` + `docs/BRP_CORRELATION_ARCHITECTURE_SPEC_2026-05-24.md`, reconciled against a direct Go-code audit (2026-07-02). |
| **Supersedes** | any framing of xhelix as "a generic Linux EDR" |

This document is the single reference for **what xhelix is**, **how it is architected**, and **what is actually built vs. missing in the code** (with file:line evidence). Where the docs and the code disagree, the **code wins** and is noted.

---

## 1. Product definition (verbatim)

> **xhelix is a per-application causal behavior compiler for Linux servers, with service-level hard invariants and kernel-level egress isolation.**
> *— Not "an EDR." EDR-style detections remain supporting signals. The primary object xhelix produces and enforces is an app contract derived from the observed, attributed, causal behavior of one application.*

The unit of policy is **not a process** — it is a **causal workflow chain**: the complete graph of OS-level actions a valid request or job is allowed to produce, from first network accept to final log write.

---

## 2. The two co-equal pillars

### PILLAR 1 — Per-application causal behavior compiler

Produce and enforce a per-app **contract / Behavioral Reference Profile (BRP)** from the observed, attributed, causal behavior of ONE application.

- **Three-contract model:** Code Contract (declared capability ceiling) → Causal Runtime Contract (observed event graph per workflow) → Enforcement Contract (compiled kernel/userland controls; never hand-edited — you change the inputs and recompile).
- **Three-decision-per-event rule (never collapsed):** every event independently gets **Boundary** (is it this app's?), **Causality** (what root caused it?), **Learnability** (may it become "normal"?). Learnable ⇔ `app_scoped AND chain_scoped AND clean_window AND NOT red_zone AND NOT admin_noise AND NOT compromise_window`.
- **Learning pipeline:** Recorder (dedup workflow shapes) → Synthesizer (shapes → candidate contract) → operator review → Compiler (→ kernel/userland controls). ML may **rank/cluster, never decide** enforcement. Requires an operator-asserted **clean window**.
- **Fidelity is honest:** the kernel cannot supply SQL table names / app function names / decrypted payloads, so every dimension carries `coarse | precise`. A coarse-DB contract must not claim table-level enforcement.
- **Lock ceilings by app class:** static nginx 98–99.5%; reverse proxy 95–98%; API w/ known deps 90–97%; PHP/Node w/ plugins 80–95%; WordPress + 3rd-party 70–90%; dev box 50–70%. Out of scope by design: semantic attacks over the app's own allowed channels (SQLi via app's DB conn, logic abuse within contract, malicious code inside a declared dependency).

### PILLAR 2 — Inter-app / cross-app causal graph correlation

A "graph of graphs" over the whole host: **who talks to whom, and does a scattered set of signals converge into one attack story.**

- **Cross-app edge model** — declared allowed inter-app interactions. `Edge{FromApp, ToApp, AllowedActions, Destinations}`, Ed25519-**signed**, loaded from `*.edge.json`. Worked example: `nginx → php-fpm via FastCGI`.
- **CrossApp scorer** — scores each `(actor_app → target_app)` edge. Known-good edges *attenuate* risk (nginx→php-fpm −1.5; php-fpm→mysql −1.5); novel/forbidden edges *compound* it (**web/db-tier → shell +3.0** — "nginx directly spawns a shell"); operator-signed edge corroborates (−2.0).
- **Incident graph** — the maximal subgraph where multiple evidence chains **converge** on the same **lineage** (process tree), **asset** (one file tampered cross-lineage), or **destination** (multiple lineages calling one C2). Single-chain alerts stay alerts; multi-chain convergences become **incidents**.
- **Source/provenance graph** — SourceAnchor (minted at trusted ingress) + ExecutionLineage + **CausalSet** (append-only bounded provenance handling delayed/file-mediated/socket-mediated causality) + PrimarySource. "A cron job firing today inherits the anchor of the SSH session that wrote it 3 weeks ago."
- **Eight evidence chains** feed both graphs: process, file-read, file-write, network, identity, persistence, privilege, resource-abuse; overlaid by an **asset graph** (crown-jewel = 10× weight) and a **destination graph** (known-bad = 15× weight).

---

## 3. The five enforcement layers (deterministic → learned)

1. **Global red zones** — categorically forbidden everywhere; kernel hard-deny unless a signed maintenance chain unlocks. **Never learnable.** (`pkg/redzones` + `ruleset/core/redzones.yaml`)
2. **Service-role contracts** — per-service role invariants, **not learned** (`nginx → /bin/sh` blocked with zero app profile). (`pkg/servicerole`)
3. **Per-app causal BRP** — the learned workflow envelope; multi-app per host with attribution splitting. (`pkg/brp` — Pillar 1)
4. **Egress isolation** — a separate privileged plane; allowlist-first, **installed before the app starts** (cgroup-BPF → nftables per-cgroup → systemd IPAddressAllow/Deny; DNS/SNI-bound). (`pkg/egressguard`)
5. **Maintenance chains** — signed, time-boxed, cgroup-scoped unlocks of red-zone actions for deploy/migration/cert/pkg. (`pkg/maintenancechain`)

> *"The app BRP is the brain; layers 1–2 and 4 are the bones. Without the deterministic layers the system is smart but not hard."*

**Layered decision stack:** L0 hard invariants → L1 BRP runtime (`allow`/`verify`/`unknown`) → L2 verification engine (8 domains incl. CrossApp) → L3 correlation/incident engine → L4 response.

---

## 4. Mode ladder & companion subsystems

**Modes:** `observe → shadow → guarded → locked → sealed`. Red zones enforce from **guarded** onward. **Auto-block only deterministic facts; never auto-block soft novelty.** Every action reversible (<60s); kill-switch `/run/xhelix/disarm.off`.

**Companion fabrics:** DLCF (Data Leak Containment Fabric — data catalog, taint ledger, sensitivity budget, data passport, egress valve, export broker, canaries; *design-locked*), secret-taint state machine, credential broker (denies secret release at `FAN_OPEN_PERM` — mediate, not observe), signed forensic chain (`pkg/chain` + `xhelix-verify`), deterministic replayable correlator, xhub fleet intelligence.

---

## 5. Code analysis — built vs. missing (audited 2026-07-02)

Verdicts are from the Go source, not docs. Wiring files: `cmd/xhelix/run.go`, `cmd/xhelix/foundation.go`, `pkg/pipeline/pipeline.go`.

### Pillar 2 — inter-app causal graph

| Capability | Verdict | Wired | Evidence |
|---|---|---|---|
| Observed **per-app → external destination** | BUILT | yes | `egressmon/observer.go:52-68`; draft policy `egresspolicy/workflow.go` |
| Observed **app → app EDGE** accumulator (who-calls-which-local-app) | **ABSENT** | — | no `from_app→to_app` collector exists (only signed `brp/edges.go`) |
| Network peer → **TargetApp** resolution | **PARTIAL / DEAD** | no | exec resolves `pipeline.go:2487`; network reads `ev.Tags["dst_app"]` `pipeline.go:2496` but **nothing writes `dst_app`** → always empty |
| **CrossApp scorer** | BUILT | yes, gated | `verify/engine.go:197`, invoked `pipeline.go:2508`; **only under `DecisionVerify`** `pipeline.go:2430`; net edges score 0 because target=="" `domains.go:144` |
| **BRP signed inter-app edges** | BUILT | yes | `brp/edges.go:34-52`; loaded `foundation.go:406`; CLI `xhelixctl brp edge`; consulted `pipeline.go:2499-2505` |
| **Incident graph / convergence** | BUILT | yes | `incidentgraph.Engine`+`Store`; persisted `foundation.go:461` (`incidents.db`); fed `run.go:1351 incidentSink` → `incident_sink.go:33 ObserveAlert`; multi-lineage via shared anchor |
| **Source / provenance causal graph** | BUILT | yes | `source.Minter/Store/FileTaint` `pipeline.go:236/282/289`; CausalSet merge `pipeline.go:777`; `hotgraph.Insert` `pipeline.go:1967` |

### Pillar 1 — per-app compiler

| Capability | Verdict | Wired | Evidence |
|---|---|---|---|
| Workflow-chain stamping | BUILT | yes | `pipeline.go:1500 stampWorkflowChain` → `workflowchain.Compute/Apply` `pipeline.go:1974-2009` |
| Recorder | BUILT | yes (config-gated) | `run.go:3617`; `pipeline.go:1502 Recorder.Observe`; gated `recorder.go:20 learnable!="true"` |
| Synthesizer | BUILT | **CLI only** | `xhelixctl synth propose` `cmd/xhelixctl/synth.go:140`; 0 pipeline importers (offline by design) |
| Compiler | BUILT | yes but **STAGED/disarmed** | `contractcompiler.NewManager` `foundation.go:602`; "not armed" `foundation.go:601`; exec-deny consulted `run.go:847`; plane "disarmed by default" `run.go:1739` |
| BRP runtime enforcement | BUILT | yes | `pipeline.go:2396 BRPRuntime.Evaluate` (`brp/runtime.go:331`) |
| Deterministic layers (red zone / service-role / egress / maintenance) | BUILT | yes (all) | `run.go:813`; `pipeline.go:553/851`; `pipeline.go:1851 EgressGuard.Decide` (ModeObserve default); `foundation.go:569` |

**Dead/unwired packages:** none. `synth` is intentionally CLI-only; `sourcescore` is transitively wired via `incidentgraph`; compiler/enforcement are staged-disarmed.

---

## 6. The genuine gaps (everything else is built)

Only **two** true code holes, both in the cross-app **network** path:

1. **`dst_app` is a dead read.** `pipeline.go:2496` consumes it but no code writes it, so the already-built **CrossApp scorer is blind to network edges** (nginx↔php-fpm↔mysql↔redis). Fixing peer→app resolution (via the listen-port/container map that already exists) makes the network graph score live. **Small, highest leverage.**
2. **No live app→app edge accumulator.** Nothing records the observed "who-calls-which-local-app" topology to auto-propose signed edges (only per-app→external-destination + hand-signed edges exist). Fills the thin-corpus gap.

Beyond those, the remaining distance is **not missing subsystems** but:
- **Fidelity ceiling (hard R&D):** coarse attribution — no per-request `request_id` for server traffic (needs an **L7 root emitter** / socket-cookie), no **DB/Redis semantic** visibility (table/verb/key — SP-3). This gates precise contracts.
- **DLCF:** design-locked, largely unbuilt.
- **Posture:** the compiler + enforcement plane ship **disarmed by default** — turning them on is calibration, not building.

---

## 7. Honest maturity

- **Architecture completeness:** ~**85–90%** of the designed subsystems exist and are wired (both pillars' engines, all five layers, recorder, synthesizer, compiler, incident/source graphs).
- **Effective capability today (default posture):** lower, because (a) enforcement is **disarmed by default**, (b) the cross-app graph is **blind to network edges** (the `dst_app` gap), (c) attribution is **coarse** (no per-request / DB-semantic), (d) the signed-edge **corpus is thin**, and (e) the synthesizer is **offline/CLI-only**.
- **The bones are hard, the graph engine is real but under-fed and net-blind, and the learned brain is built but not yet trustworthy end-to-end.**

**Correction of record:** earlier assessments in this engagement under-counted what is built (nearly rebuilt the app→app edge collector, and mislabeled Pillar-2 engines as missing). This document is the corrected, code-grounded baseline.

---

## 8. Build plan for what remains (small → large)

1. **Populate `dst_app`** (network peer → app resolution) → unblocks CrossApp network-edge scoring. *Small wire, live-provable on the real nginx↔php-fpm↔mysql topology.*
2. **Observed app→app edge accumulator** → auto-propose signed edges (feed the thin corpus + the CrossApp scorer). *New small package + CLI, mirrors `synth propose`.*
3. **DB/Redis coarse semantic adapter (SP-3 slice)** → lift DB fidelity from coarse toward precise.
4. **L7 per-request root emitter** → per-request `request_id` for server traffic (the fidelity gate).
5. **Synthesizer hardening + arm-by-calibration** → make the learned contract trustworthy; graduate enforcement observe→shadow→guarded per app.
6. **DLCF primitives** → taint ledger + budget + passport + export broker.

Items 1–2 are the immediate, high-leverage, low-risk wins that make the *existing* cross-app graph actually function for network edges.
