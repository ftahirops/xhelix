# Refactor Roadmap — reconciling the architecture

xhelix's architecture has been described from multiple angles in
separate docs:

- `BEHAVIORAL_DEFENSE.md` — three-tier detection model
- `DATA_LEAK_FABRIC.md` — DLCF (catalog + taint + budget + passport)
- `CROWN_JEWEL_PROFILE.md` — SMB-targeted protection profile
- `FULL_TAKEOVER_DETECTION.md` — scorer + phase-coverage matrix
- `CONTAINMENT_DESIGN.md` — 5-layer jail + deception + bastion

This document **reconciles them around three shared types**:

- `ActionPlan` — the canonical output of every decision
- `CapabilitySet` — what the runtime can actually do right now
- `ContainmentState` — the per-lineage state machine

After this reconciliation, the design is one coherent system instead
of five complementary-but-overlapping ones.

> Status: design locked. Implementation tracked in `ROADMAP.md`
> Phase P-REFACTOR. Companion to all other architecture docs.

---

## 1. Why this doc exists

A code-analysis review (`docs/ARCHITECTURE_REFACTOR_ROADMAP_2026-05-20.md`)
identified that xhelix's enforcement semantics are split across:

- alert production in `cmd/xhelix/run.go`
- response execution in `pkg/response/policy.go`
- network block plumbing in `cmd/xhelix/enforce_wiring.go`
- rule mode metadata in `pkg/model/alert.go`

The proposed fix: one `ActionPlan` type that every decision produces
and every executor consumes. Plus `CapabilitySet` for runtime degradation
modeling, plus `ContainmentState` for reversible state tracking.

**This is the right fix.** It converts our existing designs from
"five overlapping primitive sets" into "one type system" without
changing the security guarantees.

---

## 2. The shared type vocabulary

These types are the SOURCE OF TRUTH. Other docs reference them.

### 2.1 ActionPlan — the canonical decision output

```go
package decision

// ActionPlan is what every detection-and-decision path emits.
// Every executor consumes only this. No more RuleID bitmasks,
// no more Alert.Mode strings, no more direct quarantine.Stop()
// shortcuts.
type ActionPlan struct {
    // Provenance
    AlertID       string    // the originating alert
    RuleID        string    // the rule that fired (or "" for compositions)
    LineageID     uint64    // pkg/lineage.LineageID — causal chain
    ProcKey       string    // canonical.ProcKey — "pid@start_ticks"
    CreatedAt     time.Time

    // Confidence
    Score         int       // 0-100; per FULL_TAKEOVER_DETECTION.md §4.1
    Tier          string    // "observed", "suspicious", "likely", ...
    Confidence    string    // "deterministic", "high", "medium", "low"

    // Action bits — what to execute (in this order if multiple set)
    Snapshot       bool     // /proc + memory snapshot before any destructive action
    Memscan        bool     // YARA + IOC scan against process memory
    Delay          time.Duration // soft-enforce: inject latency on next sensitive op
    RequireStepUp  bool     // soft-enforce: demand fresh WebAuthn before continuing
    SuspendProcess bool     // Layer 2 — SIGSTOP the lineage
    IsolateCgroup  bool     // Layer 3 + 4 — nft deny + LSM fs-jail + cap strip
    BanRemoteIP    bool     // pkg/netban — drop to remote
    Tarpit         bool     // Layer 6 — 8 b/s QoS on attacker IP
    IsolateHost    bool     // Layer 5 — host-lockdown of sensitive routes
    RemediateFile  bool     // pkg/remediate — restore from baseline
    LockLocalUser  bool     // pkg/lockout — refuse new login sessions for user
    KillProcess    bool     // SIGKILL — ONLY after snapshot + operator confirm

    // Provenance + safety
    Reasons            []string
    Preconditions      []string  // e.g. "off-host chain mirror confirmed"
    CapabilityWarnings []string  // e.g. "memscan unavailable; skipped"

    // Reversibility (ContainmentState transitions)
    Reversible bool      // false only for SIGKILL + RemediateFile
    ExpiresAt  time.Time // auto-rollback boundary (§11.4 of CONTAINMENT_DESIGN.md)
}
```

### 2.2 CapabilitySet — what the runtime can actually do

```go
package runtime

// CapabilitySet is built at daemon startup. Consulted by every
// decision so it can degrade explicitly instead of silently
// (closes the "silent degradation" class from ERRORS.md).
//
// Sources: kernel feature probes + pkg/configaudit witnessed knobs
// + sensor.Health() polls.
type CapabilitySet struct {
    // Kernel / runtime features
    EBPF           bool   // basic eBPF available (CO-RE, ringbuf, etc.)
    BPFLSM         bool   // BPF LSM hooks (for bpf_send_signal, override_return)
    NFTables       bool   // nftables present + writable
    Cgroupv2       bool
    SystemdCgroups bool

    // xhelix subsystems
    NetBan         bool
    HostQuarantine bool
    Snapshotter    bool
    Memscan        bool
    Remediator     bool
    LocalAPI       bool
    ProtectedUI    bool
    ColdStore      bool
    Chain          bool
    OffHostMirror  bool   // P-CJ.10 — REQUIRED for safe Layer 5

    // Deception layer (P-FT.11)
    Tarpit         bool
    SyscallLatency bool
    FakeSuccess    bool
    DecoyFS        bool

    // Bastion (P-FT.12) — REQUIRED before Layer 5
    BastionConfigured bool
    BastionCount      int   // must be >= 2 for safe Layer 5
}

// CanExecute reports whether a given ActionPlan can fully execute
// given current capabilities. Missing capabilities don't fail —
// they get appended to CapabilityWarnings.
func (c CapabilitySet) CanExecute(plan *ActionPlan) (canExecute bool, warnings []string)
```

### 2.3 ContainmentState — the reversible state machine

```go
package actionlog

// ContainmentState tracks per-lineage containment progress.
// Operator sees not just "alert fired" but "what state are we in
// right now and how do I get out".
type ContainmentState string

const (
    StateObserved   ContainmentState = "observed"    // signal seen, no action
    StateTriaged    ContainmentState = "triaged"     // 50-74 score, soft enforce
    StateSuspended  ContainmentState = "suspended"   // Layer 2 SIGSTOP
    StateIsolated   ContainmentState = "isolated"    // Layers 3+4 active
    StateContained  ContainmentState = "contained"   // Layer 5 host-lockdown
    StateRemediated ContainmentState = "remediated"  // operator-cleared, evidence kept
    StateReleased   ContainmentState = "released"    // auto-rollback or clear
    StateTerminated ContainmentState = "terminated"  // SIGKILL'd (post-snapshot)
)

// Transition records one state change for the action log.
type Transition struct {
    LineageID  uint64
    From       ContainmentState
    To         ContainmentState
    At         time.Time
    Reason     string
    PlanID     string  // points to the ActionPlan that drove this
    OperatorID string  // empty for auto-transitions, set for manual
}
```

---

## 3. How this reconciles existing docs

Each design doc gets a section that translates its primitives into
these shared types:

### 3.1 `FULL_TAKEOVER_DETECTION.md` → `pkg/takeover` produces ActionPlan

The scorer described in `FULL_TAKEOVER_DETECTION.md §4.1` produces
**`ActionPlan` values** instead of opaque "tier promotion events".

```
Score crosses 50 → ActionPlan{ Delay: 1s, RequireStepUp: true,
                               Score: 50, Tier: "triaged" }
Score crosses 75 → ActionPlan{ SuspendProcess: true,
                               IsolateCgroup: true,
                               BanRemoteIP: true,
                               Tier: "suspended" }
Score crosses 90 → ActionPlan{ + LockLocalUser, + Snapshot,
                               + Memscan, Tier: "isolated" }
Score = 100      → ActionPlan{ + IsolateHost, Tier: "contained" }
+ attacker IP    → ActionPlan{ + Tarpit, Reversible: true,
   identified                   ExpiresAt: now+6h }
```

Per-rule weights from `ruleset/dlcf/takeover.yaml` (P-FT.2) feed
into the score; the scorer composes the ActionPlan from the score
+ CapabilitySet.

### 3.2 `CONTAINMENT_DESIGN.md` → 5 layers ARE ActionPlan field semantics

The 5-layer cell from `CONTAINMENT_DESIGN.md §1` maps directly:

| Layer | ActionPlan fields |
|---|---|
| 1. Soft block | `Delay`, `RequireStepUp`, refuse-passport-issuance flag |
| 2. SIGSTOP cell | `SuspendProcess`, `Snapshot` |
| 3. Network jail | `IsolateCgroup` (nft side), `BanRemoteIP` |
| 4. FS + cap | `IsolateCgroup` (LSM fs-jail side) |
| 5. Host lockdown | `IsolateHost`, `Snapshot`, `Memscan` |
| 6. Deception | `Tarpit`, plus capability flags for syscall-latency / fake-success / decoy-fs |

The bastion (§3) and root-session lockdown (§4) become preconditions:

- Layer 5 (`IsolateHost`) requires `CapabilitySet.BastionCount >= 2`
  in Preconditions; the decider refuses to set `IsolateHost = true`
  otherwise.
- Layer 6 (`Tarpit`) requires high-confidence attribution; the
  decider sets it only when `Score == 100` AND threat-intel
  confirms the source IP.

### 3.3 `BEHAVIORAL_DEFENSE.md` → composition rule produces ActionPlan

The composition rule from `BEHAVIORAL_DEFENSE.md §5`:

```
hard_action  ← any Tier-1 signal
             OR (two independent Tier-2 + one Tier-3 above threshold)
soft_action  ← one Tier-2 signal
             OR two Tier-3 signals
score_only   ← single Tier-3 signal
```

…becomes the planner's decision function:

```go
func Plan(alert *Alert, signals SignalSet, caps CapabilitySet) *ActionPlan {
    if signals.HasTier1() {
        return planHardAction(alert, signals, caps)
    }
    if signals.HasTwoIndependentTier2() && signals.HasTier3() {
        return planHardAction(alert, signals, caps)
    }
    if signals.HasOneTier2() || signals.HasTwoTier3() {
        return planSoftAction(alert, signals, caps)
    }
    return planScoreOnly(alert)
}
```

### 3.4 `DATA_LEAK_FABRIC.md` → existing primitives slot in cleanly

DLCF's Egress Valve, Sensitivity Budget, Canary rules, and Data
Passport remain as-is. The Action Passport (P7.1.7) is a
*precondition* on ActionPlans involving bulk movement, not a
separate action.

### 3.5 `CROWN_JEWEL_PROFILE.md` → L1-L6 tiers integrate with ActionPlan

The L1-L6 protection tiers from `CROWN_JEWEL_PROFILE.md §4` become
the input to the planner: a request that fails `pkg/policy.Check`
for its route's tier triggers an ActionPlan with `RequireStepUp`,
`Delay`, or higher actions depending on the tier mismatch.

---

## 4. The target package layout

After the refactor, the post-detection pipeline is:

```
sensors/*  →  pkg/pipeline  →  pkg/detect  →  pkg/decision  →  pkg/response/executor
                                                       ↓
                                                 pkg/actionlog
                                                       ↓
                                              UI / LocalAPI / xhub
```

Mapping new packages to existing primitives:

| New package | Contains | Sourced from |
|---|---|---|
| `pkg/runtime` | `CapabilitySet`, capability discovery | NEW; partial inputs from `pkg/configaudit` |
| `pkg/pipeline` | dispatcher, normalize, persist fan-out | extracted from `cmd/xhelix/run.go` |
| `pkg/detect` | rules, heuristics, correlator, anomaly | mostly already exists; just regrouped |
| `pkg/decision` | planner, ActionPlan, suppression, soak | NEW; absorbs `pkg/takeover` (P-FT.1) and current `pkg/response/policy` decision logic |
| `pkg/response/executor` | executes ActionPlan; backends for each action | refactored from `pkg/response/policy` + `pkg/enforce` |
| `pkg/actionlog` | persists outcomes; tracks `ContainmentState` | NEW |

---

## 5. Sequencing — when to do what

The refactor doc proposes 5 phases. Adjusted for what's already done
and what other work is in flight:

| Phase | Status | Effort | Sequencing constraint |
|---|---|---:|---|
| **Phase 0** — security stabilization (no dispatch-level destructive actions) | ✅ Done (`c926c24`) | 0 | — |
| **Pre-1** — write golden tests for current Alert → action behavior | not done | 2 d | Must precede Phase 1; safety net |
| **Phase 1** — extract `bootstrap.go`, `dispatch.go`, `alerts.go`, `shutdown.go` from `run.go` | not done | 5-7 d | Should land alongside or just after pkg/takeover so it has one real consumer |
| **Phase 2** — `pkg/pipeline` extraction | not done | 5 d | After Phase 1 |
| **Phase 3** — `pkg/decision` + `ActionPlan` | partially designed (P-FT.1) | 7-10 d | Highest-leverage; ships P-FT.1 inside the new package |
| **Phase 4** — `pkg/actionlog` + `ContainmentState` machine | designed in `CONTAINMENT_DESIGN.md §11.4` | 5 d | After Phase 3 |
| **Phase 5** — `pkg/runtime.CapabilitySet` discovery + decision integration | partially designed | 4 d | After Phases 3+4 |

**Total: ~26-31 days end-to-end.**

### What changes in our current roadmap

- **P-FT.1 (pkg/takeover scorer)** becomes **P-FT.1 (pkg/decision planner) + emits ActionPlan** — same code, new vocabulary
- **P-FT.5 (containment actions in pkg/enforce)** becomes **pkg/response/executor backends** — same code, new structure
- **P-FT.4 (stateguard)** becomes a contributor to `CapabilitySet` (in addition to its drift-detection role)
- **P-CJ.5 (watchdog + heartbeat)** becomes a `CapabilitySet` updater (heartbeat status affects what actions are available remotely)
- **The configaudit `Witness` set (shipped `db1b90c`)** feeds `CapabilitySet.<knob>Configured` flags

---

## 6. The non-negotiable refactor rules

These are constraints on the implementation. Violating any means the
refactor failed its purpose.

1. **One path to act.** No code outside `pkg/response/executor` may
   call SIGSTOP, SIGKILL, nft rules, or quarantine APIs directly.
   Architectural test: `grep -rn "kill\|nft -A\|quarantine\.Stop" -- pkg/* sensors/*` returns ZERO matches outside the executor package.

2. **Decisions are reversible by default.** Every ActionPlan must
   have `Reversible: true` unless the operator policy explicitly
   set otherwise. SIGKILL and RemediateFile are the only built-in
   non-reversible actions and require explicit opt-in.

3. **No silent degradation.** If a Plan can't fully execute due to
   missing capabilities, the WARNING goes into `CapabilityWarnings`,
   the chain records it, and the operator dashboard shows it. Never
   silent.

4. **Golden tests precede file moves.** Before any Phase 1 work,
   capture current `Alert → action` outcomes in a test corpus. After
   each refactor commit, re-run the corpus; outputs must match.

5. **Containment state changes go through the actionlog.** Every
   transition (`StateObserved → StateTriaged`, etc.) is logged with
   reason, plan id, operator id (or "auto"). Operator can replay.

6. **`pkg/configaudit` keeps its veto power.** If a knob is declared
   without a Witness, the daemon still warns. The refactor doesn't
   bypass the architectural lock.

---

## 7. Honest non-promises

1. **The refactor takes 26-31 days.** That's substantial. It's not
   a weekend cleanup. Plan for ~6 weeks of focused effort if shipped
   end-to-end; longer if interleaved with feature work.

2. **Behavior drift IS a risk** during file moves. Golden tests
   mitigate but don't eliminate. Expect one or two "wait, did
   that change?" bugs during Phase 1-2.

3. **The new types DON'T magically fix existing detection gaps.**
   `ActionPlan` is a vocabulary upgrade; it doesn't change what
   xhelix CAN detect or contain. The behavioral defenses (`P-B.*`)
   and DLCF (P7.*) still need to be built underneath.

4. **`CapabilitySet` is best-effort.** Some capabilities (e.g.
   "BPF LSM works") can only be verified by trying. The set is
   probed at startup and re-probed periodically, not perfectly
   real-time.

5. **`ContainmentState` is per-lineage.** xhelix doesn't yet support
   per-user or per-tenant state machines. Operators wanting "freeze
   all of tenant X" need to compose across lineages manually for now.

---

## 8. The immediate next steps

After this doc lands:

1. **Update `CONTAINMENT_DESIGN.md` and `FULL_TAKEOVER_DETECTION.md`**
   with cross-references to this doc's type vocabulary. (~30 min)

2. **Write golden tests for current alert → action behavior.** Even
   if no refactor happens immediately, the corpus protects against
   regressions. (~2 days)

3. **Build `pkg/decision.ActionPlan` as a struct + tests.** Standalone
   type; no consumers yet. ~1 day.

4. **Build `pkg/runtime.CapabilitySet` with startup discovery.** ~2
   days. First consumer is the daemon-startup log line that
   currently says "rules loaded count=58" — extend it to dump the
   full CapabilitySet so operators can see what's actually live.

5. **Ship `pkg/takeover` (P-FT.1) using `ActionPlan` as its output**.
   ~7 days. This is the first real consumer.

6. **Then start Phase 1 file moves**, with golden tests in CI.

---

## 9. The TL;DR

The refactor proposal is right. Our existing design docs already
describe most of what it calls for, but in different vocabulary.
Adopting `ActionPlan`, `CapabilitySet`, and `ContainmentState` as
the shared types converts five overlapping designs into one
coherent type system.

Cost: ~26-31 days end-to-end. Highest-leverage step is `pkg/decision`
+ ActionPlan (Phase 3). Should not be started without golden tests
and a real first consumer (pkg/takeover).

This is the right next big architectural move after the operational
fixes shipped this session (`db1b90c`, `f516c80`, `c926c24`,
`541224c`).
