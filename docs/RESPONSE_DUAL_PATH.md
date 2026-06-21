# Response dual-path contract (legacy OnAlert ↔ planner Executor)

Status: **both paths live; legacy is authoritative; planner runs in shadow.**
Owner doc for the P-RF.9 migration. Last verified 2026-06-21 by
`pkg/response/equivalence_test.go`.

## Why there are two paths

During the takeover-planner migration (P-RF.9) the response engine has two
dispatch surfaces that **share the same backends**:

| | Legacy | Planner |
|---|---|---|
| Entry point | `Engine.OnAlert(alert)` | `Executor.Execute(plan, alert)` |
| Input | a `model.Alert` + a `RuleID → Action` bitmask `Policy` | a `decision.ActionPlan` emitted by the takeover planner |
| Decision | per-rule policy lookup → bitmask | planner already decided; the plan IS the decision |
| Backends | `Engine.do*` (doSnapshot/doNetBan/doQuarantine/doKill/…) | the **same** `Engine.do*` methods, via `Executor` |
| Posture | **authoritative** — its actions are the ones that happen | **shadow** by default (`takeover.active=false`): the planner computes plans and logs what the Executor *would* do; it does not act |

The planner is wired in `cmd/xhelix/run.go` as `wire.PlannerWiring`, gated on
`cfg.Takeover.Active`. While `active=false`, `PlannerWiring` never calls
`Executor.Execute` against live alerts — it only observes and logs. The legacy
`Engine.OnAlert` remains the single source of enforcement.

This split is **deliberate** and tracked in memory (`c2_engagement_deferred`,
`full_takeover_direction`): the planner stays in shadow until the takeover
scorer is calibrated on real traffic. Do **not** delete the legacy path or
flip `takeover.active` on by default as part of unrelated work.

## What is actually equivalent (and what is not)

The `Executor` docstring says each action bit maps "1:1 … in the same order as
OnAlert's bitmask walk." The **1:1 backend mapping is true**; the **"same
order" is an overstatement** and should not be relied on. The two walks order
the destructive/network actions differently:

```
legacy  OnAlert : snapshot → memscan → netban → remediate → quarantine → kill → lockuser → hostquarantine → webhook
planner Execute : snapshot → memscan → suspend(quarantine) → isolate_cgroup → netban → [tarpit] → isolate_host(hostquarantine) → remediate → lockuser → kill → webhook
```

(Empirically reproduced by `TestResponsePaths_EvidenceBeforeDestruction`'s log
output.)

The properties that **are** guaranteed in both, and are pinned by tests:

1. **Same backend set.** For a maximal action set, both paths reach exactly the
   same `Engine.do*` backends — no action is reachable by one path but not the
   other. (`TestResponsePaths_ReachSameBackends`)
2. **Evidence before destruction.** A forensic snapshot is captured before any
   process-destroying signal (SIGSTOP/SIGKILL), because the signal destroys the
   `/proc` state the snapshot reads. (`TestResponsePaths_EvidenceBeforeDestruction`)
3. **Panic-switch parity.** An armed `enforce.PanicSwitch` suppresses every
   backend on **both** paths — the daemon-wide kill switch cannot be bypassed by
   routing through one surface or the other. (`TestResponsePaths_PanicParity`)

### Action → backend map (the 1:1 that IS true)

| `decision.ActionPlan` field | legacy `Action` bit | `Engine.do*` |
|---|---|---|
| `Snapshot` | `ActionSnapshot` | `doSnapshot` |
| `Memscan` | `ActionMemScan` | `doMemScan` |
| `SuspendProcess` / `IsolateCgroup` | `ActionQuarantine` | `doQuarantine` |
| `BanRemoteIP` | `ActionNetBan` | `doNetBan` |
| `IsolateHost` | `ActionHostQuarantine` | `doHostQuarantine` |
| `RemediateFile` | `ActionRemediate` | `doRemediate` |
| `LockLocalUser` | `ActionLockUser` | `doLockUser` |
| `KillProcess` | `ActionKill` | `doKill` |
| (always, if configured) | `ActionWebhook` | `doWebhook` |
| `Delay`, `RequireStepUp`, `Tarpit` | — | deferred (no backend yet) |

Differences to be aware of when reasoning about the planner path:

- **MonitorMode / autobaseline gating live only on the legacy path.**
  `OnAlert` strips destructive actions under `monitor_mode` and under the
  autobaseline `baseline_observing` / `baseline_known` tags. `Executor.Execute`
  has no such gate — in active mode the *planner* is responsible for not
  emitting destructive plans during learning. Until the planner enforces those
  gates, `takeover.active=true` must not be combined with `monitor_mode`
  expectations.
- **Soft-enforce actions** (`Delay`, `RequireStepUp`, `Tarpit`) exist only on
  the plan; they have no legacy equivalent and are recorded as `Deferred`.

## Cutover criteria (legacy → planner)

Before `takeover.active=true` becomes a default, all of the following must hold:

1. Planner reproduces `monitor_mode` and autobaseline gating (no destructive
   plan during day-0 learning).
2. Shadow-mode logs show planner plans matching legacy policy decisions on real
   host traffic for the soak window (see `maturity_gate_dropper`).
3. The equivalence tests above stay green, extended to cover memscan and the
   soft-enforce backends once those land.
4. A single operator-visible "response posture" knob replaces the current
   `monitor_mode` + `takeover.active` pair, so there is one authoritative path.

Until then: **legacy `OnAlert` enforces; the planner watches.**
