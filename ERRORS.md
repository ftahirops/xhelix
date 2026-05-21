# ERRORS.md

Project-specific bugs and gotchas that cost real time. Check before
proposing approaches in adjacent areas.

Each entry: what didn't work, what worked instead, note for next time.

---

## Daemon binary path is `/usr/local/bin/xhelix`, not `/usr/local/sbin/`

**What happened**: A new binary was built and deployed via
`sudo cp xhelix /usr/local/sbin/xhelix`. Daemon restart silently
re-ran the OLD binary because systemd's `ExecStart` points to
`/usr/local/bin/xhelix`. Took ~10 min to notice the version
string in logs still said the old commit hash.

**What works**: Deploy to `/usr/local/bin/xhelix`.

**Diagnostic**: `grep ExecStart /etc/systemd/system/xhelix.service`
and compare to the path you're copying to.

**For next time**: Whenever deploying a fresh build, the sequence is
`md5sum repo/xhelix /usr/local/bin/xhelix` before AND after the
copy. If the hash didn't change, the wrong path was used.

---

## FileSink rotation never landed before 0.0.2 — config knobs were a lie

**What happened**: `alerts.jsonl` grew to 3.8 GB on the live host
even though `xhelix.yaml` declared `rotate_size_mb: 100` and
`keep: 7`. The `pkg/alert.FileSink` had a TODO comment saying
"rotation lands in Phase 1" — that helper never landed. The config
fields were accepted at parse time and silently ignored at runtime.

**What works**: P-0.2 (`025a88e`) implemented size-bounded rotation
with an atomic byte counter, seeded from existing file size at open.
Active file is renamed `.1`, existing `.N → .N+1`, `.keep` deleted.

**For next time**: When adding a config knob to ANY sink/exporter,
verify the value is actually consumed by the runtime — search for
the field name in the code, not just confirm parsing accepts it.
Treat unused config fields as bugs.

---

## `geoip.Result.ASN` is a string `"AS64500"`, not a uint32

**What happened**: `pkg/adminguard` (P-B.0b) was designed assuming
ASN was a numeric type, with `allowed_asns: []uint32` in YAML. Build
failed because the existing `pkg/geoip` Provider returns
`Result.ASN` as a string in canonical `"AS<number>"` form.

**What works**: Use string ASN throughout adminguard, store
allowed ASNs in `map[string]struct{}`, uppercase on insert + lookup.

**For next time**: When integrating with an existing package, read
its types BEFORE designing the consumer. `grep -n "^type" pkg/<x>/*.go`
is a 5-second check that saves an hour.

---

## `pkg/lineage.Store` was concurrency-unsafe through P1.2

**What happened**: The Store mutated `origins map[LineageID]Origin`
in `Put` / `SweepOlderThan` and read it in `Get` / `Size` with no
synchronization. The sweep goroutine in `foundation.go` raced the
LocalAPI snapshot handler reading `Size()`. Latent — only surfaced
when a 100-goroutine torture test was added in P7.1.2.

**What works**: `sync.RWMutex` on every Store method (added in
`43c5acf`). Test `TestStore_ConcurrentTaintWrites` is the regression.

**For next time**: When a package has a `sync.Mutex`-shaped problem
("read by N consumers, written by M goroutines, no lock"), add the
lock immediately. Don't wait for a race-detector test to surface it.

---

## "Bench Lookup is sub-µs" did not mean "Lookup is sub-µs on the hot path"

**What happened**: `canonical.ReadProcKey` benchmarks at 9.5 µs cold.
That sounds fast in isolation. But on a 50k-event/sec dispatch loop,
9.5 µs × 50 000 = 475 ms/sec of CPU just on /proc reads — the whole
pipeline is gated on that.

**What works**: P2.0 (`fd5bc7a`) added `pkg/canonical.ProcKeyCache`.
Warm hit is 49 ns — 190× faster — and any non-pathological event
stream hits the cache.

**For next time**: A bench number is only meaningful in context of
the rate at which it'll be called. Multiply bench cost by expected
QPS before claiming "fast enough".

---

## `hot.db` grew to 14 GB — retention config exists, pruner does not

**What happened**: `/var/lib/xhelix/hot.db` reached 14 GB on a single
host. xhelix.yaml correctly declared
`storage.hot.retention_hours: 24` and `storage.hot.max_size_mb: 2048`
but neither was enforced at runtime. Filesystem was at 87% capacity
on a 100 GB volume; one more day would have filled it.

**Root cause**: `pkg/store.HotStore` exposes a `Prune(cutoffNs)`
method but **no goroutine calls it**. The only `Prune()` call in
`cmd/xhelix/run.go:2222` operates on the *history* store
(`pkg/store/history.Store`), not `HotStore`. The two are different
types; the daemon prunes one and ignores the other.

This is the SECOND occurrence of the "config knob accepted but not
consumed" class of bug. The first was FileSink rotation. Same shape:
operator reads config, sees retention/cap, assumes enforcement,
no error message at startup says otherwise.

**What works**: Set `storage.hot.path: ""` to fall back to
`:memory:` (existing fallback in run.go:131). Delete the on-disk
files. Restart. 14 GB reclaimed in seconds.

**For next time**:
1. When adding a config field, search for its consumer the same
   way ERRORS.md says to search for unused config knobs. If no
   consumer exists, the field is a lie.
2. Daemon should refuse to start if a config knob is declared
   but no consumer is registered. This needs a `config.MustBeConsumed`
   audit step at startup.
3. Hot store needs a periodic pruner goroutine wired the same
   way the history pruner is. Roadmap task.

Commit: 66b9c2e session — fix applied via config disable, root cause
fix tracked as a roadmap follow-up.

---

## `cold.db` 4.3 GB and growing (related)

**What happened**: `pkg/coldstore` (P2.3, shipped `daa6aeb`) creates
per-day partition tables and inserts events forever. No old-day
pruning. After ~1 day of dispatch wiring, 4.3 GB.

**What works**: not yet — `cold.db` is load-bearing for current
investigations so deletion is risky. Acceptable in the short term
because cold.db's growth rate (~4 GB/day at observed event rates)
won't fill the disk for ~7 days, but a proper fix is:

1. Per-day partition table → `DROP TABLE events_YYYYMMDD` for
   any day older than `retention_days`. Implementation is a
   one-liner extension to `pkg/coldstore.Sweep()`.
2. Default retention: 14 days for the cold store, configurable.
3. Off-host mirror to S3 Object Lock (P-CJ.10) takes the
   long-term durability burden off local disk.

Tracked as a new roadmap task in P-FT/P-CJ. Until fixed, operators
should monitor disk usage of `/var/lib/xhelix/cold.db`.

**For next time**: every persistent store added to xhelix must
have an explicit retention test in CI that confirms the store
shrinks (or maintains a bounded size) when the pruner runs.

---

## Format for new entries

```markdown
## <one-line title>

**What happened**: <concrete description, what time it cost>

**What works**: <fix, with commit hash if shipped>

**For next time**: <generalizable lesson — what to check / do differently>
```

---

## xhelix SIGSTOP'd the operator's own shell (memfd self-DoS)

**What happened**: Live-attack demo with all sensors enabled. Response
engine fired `memfd_run_pattern` → ActionQuarantine on every new bash
spawned by Claude Code (Claude's runtime exec's bash via memfd_create
+ execveat, so `image == /proc/self/fd/N`). Every CLI invocation got
SIGSTOPped before printing a single byte. Also fired
`mem_mprotect_rwx` on node, python, runc, java for normal JIT — all
SIGSTOPped. Operator could not run `pkill xhelix` from the agent
shell because that shell itself was quarantined. Cost: ~45 min and
required a separate SSH session to recover.

Same operator config had `response.enabled: true` (intent: monitor
mode), but ActionQuarantine ran anyway — the engine had no
observe-only mode wired. The runbook in `scripts/test-setup.sh`
*comments* claimed monitor semantics but the code path delivered
enforce.

**What works** (P-PS.23):

1. `pkg/response/policy.go`: removed `ActionQuarantine` from
   `memfd_run_pattern` and `mem_mprotect_rwx` defaults. Both fire on
   legitimate runtimes (V8/Node, HotSpot, .NET, LuaJIT, BPF JIT,
   Python runpy, Docker BuildKit, Claude Code, Buildkite, snapd) —
   the FP rate is too high to justify a SIGSTOP default. Kept Log +
   Snapshot + MemScan so real fileless payloads are still triagable.
2. `ResponseConfig.MonitorMode bool` + `response.Config.MonitorMode`
   + `Engine.monitorMode`. When true, `OnAlert` masks every alert to
   `ActionLog | ActionWebhook` BEFORE dispatch, regardless of policy.
3. `scripts/test-setup.sh` writes `response.monitor_mode: true` in
   the generated YAML.

**For next time**:

- Any rule whose match expression can fire on a legitimate userland
  runtime must NOT have `ActionQuarantine` or `ActionKill` in its
  default policy. Triage criterion: would the worst-case FP STOP a
  production process? If yes, log-only by default. Operator opts in
  per-rule once they've audited their workload.
- "Monitor mode" must be a single config flag that short-circuits
  the dispatch path. Documentation-only "monitor mode" (comments in
  a setup script) is a lie until it's a `MonitorMode bool` the
  engine actually reads.
- Before enabling the response engine on a live host, search policy
  defaults for `ActionQuarantine|ActionKill` and confirm each rule
  fires only on attacker behavior, not common-runtime behavior. Run
  `grep -E 'Action(Quarantine|Kill)' pkg/response/policy.go` as a
  pre-deploy checklist.
- Recovery procedure when self-DoS hits: separate SSH session →
  `sudo pkill -9 -f xhelix` → `for p in $(ps -eo pid,stat | awk
  "\$2~/T/{print \$1}"); do kill -CONT $p; done` to release SIGSTOP'd
  victims.
