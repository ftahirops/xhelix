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

## Format for new entries

```markdown
## <one-line title>

**What happened**: <concrete description, what time it cost>

**What works**: <fix, with commit hash if shipped>

**For next time**: <generalizable lesson — what to check / do differently>
```
