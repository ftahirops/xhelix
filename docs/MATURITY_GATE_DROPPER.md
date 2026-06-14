# Maturity Gate — Dropper-class self-detection + triageable FP

Status target tracked across sessions. This is the **one measurable gate**
we agreed to drive toward instead of calendar promises (see memory
`no_manual_detection`, `behavioral_defense`). It has two halves; both must
pass on **prod**, measured from xhelix's **own outputs** (never by manual
grep-hunting).

Tracker: `scripts/maturity_gate.sh` — read-only over `/var/log/xhelix/alerts.jsonl`.
Run it to refresh the scorecard. Record each run's numbers in the log table below.

---

## Gate 3 — engine self-detects the WordPress-dropper class

The engine must flag a *seeded* instance of the attack class **by itself**,
without anyone grepping the box.

**Seed (controlled, benign, only on an explicit "yes" — touches prod):**
On a designated **test vhost**, reproduce the host-observable shape of the
dropper as the web worker (php-fpm / www-data):
1. Write a harmless marker PHP into a docroot:
   `…/<testvhost>/httpdocs/wp-content/uploads/xhelix-gate-<unixts>.php`
   content: `<?php /* xhelix maturity-gate seed — harmless */ echo 0;`
2. (optional) one outbound HTTPS from php-fpm to a benign host it has never
   contacted before (new-endpoint half).

**PASS** = within the latency budget (≤ ~3h, conservative tune), xhelix's own
alert stream contains an alert **attributable to the seed**, found by the
tracker via the `xhelix-gate-<ts>` marker — *preferably*
`baseline.behavioural_deviation` whose `new_file_writes` contains the seed
path (proves behavioural generalization), or at minimum `fim.drift` /
`webdrop` on the seed path.

**Known prerequisites** (the first attempt will likely FAIL on these — that is
the gap this gate exists to expose, not a surprise):
- FIM must watch `/var/www/vhosts/**` (was unconfigured on prod).
- The aggregator must receive php-fpm file-write events for the test binary.
- php-fpm's baseline must be warm (past `warmup_hours`).

**Cleanup:** delete the seed file; revert any test-only config.

---

## Gate 4 — triageable false-positive volume

A human must be able to read one day's *actionable* alerts.

**Noise rules** (high-volume, low-actionability — must be gated/sampled out of
the triage stream, not counted as signal):
`tls_no_sni`, `tls_no_sni_from_webserver`, `deleted_binary_running`.

**Triage stream** = alerts with `severity >= High (2)` AND `rule_id ∉ noise`,
deduped into clusters by `(rule_id, comm)`.

**PASS target:** ≤ **50 triage clusters / 24h**. (Threshold is a judgement —
tune it with the user; the tracker prints raw numbers so it can be adjusted.)
Also reported: total/24h, noise share %, signal/24h.

---

## Tracking log

| Date (UTC) | Host | Total/24h | Noise % | Triage clusters/24h | G4 pass? | G3 seed result | Notes |
|---|---|---|---|---|---|---|---|
| 2026-06-05 | plesk.douxl.com (65.x) | 36869 | 88.1% | 86 | FAIL (≤50) | not yet seeded | baseline. Next FP tier: credbroker.plaintext_read(491), cred_proc_scrape(477), mem_new_rwx_mapping(455). baseline.behavioural_deviation=0 (warm-but-quiet). |
| 2026-06-05 | (projected, NOT measured) | — | — | ~40 | PROJECTED PASS | n/a | FP tuning landed in repo (procscrape allowlist + spawn_burst→Warn). MUST deploy + re-run scripts/maturity_gate.sh on prod to confirm — projection is not a measurement. |
| 2026-06-05 20:32Z | prod-1 65.x | (deployed) | — | early:4 | inconclusive (sample too small) | n/a | FP-tuned binary DEPLOYED + healthy (0 restarts). Early since-deploy read (27 alerts/6min) = 4 clusters all verdict.incident. Real measurement queued for ~75min post-deploy (need cron/systemctl cycle). Clean 24h-comparable read at +24h (≈2026-06-06 20:32Z). Use GATE_CUTOFF=<deploy-ts> with tracker. |
| 2026-06-05 21:48Z | prod-1 65.x (75min sample) | 207 | 0%* | 6 | PASS (≤50) | n/a | MEASURED since-deploy. 6 clusters, all verdict.incident. CONFIRMED: zero raw process_spawn_burst (now Warn) and zero benign cred_proc_scrape (systemd/filwrpr/imunify/needrestart allowlisted); php/agetty survive only inside verdict.incident composites (correct — detection preserved). *CAVEAT: small off-peak sample, ~no tls_no_sni traffic → noise% not representative. Definitive 24h read at +24h. |
| 2026-06-06 20:32Z | prod-1 65.x (definitive 24h, GATE_CUTOFF=2026-06-05T20:32:48) | 5660 | 0%* | 10 | **PASS** (≤50) | not seeded | DEFINITIVE 24h measurement. 10 clusters, all verdict.incident. Cluster breakdown: php-fpm×3247 (tls_no_sni accumulation into scorer — FP, see note), sw-engine-fpm×111 (credbroker.plaintext_read — Plesk updater, likely FP), php×32 (cred_proc_scrape+tls_no_sni), agetty×24 (deleted_binary_running — known FP), -×23 (removed/anon), sw-engine×18 (spawn_burst+tls_no_sni), https×2. *noise% zero because tls_no_sni individual alerts aren't appearing directly — they're being accumulated by the verdict.incident scorer instead (design gap: noise signals still feed scorer). |
| 2026-06-07 11:13Z | prod-1 65.x (rolling 24h) | 3455 | 0%* | 7 | **PASS** (≤50) | not seeded | Rolling 24h check confirming stability. 7 clusters, same composition. G4 holds under full traffic load. |
