# Production Trace Corpus

Canonical FP corpus for every detection-related change. No detection task
is considered complete unless it has been replayed against this trace and
the alert counts before/after are recorded in the task's commit message.

## Current corpus

| Trace | Host | Window | Lines | SHA-256 | Workload |
|---|---|---|---|---|---|
| `2026-05-27_to_2026-05-29_mail-nocgurus.jsonl` | mail.nocgurus.com (135.181.79.11) | 2026-05-27T20:23Z → 2026-05-29T14:19Z (42h) | 89239 | ef9284429e05ad21ad2c738810d91d82191f446fcc7b056c637ac5efeac0f56f | mail server with containers, JIT runtimes, and modern HTTP — representative of the workloads that produced the worst FP volume |

Storage location (this dev box (135.181.79.27)): `/var/lib/xhelix/replay-corpora/`
Not committed to git (too large). Re-fetch via:

    ssh root@135.181.79.11 'cat /var/log/xhelix/alerts.jsonl' \
      > /var/lib/xhelix/replay-corpora/2026-05-27_to_2026-05-29_mail-nocgurus.jsonl

```bash
# Verify integrity against the hash in the table above:
sha256sum /var/lib/xhelix/replay-corpora/2026-05-27_to_2026-05-29_mail-nocgurus.jsonl
# Must match the SHA-256 column. Mismatch = stale/tampered corpus; re-fetch.
```

## Truth labels

12 `alerts.jsonl` lines have been hand-labeled as **TRUE POSITIVES**. The raw lines are
preserved off-repo at `/var/lib/xhelix/replay-corpora/true_positives.jsonl`.
All 12 happened to fire the rule `brp.hard_deny` — the only class-1 rule with hits in
this trace — so the in-repo file contains exactly 1 unique rule ID.
The unique rule IDs touched by those lines are listed in `testdata/prod-trace/true_positive_rules.txt`.

Any detection change that suppresses `brp.hard_deny` is a TP regression and must be
justified explicitly in the commit message.

`true_positive_rules.txt` is line-delimited. Each non-blank, non-`#`-prefixed line is
a `Rule.ID` value exactly as it appears in `ruleset/core/*.yaml`. Tools should
`strings.Split(data, "\n")` and skip empty/comment lines.
