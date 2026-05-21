# xhelix Soak Harness — 30-day reference-workload procedure

The single test that determines whether xhelix is enforce-safe on a
real workload. Procedure for **PF-04** (TEST_PLAN.md §9), **30-day
no-SIGSTOP-on-legit** soak, plus the **90-day** operator-labelling
campaign that drives the six-nine FP-rate claim (ALERTS_AND_FP_PLAN
§2, §11).

This is operational doctrine — execution requires a reference host
and 30 days of wall time. The code that makes it executable is
already in tree (P-PS.29). This document captures the harness +
acceptance criteria.

---

## 1. Reference workstation profile

Pick ONE host that mirrors a production target. The soak result is
only valid for workloads similar to this host's profile.

| Profile | Composition |
|---|---|
| **dev_workstation** | node + python + docker + git + IDE + chat client. Operator typing. |
| **prod_web** | nginx + PHP-FPM (or gunicorn/uwsgi). Sustained HTTP requests. |
| **prod_db** | Postgres + WAL replication. Mostly idle, periodic vacuum. |
| **ci_runner** | github/gitlab/buildkite agent + docker + git + build toolchains. |
| **k8s_node** | containerd + kubelet + many container restarts. |

Run **one host per profile** in parallel. Each host's soak result is
specific to its profile — operators reuse the profile that matches
their target.

---

## 2. Pre-flight checklist

Before starting the 30-day window:

```sh
# 1. Latest binaries
make build && sudo install -m 0755 xhelix xhelixctl xhelix-watchdog /usr/local/bin/

# 2. Wire monitor mode + FileSink (already default in test-setup.sh)
sudo bash scripts/test-setup.sh

# 3. Wire watchdog under systemd
sudo tee /etc/systemd/system/xhelix-watchdog.service <<'EOF'
[Unit]
Description=xhelix independent chain + alert-sink verifier
After=xhelix.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xhelix-watchdog \
    --once \
    --pid /run/xhelix/xhelix.pid \
    --socket /run/xhelix/xhelix.sock \
    --alerts /var/log/xhelix/alerts.jsonl \
    --chain /var/lib/xhelix/chain \
    --pub-file /etc/xhelix/chain.pub.hex \
    --alarm-log /var/log/xhelix/watchdog.jsonl
EOF
sudo tee /etc/systemd/system/xhelix-watchdog.timer <<'EOF'
[Unit]
Description=Run xhelix-watchdog every 5 min

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now xhelix-watchdog.timer

# 4. Confirm posture
xhelixctl status
xhelixctl posture lsm
xhelixctl alerts stats --since 1h  # baseline noise
```

The soak BEGINS at the moment posture is recorded; the END is
exactly 30 × 24h later. Log the start time in
`tests/redteam/soak-START.txt`.

---

## 3. What we measure

### 3.1 Hard pass/fail (PF-04)

| # | Metric | Threshold |
|---|---|---|
| 1 | Number of legitimate processes SIGSTOPped | 0 |
| 2 | Number of legitimate accounts locked | 0 |
| 3 | Number of legitimate IPs banned | 0 |
| 4 | Number of legitimate files remediated | 0 |
| 5 | Daemon uptime | > 99.9% (max ~43min/30d downtime) |
| 6 | watchdog alarms — chain-verify-failed | 0 |
| 7 | watchdog alarms — alerts-stale | 0 |
| 8 | Disk growth `/var/lib/xhelix` | < 5 GB cumulative |
| 9 | RSS growth (rolling 7-day) | ≤ 15 % |

Any single failure fails the soak.

### 3.2 FP-rate measurement (ALERTS_AND_FP_PLAN §2)

Daily operator triage:

```sh
# Each day, pick 20 random alerts not yet labelled
xhelixctl alerts ls --since 24h --limit 100 \
    | shuf | head -20

# Label each manually:
xhelixctl alerts label <event-id> --verdict {tp|fp|benign} \
    --tag <free-text> --notes <optional>
```

Weekly rollup:

```sh
xhelixctl alerts fp-rate --since 7d
```

Acceptance ladder (per ALERTS_AND_FP_PLAN §2):

| Phase | Target FP rate | Sufficient labels |
|---|---|---|
| α | ≤ 5 × 10⁻² | 100 |
| β | ≤ 1 × 10⁻³ | 500 |
| γ | ≤ 1 × 10⁻⁴ | 2,000 |
| δ | ≤ 1 × 10⁻⁶ | 30,000 (≈ 30 days × 1k/day) |
| ε (six-nine) | ≤ 1 × 10⁻⁷ | 90,000 (≈ 90 days × 1k/day) |

The 30-day window targets δ — δ being the precondition for the
six-nine claim that needs the 90-day extension.

---

## 4. Daily cron (the operator's checklist)

```sh
# /etc/cron.daily/xhelix-soak
#!/bin/bash
set -u

DATE=$(date -u +%Y-%m-%d)
SOAK_DIR=/var/log/xhelix/soak/$DATE
mkdir -p $SOAK_DIR

# 1. Counters snapshot
xhelixctl status              > $SOAK_DIR/status.txt
xhelixctl alerts stats --since 24h > $SOAK_DIR/stats.txt
xhelixctl alerts stats --since 24h --by comm > $SOAK_DIR/by-comm.txt
xhelixctl takeover lineages --since 24h --top 20 > $SOAK_DIR/lineages.txt

# 2. Daemon uptime + RSS
ps -o etime,rss,vsz -p $(cat /run/xhelix/xhelix.pid) > $SOAK_DIR/proc.txt

# 3. Disk usage
du -sh /var/lib/xhelix /var/log/xhelix > $SOAK_DIR/disk.txt

# 4. Any quarantine/remediate/netban/lockuser actions?
grep -aE 'response: (quarantined|killed|banned|remediated|locked)' \
    /var/log/xhelix/xhelix.out \
    | awk -v cutoff="$(date -d '24 hours ago' '+%Y-%m-%dT%H:%M:%S')" \
        '$1 >= cutoff' > $SOAK_DIR/destructive.txt

# 5. Watchdog alarms
[ -f /var/log/xhelix/watchdog.jsonl ] && \
    tail -100 /var/log/xhelix/watchdog.jsonl > $SOAK_DIR/watchdog.txt

# 6. Operator triage queue — random 20 alerts to label
xhelixctl alerts ls --since 24h --limit 200 | shuf | head -20 > $SOAK_DIR/triage-queue.txt

# 7. Sound an alarm if hard-fail thresholds tripped
if [ -s $SOAK_DIR/destructive.txt ]; then
    logger -p user.warn "xhelix soak: destructive action observed today — review $SOAK_DIR/destructive.txt"
fi
```

---

## 5. Weekly report

Run on day-7, day-14, day-21, day-30:

```sh
WEEK=$1   # 1..4
DEST=/var/log/xhelix/soak/week-$WEEK
mkdir -p $DEST

xhelixctl report --since 168h --format html > $DEST/week-$WEEK.html
xhelixctl alerts fp-rate --since 7d > $DEST/fp-rate.txt
xhelixctl alerts stats --since 7d --by rule > $DEST/rules.txt

# Per-rule labels:
xhelixctl alerts fp-rate --since 7d \
    | awk 'NR>2 && $5+$6 > 0 {printf "%s\t%.2f\n", $1, $3*100/($2+$3+$4)}' \
    > $DEST/per-rule-fp-pct.tsv
```

The HTML report is the artefact for stakeholder review.

---

## 6. Acceptance ceremony (day 30)

```sh
# Final snapshot
xhelixctl report --since 720h --format html > /srv/lab/results/SOAK-FINAL.html

# Chain integrity end-to-end
xhelix-verify --chain /var/lib/xhelix/chain --pub <hex>

# Cumulative counters
echo "Destructive actions in 30d (must be 0):"
grep -ac 'response: (quarantined|killed|banned|remediated|locked)' \
    /var/log/xhelix/xhelix.out

echo "Watchdog alarms in 30d (must be 0):"
wc -l /var/log/xhelix/watchdog.jsonl 2>/dev/null

echo "Total labels accumulated:"
sqlite3 /var/lib/xhelix/labels.db 'SELECT COUNT(*) FROM labels'
```

Promote to enforce mode ONLY if every hard-fail metric is zero AND
operator-labelled FP rate is below the target for the host's
phase. Otherwise: investigate the failure, fix it, **restart the
30-day clock**.

---

## 7. What we do during operator-labelling (the 90-day path)

Days 31–120: continue daily triage. Goal is 90,000+ labels.

```sh
# Once the alerts label db is big enough to be useful:
xhelixctl alerts replay --since 7d --rules ruleset/core
# → shows which labelled FPs are still firing under current rules.

# Rule tuning per ALERTS_AND_FP_PLAN §6:
#   1. pick a (rule, tag) with highest FP count
#   2. hypothesise an allowlist or match-tightening
#   3. edit ruleset/core/<file>.yaml
#   4. xhelixctl alerts replay --since 30d
#   5. confirm: FPs eliminated, TPs unchanged
#   6. ship rule update, restart xhelix
#   7. repeat
```

Document each rule edit in `tests/redteam/RULE_TUNING.md`
(per-rule changelog) so the regression list grows over time.

---

## 8. Failure-mode runbook

| Symptom | First action |
|---|---|
| daemon dies | journalctl -u xhelix --since '5 min ago'; look for panic; restart; if recurs, downgrade binary one version |
| watchdog alarms `alerts-stale` | check `ls -la /var/log/xhelix/alerts.jsonl` mtime; investigate file-sink (GAP-140 class) |
| watchdog alarms `chain-verify-failed` | DO NOT RESTART. Preserve `/var/lib/xhelix/chain/` for forensic. Investigate from off-host backup |
| disk runaway | re-confirm retention configured (cold.db pruner from #154) |
| FP rate stays > target | identify top noisy (rule, tag) via `alerts fp-rate`; tighten allowlist |
| destructive action on legit pid | bug — open ticket; downgrade rule's action mask to log-only immediately |

---

## 9. Status

| Component | State |
|---|---|
| Daily cron template | here, not yet installed on any host |
| Weekly report generator | already shipped (xhelixctl report) |
| Acceptance ceremony commands | here |
| Watchdog service unit | template here |
| Labels store | shipped (pkg/labels P-PS.29) |
| Replay tool | shipped (xhelixctl alerts replay P-PS.29) |
| Off-host chain mirror push | shipped abstraction (pkg/chainmirror P-PS.30); receiver pending |
| Reference host | NOT YET CHOSEN — operator picks |

**Execution unlock: 30 days from operator picking a host and pressing go.**
