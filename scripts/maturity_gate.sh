#!/usr/bin/env bash
# maturity_gate.sh — read-only scorecard for the dropper-class maturity gate.
# Computes Gate 4 (triageable FP) from xhelix's own alerts.jsonl, and a Gate 3
# check (does any alert reference a seed marker). NO jq dependency (awk only),
# so it runs anywhere the log lives — including on prod over ssh.
#
# Usage:
#   scripts/maturity_gate.sh [alerts.jsonl] [seed-marker] [window-hours]
#   ssh root@HOST 'bash -s' < scripts/maturity_gate.sh        # run on prod
# Defaults: /var/log/xhelix/alerts.jsonl  (no seed)  24h
set -euo pipefail

LOG="${1:-/var/log/xhelix/alerts.jsonl}"
SEED="${2:-}"
WINDOW_H="${3:-24}"

[ -r "$LOG" ] || { echo "ERROR: cannot read $LOG" >&2; exit 2; }

# cutoff = now - window, as an ISO-8601 prefix string compare against event.time.
# Override with $GATE_CUTOFF (e.g. a deploy timestamp) to measure a precise span.
if [ -n "${GATE_CUTOFF:-}" ]; then
  CUTOFF="$GATE_CUTOFF"
else
  CUTOFF="$(date -u -d "${WINDOW_H} hours ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null \
          || date -u -v-"${WINDOW_H}"H +%Y-%m-%dT%H:%M:%S)"
fi

awk -v cutoff="$CUTOFF" -v seed="$SEED" '
BEGIN{
  noise["tls_no_sni"]=1; noise["tls_no_sni_from_webserver"]=1; noise["deleted_binary_running"]=1
}
{
  # event.time is the first "time":"..." on the line
  if (match($0,/"time":"[^"]+"/)) { t=substr($0,RSTART+8,RLENGTH-9) } else { t="" }
  if (t!="" && t < cutoff) next            # outside window
  total++
  if (match($0,/"rule_id":"[^"]+"/)) { rid=substr($0,RSTART+11,RLENGTH-12) } else { rid="-" }
  if (match($0,/"severity":[0-9]+/)) { sev=substr($0,RSTART+11,RLENGTH-11)+0 } else { sev=0 }
  if (match($0,/"comm":"[^"]*"/)) { comm=substr($0,RSTART+8,RLENGTH-9) } else { comm="-" }
  rulecount[rid]++
  if (rid in noise) { noisetot++; next }
  signaltot++
  if (sev>=2) {                              # triage stream: High/Critical, non-noise
    hi++
    ckey=rid"|"comm
    if (!(ckey in cl)) { cl[ckey]=0; rulecluster[rid]++ }  # new distinct (rule,comm) cluster
    cl[ckey]++
  }
  # Gate-3 seed hit
  if (seed!="" && index($0,seed)>0) { seedhits++; seedlines[NR]=rid }
}
END{
  nclusters=0; for(k in cl) nclusters++
  noisepct = (total>0)? (100.0*noisetot/total) : 0
  printf("=== xhelix maturity-gate scorecard ===\n")
  printf("window         : last %s h (cutoff %sZ)\n", "'"$WINDOW_H"'", cutoff)
  printf("alerts total   : %d\n", total)
  printf("noise (3 rules): %d  (%.1f%%)\n", noisetot+0, noisepct)
  printf("signal (non-noise): %d\n", signaltot+0)
  printf("--- GATE 4 (triageable FP) ---\n")
  printf("triage stream  : sev>=High & non-noise, deduped by (rule_id,comm)\n")
  printf("triage clusters: %d   [PASS if <= 50]  => %s\n", nclusters, (nclusters<=50?"PASS":"FAIL"))
  printf("triage alerts  : %d\n", hi+0)
  printf("--- top non-noise rules ---\n")
  # simple descending sort by count
  m=0; for(r in rulecount){ if(!(r in noise)){ rk[m]=r; m++ } }
  for(i=0;i<m;i++) for(j=i+1;j<m;j++) if(rulecount[rk[j]]>rulecount[rk[i]]){ tmp=rk[i]; rk[i]=rk[j]; rk[j]=tmp }
  for(i=0;i<m && i<15;i++) printf("  %7d  %s\n", rulecount[rk[i]], rk[i])
  printf("--- triage CLUSTERS by rule (distinct comms at sev>=High; this is what G4 counts) ---\n")
  p=0; for(r in rulecluster){ ck[p]=r; p++ }
  for(i=0;i<p;i++) for(j=i+1;j<p;j++) if(rulecluster[ck[j]]>rulecluster[ck[i]]){ tmp=ck[i]; ck[i]=ck[j]; ck[j]=tmp }
  for(i=0;i<p;i++) printf("  %4d clusters  %s\n", rulecluster[ck[i]], ck[i])
  if (seed!="") {
    printf("--- GATE 3 (seed self-detection) ---\n")
    printf("seed marker    : %s\n", seed)
    printf("alerts hitting seed: %d  => %s\n", seedhits+0, (seedhits>0?"DETECTED":"NOT DETECTED"))
    for(k in seedlines) printf("   line %d rule=%s\n", k, seedlines[k])
  }
}
' "$LOG"
