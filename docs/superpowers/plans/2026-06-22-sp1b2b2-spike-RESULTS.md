# SP-1b.2b.2 Mechanism Spike — RESULTS (2026-06-22)

**Run on:** dev box `135.181.79.27`, against a throwaway redis instance
(`xhelix-redis-spike.service`, port 6390, no data). **Prod redis-server.service
(5004 keys) was never touched and verified intact before/after.** Spike unit
fully removed at the end.

## Environment (Phase 0)
- **systemd 255** (255.4-1ubuntu8.16) — note: in the #34773 affected band.
- kernel **6.8.0-124-generic**, **cgroup v2** (`cgroup2fs`) confirmed → IPAddress BPF filtering available.

## Phase 1 — does a static egress drop-in enforce? **YES**
With `IPAddressAllow=localhost link-local 1.1.1.1/32` + `IPAddressDeny=any` on the unit:
- Outbound to **1.1.1.1:443 (allowed)** → connect **succeeded** (redis `Non blocking connect for SYNC fired` + HTTP reply).
- Outbound to **8.8.8.8:443 (denied)** → **`Timeout connecting to the MASTER`** — the SYN is **packet-dropped** by the cgroup filter (NOT an EPERM; the connect just never completes).

**This is the first live proof that SP-1b.1 / SP-1b.2a egress drop-ins actually enforce on a real unit.** Signal used throughout: connect-success(+HTTP) = allowed; `Timeout` = blocked.

## Phase 2/3 — live update of a RUNNING unit, no restart

| Mechanism | GROW (add IP) | SHRINK (remove IP) | Restart? | Verdict |
|---|---|---|---|---|
| **A — `systemctl set-property --runtime IPAddressAllow=…`** | n/a (failed first) | n/a | no | **REJECTED** — see below |
| **B — rewrite config drop-in + `systemctl daemon-reload`** | ✅ live (8.8.8.8 Timeout→connect) | ✅ **live** (1.1.1.1 connect→Timeout) | **no** (MainPID `2506265` stable throughout) | **WINNER** |

**Mechanism A rejected — two concrete failures observed:**
1. `set-property` **does not accept the `localhost` / `link-local` tokens**: `Failed to parse IP address prefix: localhost`. It requires literal CIDRs only (`127.0.0.0/8 ::1/128 169.254.0.0/16 fe80::/64`).
2. The documented "reset first" workaround (`IPAddressAllow=` empty) at runtime **resets the COMBINED list — it undoes the config drop-in's always-allowed entries too**, leaving the unit with an empty allow-set + `IPAddressDeny=any` = everything (incl. loopback) blocked until repaired.

**Mechanism B confirmed live in BOTH directions** — including the make-or-break **shrink** — with **no restart** (process kept the same MainPID). `daemon-reload` re-applies the unit's `IPAddress*` cgroup BPF program to the already-running cgroup.

## DECISION → unblocks the SP-1b.2b.2 `Applier`

**`egressrefresh.Applier` = rewrite-drop-in + `daemon-reload` (Mechanism B).** Live shrink works on this host, so the grace-window design is viable via systemd — **do NOT escalate to SP-1b.3** for this capability.

**Design constraints carried into the SP-1b.2b.2 implementation plan:**
1. **Own a SEPARATE dynamic-egress drop-in file.** systemd combines drop-ins, so the refresher should write its full computed allow-set to e.g. `51-egress-dynamic.conf` (a distinct file from the arm-time `50-…`/seccomp/apparmor drop-in) and `daemon-reload`. This way the refresher never has to re-render seccomp/AppArmor — it owns one file. (Because lists *combine*, the dynamic file should carry the COMPLETE allow-set — `localhost link-local` + static CIDRs + dynamic IPs — and the arm-time drop-in should NOT also list egress allows, or the two would union and shrink would be impossible. Decide ownership: either the dynamic file is the *sole* egress source, or it uses an empty-reset line first.)
2. **`daemon-reload` is the apply primitive** — not `set-property`. Wrap it in `contractarm.Armorer.Runner` (already `func(args...string) error`; add an `Armorer` method like `ApplyEgress(unit string, allowCIDRs []string) error` that writes the dynamic drop-in + reload).
3. **Tokens are fine in drop-in files** (config drop-ins expand `localhost`/`link-local`); literal CIDRs are only required for `set-property`, which we're not using.
4. **Reload cost:** `daemon-reload` is global (re-reads all units). At the refresher's 5-min cadence this is fine; do not reload per-FQDN — batch all changed units into one reload per tick.
5. Carry the SP-1b.2b.1 review carry-forwards: explicit empty-set guard (never apply an empty set unless the unit previously had a non-empty one — an empty dynamic file = total egress lockdown), and evict `lastSet` on `Forget`.

## Next step
Write the SP-1b.2b.2 implementation plan (a normal TDD plan) for the Mechanism-B `Applier` + swapping the shadow `LogApplier` for it behind a config-gated promotion (observe→enforce), per the design constraints above. Promotion to live should stay opt-in and default-off.
