# SP-1b.2b.2 — Systemd Live-Egress-Update Mechanism Spike (Runbook)

> **This is a SPIKE, not a code plan.** Its output is a *decision*, not a
> merge. No `Applier` code is written until this spike resolves which
> mechanism (if any) updates a **running** unit's `IPAddressAllow` filter
> live on this host's systemd version — and specifically whether it can
> **shrink** the allow-set live (the FP-critical case the grace-window
> design depends on).

**Goal:** Empirically determine, on the dev box, whether the egress allow-set
of an *already-running* systemd unit can be updated **without a restart**, for
both **grow** (add an IP) and **shrink** (remove an IP), via either:
- **(A)** `systemctl set-property --runtime <unit> IPAddressAllow=…` (transient layer over a minimal config drop-in), or
- **(B)** rewriting the config drop-in + `systemctl daemon-reload`.

The result picks the concrete `egressrefresh.Applier` for the live slice — or, if live-shrink is impossible via systemd on this host, escalates the live-refresh capability to **SP-1b.3** (nftables-per-cgroup / cgroup-BPF), which the SP-1b.2b.1 review and the SP-1b.2 grounding already flagged as the fallback.

## Why this spike exists (the unresolved facts)

- **Verified (systemd.resource-control(5)):** `IPAddressAllow=` lists from multiple drop-ins **combine**; an **empty `IPAddressAllow=` resets** the list.
- **Unverified:** the man page does **not** state resource-control changes apply to an already-running unit without restart.
- **Known fragility:** systemd issue [#34773](https://github.com/systemd/systemd/issues/34773) — `set-property IPAddressAllow=` list handling regressed between systemd 249 and 256 (entries dropped); "reset first" workaround.

Because **combine + reset** is the documented semantic, mechanism (A) only works for shrink if the *entire dynamic allow-set lives in the transient layer* (so a smaller transient list isn't unioned with a larger config grant). The spike tests exactly that.

---

## ⚠️ SAFETY — read before running anything

- **Dev box ONLY** (`135.181.79.27` — this machine). **NEVER prod** (`65.108.246.67`).
- **Throwaway unit ONLY.** Everything operates on a unit named `xhelix-egress-spike.service` that this runbook creates and destroys. **Never** touch `xhelix.service`, `sshd`, `nginx`, a database, or any real service — applying `IPAddressDeny=any` to a real service can sever its network and (for sshd) lock you out.
- **Hard-stop authorization:** every step here runs `sudo` against systemd (`systemctl`, writing unit files under `/etc/systemd/system/`, `daemon-reload`). Per the working agreement these are hard stops. Run them **only** on an explicit "yes, run the spike" in the current turn. This runbook is the procedure; executing it is a separate authorization.
- The test unit makes outbound TCP to `1.1.1.1:443` and `8.8.8.8:443` (public resolver IPs) in a loop — harmless, and the point (it's how we observe enforcement). Cleanup (Phase 5) removes everything.

---

## Phase 0 — Environment facts (read-only, safe)

Record these first; they bound what's even possible.

```bash
systemctl --version | head -1          # systemd version (relative to #34773: 249 vs 256+)
uname -r                               # kernel
stat -fc %T /sys/fs/cgroup             # expect "cgroup2fs" — IPAddress* needs unified cgroup v2 + BPF
zgrep -h CONFIG_CGROUP_BPF /proc/config.gz 2>/dev/null || echo "config.gz unavailable (ok)"
```

**Record:** systemd version = ____ ; cgroup2 = (yes/no) ____. If not cgroup2, IPAddress filtering is unavailable → stop, the whole systemd approach is moot on this host (go straight to SP-1b.3).

---

## Phase 1 — Baseline: does a static egress drop-in even enforce?

This also live-validates SP-1b.1 / SP-1b.2a enforcement, which has never been tested on a real unit.

**1a. Create the throwaway tester unit** (a loop that reports reachability of an allowed vs denied IP to the journal):

```bash
sudo tee /etc/systemd/system/xhelix-egress-spike.service >/dev/null <<'EOF'
[Unit]
Description=xhelix egress mechanism spike (throwaway)
[Service]
ExecStart=/bin/bash -c 'while true; do for ip in 1.1.1.1 8.8.8.8; do if timeout 3 bash -c "echo > /dev/tcp/$ip/443" 2>/dev/null; then echo "$ip OK"; else echo "$ip BLOCKED"; fi; done; sleep 2; done'
EOF
```

**1b. Add the egress drop-in** — mirrors what `contractarm.EgressDirectives` writes (localhost + link-local always allowed; one real allowed IP; deny the rest):

```bash
sudo mkdir -p /etc/systemd/system/xhelix-egress-spike.service.d
sudo tee /etc/systemd/system/xhelix-egress-spike.service.d/50-egress.conf >/dev/null <<'EOF'
[Service]
IPAddressAllow=localhost link-local 1.1.1.1/32
IPAddressDeny=any
EOF
sudo systemctl daemon-reload
sudo systemctl start xhelix-egress-spike.service
```

**1c. Observe** (run in a second shell, keep it open through all phases):

```bash
journalctl -u xhelix-egress-spike.service -f -o cat
```

**EXPECT (baseline pass):** steady `1.1.1.1 OK` and `8.8.8.8 BLOCKED`.

**Record:** baseline enforces = (yes/no) ____. If `8.8.8.8 OK` (deny not enforced), egress drop-ins don't work on this host at all → SP-1b.1/2a are not actually enforcing; that's a **critical separate finding** — stop and report it.

---

## Phase 2 — Live GROW without restart

Add `8.8.8.8` to the allow-set on the running unit; watch the journal for `8.8.8.8` flipping `BLOCKED → OK` **with no restart**. Note the unit's `MainPID` first (`systemctl show -p MainPID xhelix-egress-spike` — confirm it does NOT change across each step).

**2A. Mechanism A — set-property --runtime (transient):**

```bash
# Per the man page, reset then set (the #34773 "reset first" workaround):
sudo systemctl set-property --runtime xhelix-egress-spike.service IPAddressAllow=
sudo systemctl set-property --runtime xhelix-egress-spike.service IPAddressAllow="localhost link-local 1.1.1.1/32 8.8.8.8/32"
systemctl show -p IPAddressAllow xhelix-egress-spike.service   # what systemd now believes
# Watch journal ~10s. MainPID unchanged?
```

**EXPECT to learn:** does `8.8.8.8` flip to `OK` live? Does `set-property --runtime` *combine* with the config drop-in (so it grew) or did the reset interact badly (#34773)?

**2B. Mechanism B — drop-in rewrite + daemon-reload:**

```bash
# First clear the runtime override from 2A so it doesn't mask the result:
sudo rm -f /run/systemd/system.control/xhelix-egress-spike.service.d/*.conf 2>/dev/null
sudo systemctl daemon-reload
# Rewrite the CONFIG drop-in to include 8.8.8.8, then reload:
sudo tee /etc/systemd/system/xhelix-egress-spike.service.d/50-egress.conf >/dev/null <<'EOF'
[Service]
IPAddressAllow=localhost link-local 1.1.1.1/32 8.8.8.8/32
IPAddressDeny=any
EOF
sudo systemctl daemon-reload
# Watch journal ~10s. MainPID unchanged?
```

**EXPECT to learn:** does `daemon-reload` (no restart) re-apply the grown filter to the running cgroup?

**Record (grow):** A live-applies = (yes/no) ____ ; B live-applies = (yes/no) ____ ; MainPID stable = (yes/no) ____.

---

## Phase 3 — Live SHRINK without restart (THE make-or-break)

Remove `1.1.1.1` from the allow-set on the running unit; watch for `1.1.1.1` flipping `OK → BLOCKED` **with no restart**. Shrink is the FP-critical case: the grace-window design exists to shrink *gracefully*, so if shrink can't apply live at all, the whole live-refresh-via-systemd approach is invalid.

**3A. Mechanism A — set-property --runtime, smaller list:**

```bash
sudo systemctl set-property --runtime xhelix-egress-spike.service IPAddressAllow=
sudo systemctl set-property --runtime xhelix-egress-spike.service IPAddressAllow="localhost link-local 8.8.8.8/32"
systemctl show -p IPAddressAllow xhelix-egress-spike.service
# CRITICAL question: does the running unit now BLOCK 1.1.1.1, or does the
# config drop-in's 1.1.1.1 grant still COMBINE in and keep it allowed?
```

**EXPECT to learn:** the key combine-vs-replace question. If the config drop-in (`50-egress.conf`) still grants `1.1.1.1`, the transient *cannot* shrink below it → mechanism A can't shrink while a config drop-in carries dynamic IPs. (Implication: the Applier must keep the config drop-in MINIMAL — deny floor + localhost/link-local only — and hold the entire dynamic set in the transient layer.)

**3B. Mechanism A with a minimal config drop-in (the design-A test):**

```bash
# Make the CONFIG drop-in carry ONLY the deny floor + always-allowed:
sudo tee /etc/systemd/system/xhelix-egress-spike.service.d/50-egress.conf >/dev/null <<'EOF'
[Service]
IPAddressAllow=localhost link-local
IPAddressDeny=any
EOF
sudo rm -f /run/systemd/system.control/xhelix-egress-spike.service.d/*.conf 2>/dev/null
sudo systemctl daemon-reload
# Now manage the dynamic set ENTIRELY via transient set-property:
sudo systemctl set-property --runtime xhelix-egress-spike.service IPAddressAllow="localhost link-local 1.1.1.1/32"
# (watch: 1.1.1.1 OK) then shrink it away live:
sudo systemctl set-property --runtime xhelix-egress-spike.service IPAddressAllow=
sudo systemctl set-property --runtime xhelix-egress-spike.service IPAddressAllow="localhost link-local"
# Watch journal: does 1.1.1.1 flip to BLOCKED live? MainPID unchanged?
```

**EXPECT to learn:** whether design A (minimal config drop-in + dynamic-in-transient) supports **live shrink**. This is the most likely viable design if any is.

**3C. Mechanism B — drop-in rewrite (smaller) + daemon-reload:**

```bash
sudo tee /etc/systemd/system/xhelix-egress-spike.service.d/50-egress.conf >/dev/null <<'EOF'
[Service]
IPAddressAllow=localhost link-local 8.8.8.8/32
IPAddressDeny=any
EOF
sudo systemctl daemon-reload
# Watch journal: does 1.1.1.1 flip to BLOCKED live via reload alone?
```

**Record (shrink):** A-over-config combines/blocks = ____ ; **3B design-A live-shrink = (yes/no) ____** ; B reload live-shrink = (yes/no) ____ ; MainPID stable = ____.

---

## Phase 4 — Decision matrix → picks SP-1b.2b.2 implementation

Fill from Phases 2–3, then choose:

| Observed | Concrete `Applier` for the live slice |
|---|---|
| **3B design-A live-shrink = yes** (minimal config drop-in + dynamic transient set-property shrinks live) | **Applier = set-property over a minimal drop-in.** Config drop-in = `IPAddressAllow=localhost link-local` + `IPAddressDeny=any` (written at arm by SP-1b.1/2a, reduced to the floor); refresher pushes the full dynamic set via `set-property --runtime` (reset-then-set each change). Persist a copy to the drop-in for reboot. |
| **3B = no, but 3C (drop-in rewrite + reload) shrinks live = yes** | **Applier = drop-in rewrite + daemon-reload.** Refresher re-renders the whole egress drop-in (full `EgressDirectives` set) and reloads. Note: requires re-rendering seccomp/AppArmor too (whole-drop-in) — Applier needs the compiled service, not just the egress set. |
| **Both shrink = no** (live grow may work, live shrink does not) | **Live shrink is impossible via systemd on this host.** Options: (i) live-grow-only via systemd + shrink-on-next-restart (degraded; document the staleness), or (ii) **escalate live refresh to SP-1b.3** (nftables-per-cgroup named set or cgroup-BPF map — both support live shrink). Recommend (ii); the SP-1b.2b.1 review already named SP-1b.3 as the higher-fidelity path. |
| **MainPID changed at any step** | That step caused a restart, not a live update — disqualify it (a restart defeats the purpose and would interrupt the service). |

Also carry the SP-1b.2b.1 review carry-forwards into whichever Applier is built: (1) explicit empty-set guard (never apply an empty set unless the unit previously had a non-empty one), (2) evict `lastSet` on `Forget`.

---

## Phase 5 — Cleanup (always run, even on failure)

```bash
sudo systemctl stop xhelix-egress-spike.service 2>/dev/null
sudo rm -f /run/systemd/system.control/xhelix-egress-spike.service.d/*.conf 2>/dev/null
sudo rm -rf /etc/systemd/system/xhelix-egress-spike.service.d
sudo rm -f /etc/systemd/system/xhelix-egress-spike.service
sudo systemctl daemon-reload
sudo systemctl reset-failed xhelix-egress-spike.service 2>/dev/null || true
# Verify gone:
systemctl status xhelix-egress-spike.service 2>&1 | head -2   # expect "could not be found"
```

Stop the `journalctl -f` shell. Confirm no `xhelix-egress-spike` unit or drop-in remains.

---

## Deliverable

A short results note (paste the filled Phase 0/2/3 records + the Phase 4 decision) appended to `docs/2026-06-21-XHELIX_APP_CAUSAL_BRP_SCOPE_LOCK.md` under SP-1b, OR a new `docs/…-RESULTS.md`. That decision unblocks writing the SP-1b.2b.2 `Applier` plan (a normal TDD plan) against the chosen mechanism — or redirects the live-refresh capability to SP-1b.3.

**Nothing in SP-1b.2b.1 changes based on this spike** — the shadow refresher already computes the correct desired set; this spike only decides *how* a future non-shadow `Applier` puts that set onto a running unit.
