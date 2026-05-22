# Progress report — 2026-05-22 session 2

**Window:** afternoon → late afternoon, single session.
**Commits landed:** `c73c65e` (A1), `b9f936d` (A1.fix revert).
**Deployed to prod:** plesk.douxl.com (65.108.246.67), kernel 6.8.0-90-generic.

---

## What shipped

### P-PROCFS-A1: procscrape detector + posture hardener (detect-only)

**Userspace (working on prod):**

- `sensors/procscrape/` — `Allowlist` + `Sensor` + `Enrich()`. Baked-in allowlist of 46 legitimate /proc readers (systemd, ps, htop, monit, journalctl, gdb, xhelix*, runc/containerd, …). LoadFile overlay supports `comm:` / `image:` / `glob:` lines from `/etc/xhelix/procscrape-allowlist.conf`.
- `pkg/posture/procfs/` — pure generators for sysctl drop-in and per-service systemd drop-ins.
- `cmd/xhelixctl/posture_procfs.go` — `posture procfs status | generate | apply`. Apply is `--confirm` gated, root-only, per-file prompt or `--yes`, runs `sysctl --system` + `systemctl daemon-reload`.
- `pkg/pipeline/pipeline.go` — `ProcScrape.Enrich()` called before HotStore.Insert when `kind=proc_scrape`.
- `pkg/config/config.go` — `sensors.procscrape.{enabled, allowlist_file}` config keys (default enabled).
- `ruleset/core/procscrape.yaml` — `cred_proc_scrape` (warn, T1003.007) + `cred_proc_scrape_environ_burst` (high). Rule count 72 → 74.

**Kernel hook (deferred — verifier-rejected on 6.8):**

- New `XH_EV_PROC_SCRAPE` event kind + `tp/syscalls/sys_enter_openat` program in `sensors/ebpf/progs/all.bpf.c` failed two verifier attempts:
  - Attempt 1: 256-byte stack-allocated `path[]` + `bpf_probe_read_user_str` → *"value -2147483648 makes fp pointer be out of bounds"*.
  - Attempt 2: Read directly into the ringbuf event + variable-indexed tail-byte compare for suffix matching → *"R1 unbounded memory access, make sure to bounds check"*.
- Reverted in `b9f936d`. Userspace surface stays; will plug back in once the kernel program is rewritten with a per-CPU `BPF_MAP_TYPE_PERCPU_ARRAY` scratch buffer + `bpf_strncmp()` (kernel ≥ 5.16) for suffix matching.
- Net effect today: `cred_proc_scrape` rule never fires because no `proc_scrape` events flow.

**Prod hardening (live):**

- `kernel.yama.ptrace_scope = 2` (host-wide, kernel-level)
- `fs.suid_dumpable = 0` (host-wide)
- `fs.protected_hardlinks = 1`, `fs.protected_symlinks = 1`
- `/etc/sysctl.d/60-xhelix-procfs.conf` installed
- 14 per-service systemd drop-ins applied + services restarted:
  `apache2`, `gitlab-runner`, `httpd`, `mariadb`, `mysql`, `nginx`, `php-fpm`, `php8.1-fpm`, `php8.2-fpm`, `php8.3-fpm`, `postgresql`, `psa`, `redis`, `sw-cp-server`
- Each restarted service now has `ProtectProc=invisible`, `ProcSubset=pid`, `NoNewPrivileges=yes`, `ProtectKernelTunables=yes`.

---

## What broke and was recovered

This session went sideways three times. Recording so the same traps don't catch the next session.

1. **First prod deploy of 0.0.12-dev appeared to break eBPF entirely.** All ebpf event sensors stopped flowing post-restart. Root cause was a one-line verifier rejection on the new procscrape program — and because `cilium/ebpf.NewCollection` fails atomically, ALL programs failed to load with it.

2. **Mid-flight diagnosis was wrong.** I misread historical event counts as live counts (SQL window filter compared nanosecond `ts` against second-precision `now`), concluded "regression worse than verifier failure", panic-rolled-back to `dist/xhelix_0.0.11-4_amd64.deb` — which **predates the xhelixctl packaging**. xhelixctl vanished from `/usr/local/bin/`. The "regression" was real (verifier failure), but the rollback was an overcorrection.

3. **The .deb has no `DEBIAN/conffiles`.** Every `dpkg -i` overwrites `/etc/xhelix/xhelix.yaml` back to the package's default (which has `ebpf.enabled: false`). Operator yaml edits silently clobbered on each upgrade. **This is a packaging bug worth fixing in a follow-up.**

4. **Attempted per-program fallback loader.** Tried to make `loadCollectionPerProgram` keep the rest of eBPF alive when one program fails verification. The `MapReplacements` API misuse rejected EVERY program ("replacement map xh_X not found in CollectionSpec"). Reverted. **The "one bad eBPF program kills all observability" failure mode is still open.** Worth a separate clean fix.

5. **Final recovery:** rebuilt with broken BPF program removed, scp'd binaries direct (skipping deb to avoid the conffile clobber), edited yaml to `ebpf.enabled: true`, restarted. eBPF fully back: `ebpf.net 4599/min`, `ebpf.ssl 916/min`, `ebpf.proc 169/min`.

---

## What didn't ship

- **C1 Mode-2 disarm enforcement** — scoped during the session, found a deeper substrate gap than the roadmap implied. Saved analysis to `[[c1-substrate-analysis]]` memory.
- **A2 brokered env-var delivery** — not started.
- **The procscrape kernel hook** — pending verifier-safe rewrite.

---

## C1 substrate gap (worth surfacing)

The taint pipeline is structurally complete (`pkg/lineage.Store.AddTaint`, `pkg/egress.Policy.Allow`) but **nothing in the codebase actually calls AddTaint**. The lineage model has no PID field — it's a data-origin model (SSH session, web request) decoupled from process trees. Building C1 honestly requires:

1. PID-keyed taint store (new `pkg/pidtaint` or extension to `pkg/proctree`) — ~1 day
2. credbroker → pidtaint hook — ~0.5 day
3. FIM / decoy → pidtaint hooks — ~0.5 day
4. Pipeline outbound hook → Policy.Allow — ~0.5 day
5. Shadow-mode logging + alert — ~0.5 day
6. Enforce mode + netban + kill-switch — ~0.5 day
7. Config + tests + prod verify — ~1.5 day

**Total ~5–6 days.** The "1 week" estimate in `HARDENING_ROADMAP_2026-05-22.md` C1 was correct; my earlier 0.5-day estimate for item #1 was wrong.

---

## Honest current-state matrix

What's rock-solid vs. what isn't, end of this session:

| Attack class | Detect | Prevent | Notes |
|---|---|---|---|
| Open of managed `.sealed` cred file | ✅ | ✅ | FAN_OPEN_PERM. Real kernel-side deny. |
| Honey-decoy touch | ✅ | (intentional allow) | High-confidence alert. |
| Cross-PID `/proc/*/environ` read (same UID) | ❌ today | ✅ (post A1) | Kernel-level on restarted services. |
| Cross-PID `ptrace` / `process_vm_readv` | ❌ today | ✅ (post A1) | Yama scope=2 host-wide. |
| `/proc/<pid>/mem` cross-process | ❌ today | ✅ (post A1) | suid_dumpable=0 + ProtectProc. |
| Web server → shell / curl / wget | ✅ | ❌ | Rule fires, no block. |
| Binary in `/tmp` / `/var/tmp` / `/dev/shm` exec | ✅ | ❌ | Rule fires, no block. |
| memfd exec / deleted-binary running | ✅ | ❌ | eBPF + procmem. Detect, no block. |
| RWX mprotect | ✅ | ❌ | eBPF tracepoint. Block is roadmap B1. |
| uid 0 transition w/o setuid | ✅ | ❌ | rule cred-class. |
| Cron / bashrc / authorized_keys tamper | ✅ | ❌ | FIM inotify. |
| DNS exfil (high-entropy) | ✅ | ❌ | dnsexfil detector. |
| Beacon-shape callbacks | ✅ | ❌ | beacon detector. |
| Plaintext `~/.aws/credentials` etc | ❌ | ❌ | Not converted to sealed. |
| Env-var theft (`printenv`, own environ) | ❌ | ❌ | A2 not built. |
| IMDS theft (`169.254.169.254`) | ❌ | ❌ | No special gate. |
| HTTPS exfil to attacker-controlled host | (observe) | ❌ | Mode-1 only; C1 not built. |
| In-memory scrape of legit process | ❌ | ❌ | Named residual ceiling. |

**Net of session:** detection coverage essentially unchanged. Live prevention picked up modestly for the procfs/ptrace/dumpable class — but only within the 14 restarted services. Whole-malware verdict against the script class the user analyzed earlier: still "not impossible."
