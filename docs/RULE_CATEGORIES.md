# Rule Categories

Every detection in xhelix — whether a YAML rule in `ruleset/**/*.yaml` or a
runtime-emitted alert from Go code — declares one of four categories. The
category determines what the verdict engine does with a match.

| Category | Behavior on match | Use when |
|---|---|---|
| `fact` | Record event only. Never alerts. Does not contribute to score. | The match is a structural observation that's normal on real workloads. Examples: process gained capability, TLS without SNI, namespace change, memfd creation, mprotect RWX. |
| `weak_signal` | Records event and contributes evidence_weight points to the verdict score. Never alerts standalone. | The match is suspicious in some contexts but normal in others. Examples: outbound to first-seen IP, binary executed from /tmp, JIT memory allocation in a non-runtime process. |
| `incident` | Same as weak_signal, plus alerts when chain-confirmed (verdict engine threshold). May contribute to active response. | The match is a meaningful pattern that, combined with one or two other signals, is almost certainly malicious. Examples: shell spawned by web/mail process, secret-path read by non-allowlisted process, reverse-shell pattern. |
| `hard_deny` | Alerts on every fire. May block depending on `mode`. FP budget < 0.1%. | The match is a deterministic invariant with near-zero false positives by design. Examples: canary secret touched, PAM modified by non-package process, explicit egress-policy deny. |

## Classification rules

1. **If a rule fired more than 1000 times in 42h on a healthy production host**
   (per the `.11` corpus), it is almost certainly `fact` — no amount of
   "tuning" gets it under the FP budget for `incident` or `hard_deny`.
2. **If a rule depends on a single observation** (e.g. "process did X"), it is
   `fact` or `weak_signal`. Promotion to `incident` requires AND-ing with at
   least one other condition (source role + sensitivity + chain step) — that
   AND-ing is the verdict engine's job, not the rule's.
3. **If a rule names a sensitive target** (canary, .env, SSH private key, PAM,
   LD_PRELOAD, kernel module path) **AND** the action is deterministic (write,
   exec, ptrace), it may be `hard_deny`.
4. **If unsure, classify as `weak_signal`.** Safe: still recorded, still
   scored, never floods the alert stream alone.

## Anti-patterns

- ❌ "Process gained capability X" → `fact`. Containers do this every start.
- ❌ "TLS without SNI" → `fact`. HTTP/3 + session resumption + custom protocols omit SNI.
- ❌ "memfd execution" → `weak_signal` at most. Modern Go/Python runtimes use memfd.

## Two registries

- **YAML rules**: each rule in `ruleset/**/*.yaml` carries a `category:` field.
- **Runtime-emitted alerts**: alerts created in Go (e.g. `pkg/pipeline/pipeline.go`)
  have no YAML entry. Their categories live in `ruleset/runtime_categories.yaml`.
  Both are merged into one rule_id→Category resolver consumed by the alert-bus
  gate and the `xhelix-replay` tool.

## Authoritative mapping

### Runtime-emitted (see ruleset/runtime_categories.yaml)

| rule_id | category | justification |
|---|---|---|
| cap.gained | fact | 31,748/42h on real prod. Container runtimes request full cap set every start. |
| ungated | fact | "process outside the gated set" — matches every new process not pre-listed. |
| lolbin.suspicious | weak_signal | Needs script-context to be incident-worthy; mostly `sh`/`bash`. |
| process_spawn_burst | weak_signal | Cron + container starts trigger this. |
| contescape.detected | weak_signal | pivot_root happens during normal container start. |
| revshell.detected | incident | Precise socket→/bin/sh→exec pattern; chain-confirm to alert. |
| shell_with_socket_fd | incident | Real reverse-shell shape; was mis-classified class-1. |
| shm.exec | weak_signal | /dev/shm execution; runtimes use it too. |
| webshell.argv | incident | Web process argv looks like a shell command. |
| memfd_run_pattern | weak_signal | Modern runtimes use memfd; weight, don't alert alone. |
| ptrace.suspicious | weak_signal | Debuggers/profilers use ptrace. |
| metadata.access_by_unexpected | incident | Cloud metadata read by non-cloud process. |
| intel.bad_ip | incident | Threat-intel IP match — strong but verify chain. |
| phishing.brand_lookalike | weak_signal | Heuristic lookalike domain. |
| beacon.detected | weak_signal | Periodicity heuristic alone is weak. |
| beacon.periodic_callback | weak_signal | Same family. |
| dnsexfil.tunnel_pattern | incident | DNS tunneling shape. |
| netids.dga | weak_signal | DGA-style domain heuristic. |
| ml.anomaly | weak_signal | ML advisory only — never autonomous alert. |
| ssh_bruteforce | weak_signal | Internet background noise on any public SSH host. |
| yara.match | incident | YARA hit — strong but context-dependent. |
| takeover.composite | incident | Composite takeover scorer crossing threshold. |
| containment.endpoint_breach | incident | Endpoint breach signal. |
| baseline.poison_attempt | incident | Anti-poisoning detector — real signal. |
| baseline.behavioural_deviation | weak_signal | Baseline drift; scored not alerted. |
| baseline.rate_spike | weak_signal | Rate anomaly; scored not alerted. |
| brp.hard_deny | hard_deny | Explicit signed-BRP policy violation. THE canonical TP. |
| brp.verify_protected_path | incident | BRP verify-tier; needs context. |
| egressguard.deny | hard_deny | Explicit egress policy deny. |
| policy.global.deny | hard_deny | Explicit global policy deny. |
| policy.app.deny | hard_deny | Explicit per-app policy deny. |
| policy.app.allow-only-domains | hard_deny | Explicit policy violation. |
| policy.app.asn-restricted | hard_deny | Explicit policy violation. |
| policy.app.country-restricted | hard_deny | Explicit policy violation. |

### YAML rules

YAML rules are classified in their own files (`ruleset/core/*.yaml`) in tasks
VF-T4 through VF-T14. Notable assignments from the .11 trace:

| rule_id | category | justification |
|---|---|---|
| tls_no_sni / tls_no_sni_from_webserver / tls_no_sni_from_tmp | fact | 16,992/42h. check_imap / curl / tailscaled / rspamd legitimate. |
| bpf_syscall_unexpected | fact | systemd + runc use BPF legitimately. |
| mem_new_rwx_mapping | fact | JIT compilers (Chrome, V8, JVM, Claude runtime). |
| mem_mprotect_rwx | weak_signal | Less common than mem_new_rwx_mapping; still mostly JIT. |
| fim.drift | weak_signal | File-integrity drift fires constantly during package updates. |
| cred_proc_scrape / cred_proc_scrape_environ_burst | weak_signal | Normal for monitoring tools. |
| binary_runs_from_tmp | incident | Strong on a server with no CI. |
| deleted_binary_running | incident | Real when not a package upgrade. |
| thread_outside_module | weak_signal | Mature LSM detail. |
| web_server_spawns_shell | incident | Classic webshell vector. |
| decoy_* (all decoy/canary rules) | hard_deny | Decoy touch is deterministic. |
| boot_artifact_modified / rc_local_modified / ld_so_preload_modified / pam_module_drop / ssh_key_added_root | hard_deny | Persistence writes, deterministic outside dpkg window. |
| systemd_unit_new / profile_d_dropped / cron_* | incident | Persistence vectors; chain-confirm. |
| outbound_to_known_bad / outbound_to_tor | incident | Intel/Tor destination. |
| metadata_svc_unexpected | incident | Cloud metadata by non-cloud process. |
| messaging_platform_egress / high_volume_outbound_burst / cdn_cloaking_* | weak_signal | Behavioral, low-confidence alone. |
| sysctl_drift | weak_signal | Often during package install. |

When a new rule is added later, its category MUST appear in this doc OR in
`ruleset/runtime_categories.yaml`. CI rejects rules with no category.
