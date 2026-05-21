# Ring-A Lab — running real Linux malware safely against xhelix

This is the operational runbook for **D-10**: executing real
malware samples against an xhelix-protected host without endangering
production-adjacent systems.

**Do NOT execute real malware directly on the production xhelix
host.** The whole point of the Ring-A lab is the isolation perimeter.
Every detection number below is conditional on running inside that
perimeter.

---

## 1. Architecture: three rings

```
┌─────────────────────────────────────────────────────────────────┐
│  Ring A — disposable KVM/QEMU VM                                │
│  ephemeral disk · VLAN-isolated · no host mount                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Ring B — rootless podman container                     │    │
│  │  drop ALL caps · ro rootfs · seccomp blocks init_module │    │
│  │  ┌──────────────────────────────────────────────────┐   │    │
│  │  │  Ring C — LD_PRELOAD shim                       │   │    │
│  │  │  blocks writes to /etc, /root, /home, /boot     │   │    │
│  │  │  inotify alarm on any forbidden write           │   │    │
│  │  │  malware sample executes here                   │   │    │
│  │  └──────────────────────────────────────────────────┘   │    │
│  │  xhelix runs in this container reading via eBPF         │    │
│  └─────────────────────────────────────────────────────────┘    │
│  Network egress: ONLY to attacker box (also a VM); sinkhole     │
│                  + dnspoison capture every outbound flow         │
└─────────────────────────────────────────────────────────────────┘
```

### Ring A (VM)

```bash
# Provision (one-time)
virt-install --name xhe-ringA --memory 4096 --vcpus 2 \
    --disk size=20,backing_store=/var/lib/libvirt/images/ubuntu-server.qcow2 \
    --network network=xhe-isolated-vlan,model=virtio --os-variant ubuntu24.04 \
    --noautoconsole

# Pre-flight snapshot before each sample
virsh snapshot-create-as xhe-ringA pristine

# Revert after each sample
virsh snapshot-revert xhe-ringA pristine
```

VM network: a libvirt network with `<forward mode='none'/>` and a
single bridged interface to the attacker VM. Real internet is NOT
reachable. The attacker VM hosts a fake C2 listening on common
malware-popular ports (4444, 8080, 8888, 1337, 9999).

### Ring B (container)

```bash
podman run --rm -it \
    --name xhe-sample \
    --cap-drop=ALL \
    --read-only --tmpfs /tmp:size=256m \
    --security-opt seccomp=/etc/xhelix/seccomp-strict.json \
    --network host-isolated \
    -v /var/lib/xhelix:/var/lib/xhelix:ro \
    ubuntu:24.04 /bin/bash
```

`seccomp-strict.json` denylists: `init_module`, `finit_module`,
`kexec_load`, `setns(CLONE_NEWUSER)`, `unshare(CLONE_NEWUSER)`,
`mount`, `pivot_root`. Allowlist all common syscalls so legit
malware runtime works.

### Ring C (write-block shim)

`/usr/lib/xhe-shim.so` (LD_PRELOAD'd into the sample's bash):
intercepts `open(O_CREAT|O_WRONLY)` and rejects paths matching
`/etc/*`, `/root/*`, `/home/*`, `/boot/*`. An inotify-watch on those
paths simultaneously alarms if any write slips through.

---

## 2. Sample procurement

For each sample retain SHA-256 + source URL + observed-date.

| Source | What | Auth | Notes |
|---|---|---|---|
| [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) | binaries, scripts, droppers | API auth-key | filter `tag:linux` |
| [theZoo](https://github.com/ytisf/theZoo) | classic Linux corpus | git clone | password-protected zips |
| vx-underground | curated samples | tor + magnet | manual review |
| [ExploitDB](https://www.exploit-db.com/) | RCE / LPE PoCs | git submodule | per-license |
| Metasploit `exploit/linux/*` | productionised exploits | `msfconsole` | safe payloads |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | MITRE-mapped technique scripts | git clone | benign, baseline |

**Always**: pull samples to the attacker VM (or a staging host),
verify SHA-256 against the source's posted hash, then `scp` into
Ring A.

---

## 3. First-round sample set (8 samples)

Pick the highest-information-density samples for round 1.

| ID | Family | Behaviour we expect | What we want xhelix to catch |
|---|---|---|---|
| MW-01 | **Sliver** (BishopFox red-team C2) | beacon + memfd staging | `memfd_run_pattern`, `beacon.periodic_callback`, takeover scorer → tier=isolated |
| MW-02 | **Mirai** (IoT botnet variant) | SSH brute + drop + persist | `ssh_brute_then_success`, `outbound_to_known_bad`, `cron_new_unit` |
| MW-03 | **XMRig** drop chain | crypto-miner persist + outbound | `cron_new_unit`, `outbound_to_known_bad`, stratum pattern (gap today) |
| MW-04 | **TeamTNT** (k8s/docker) | container escape + cred theft | `contescape.detected`, cred-path read, IMDS access |
| MW-05 | **Kinsing** | shell + tor + miner | `shell_with_socket_fd`, outbound, `cron_new_unit` |
| MW-06 | **XorDDoS** | LKM rootkit + DDoS | `modules_changed`, `kallsyms_changed` |
| MW-07 | **BPFdoor** | eBPF magic-packet backdoor | `bpf_syscall_unexpected` + pinned BPF gap (P7 future) |
| MW-08 | **Atomic Red Team** Linux subset | technique-level breadth | broad MITRE coverage baseline |

---

## 4. Per-sample procedure

```bash
# On the host running Ring A VMs
SAMPLE_ID="MW-01"
SAMPLE_SHA="<sha256>"
SAMPLE_PATH="/srv/lab/samples/$SAMPLE_SHA"

# 1. Snapshot
virsh snapshot-revert xhe-ringA pristine

# 2. Stage sample into VM
virsh console xhe-ringA  # or ssh from host network
# inside VM:
mkdir -p /tmp/sample
scp attacker@attacker-vm:/samples/$SAMPLE_SHA /tmp/sample/
sha256sum /tmp/sample/$SAMPLE_SHA  # MUST match expected

# 3. Mark begin
sudo bash -c "echo '===$SAMPLE_ID""_BEGIN_$(date -u +%FT%TZ)===' >> /var/log/xhelix/xhelix.out"

# 4. Execute inside Ring B container
podman run --rm \
    --cap-drop=ALL --read-only --tmpfs /tmp:size=256m \
    --security-opt seccomp=/etc/xhelix/seccomp-strict.json \
    --network host-isolated \
    -v /tmp/sample:/sample:ro \
    -v /usr/lib/xhe-shim.so:/lib/xhe-shim.so:ro \
    -e LD_PRELOAD=/lib/xhe-shim.so \
    ubuntu:24.04 \
    timeout 300 /sample/$SAMPLE_SHA

# 5. Mark end
sudo bash -c "echo '===$SAMPLE_ID""_END_$(date -u +%FT%TZ)===' >> /var/log/xhelix/xhelix.out"

# 6. Pull results
xhelixctl alerts stats --since 6m --by rule > /srv/lab/results/$SAMPLE_ID.stats
xhelixctl alerts ls --since 6m --limit 50 > /srv/lab/results/$SAMPLE_ID.events
xhelixctl takeover lineages --since 6m --top 10 > /srv/lab/results/$SAMPLE_ID.lineages
xhelixctl report --since 6m --format html > /srv/lab/results/$SAMPLE_ID.html

# 7. Snapshot rsync-out chain dir for offline verify
rsync -av /var/lib/xhelix/chain/ /srv/lab/results/$SAMPLE_ID.chain/

# 8. Revert VM to clean snapshot
virsh snapshot-revert xhe-ringA pristine
```

---

## 5. Per-sample scoring sheet

Use this template; record once per sample.

```
Sample: MW-XX                    SHA-256: <hash>
Source: <url>                    Date observed: <date>

Detection summary:
  Expected rules:    [list from §3]
  Rules fired:       [from stats]
  Rules MISSED:      [expected - fired]
  Recall %:          (fired / expected) * 100
  Time to first alert: <sec>
  Time to tier=isolated: <sec> (or "not reached")

Causal chain:
  Lineage rooted at PID: <pid>
  PIDs in lineage: <count>
  Max planner score: <score>
  Max planner tier: <tier>

Containment readiness (would-be enforce):
  Snapshot dir: <path>
  Quarantine plan actions: [list]

False positives during window: <count>
False-positive rules (if any): [list]

Operator notes:
  [free text — anything notable, especially gaps]
```

Aggregate all 8 sheets into `PHASE_3_RESULTS.md` for stakeholder review.

---

## 6. Hard rules (don't break)

1. **Never** execute a sample on the xhelix dev host directly.
2. **Never** allow the Ring-A VM out to the public internet.
3. **Always** verify SHA-256 before execution.
4. **Always** snapshot-revert between samples — malware can hide
   in artefacts you didn't expect.
5. If the shim alarms on a write outside the allowed set, KILL the
   sample immediately and investigate before continuing.
6. Treat the chain artefacts as evidence: rsync them out before
   reverting, store under `/srv/lab/results/$SAMPLE_ID.chain/`.

---

## 7. When the sample sandbox itself misbehaves

Failure modes to plan for:

- **Sample fork-bombs** → systemd cgroup limit (`Slice=xhe-sample.slice`,
  `TasksMax=200`) caps the explosion.
- **Sample tries to load kernel module** → seccomp denies; eBPF
  records the attempt; xhelix should fire `modules_changed` from
  the host eBPF if module path actually changed (it won't because
  container is read-only).
- **Sample exhausts disk via tmpfs** → tmpfs has size cap.
- **Sample escapes container** → Ring A's VM-level isolation is
  the next perimeter. snapshot-revert recovers.
- **Sample disables xhelix in the VM** → tamperguard alerts via
  host eBPF (running on the VM host's xhelix instance, NOT the
  in-VM one).

---

## 8. Status

| Step | Status |
|---|---|
| Ring-A VM provisioning script | not yet written (this doc only) |
| Ring-B podman recipe | inline here, not yet templatized |
| Ring-C LD_PRELOAD shim | not yet written |
| seccomp-strict.json | not yet written |
| Sample procurement queue | empty |
| First-run scoring sheet | template only |

**This is the procedure. Execution is the next deliverable.**

When running:
1. Spend ½ day on Ring-A VM image + snapshot tooling
2. ½ day on Ring-B/C container + shim
3. 1 day on the first sample (Atomic Red Team) — fastest feedback
4. 1 day on Sliver — first real C2 detection result
5. ½ day on each remaining sample
6. ½ day on `PHASE_3_RESULTS.md` writeup

Total: **~5 days** to comprehensive real-malware results.
