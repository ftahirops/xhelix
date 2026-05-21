# Remote attack guide — xhelix red-team

This document tells you how to drive a realistic external attack
against an xhelix-protected host from a **separate attacker box** over
the public internet, then read what xhelix observed.

It is intentionally **not in the .gitignore claude-private path** —
treat it as operator runbook, not strategy.

---

## Architecture

```
  ┌──────────────────────────┐                 ┌──────────────────────────┐
  │  ATTACKER                │ ---public IP--> │  VICTIM                  │
  │  135.181.79.13           │   80 / 443      │  135.181.79.27           │
  │                          │  (whitelisted)  │  attack.nocgurus.com     │
  │  - curl, nmap, nc        │                 │                          │
  │  - python3 (HTTP server  │                 │  nginx ──┐               │
  │    for PoC drop)         │                 │          ▼               │
  │  - run_remote_suite.sh   │                 │  vuln-app.service        │
  │                          │                 │  (Flask, intentional RCE)│
  └──────────────────────────┘                 │          │               │
                                               │          ▼               │
                                               │  /bin/sh as www-data     │
                                               │                          │
                                               │  xhelix daemon (monitor) │
                                               │  - 48 detection rules    │
                                               │  - FIM, eBPF (when on)   │
                                               │  - sinkhole, dnspoison   │
                                               │  - honey-sh (per session)│
                                               │  - takeover scorer       │
                                               │  - forensic chain        │
                                               └──────────────────────────┘
```

The attacker has **only** TCP/80 and TCP/443 open to it via iptables:

```sh
iptables -I INPUT 1 -p tcp -s 135.181.79.13 --dport 80  -j ACCEPT
iptables -I INPUT 1 -p tcp -s 135.181.79.13 --dport 443 -j ACCEPT
```

No SSH from attacker to victim is required for the attack itself — the
attacker reaches the victim only by HTTP. (You DO need SSH the other
way around so you can scp tools and PoC binaries onto the attacker.)

---

## Bootstrap — one-time

### On the victim (xhelix host)

```sh
# Build everything
make build
make ebpf            # optional but unlocks eBPF sensors (needs clang + libbpf-dev)

# Bring xhelix up in monitor (learning) mode
sudo bash scripts/test-setup.sh

# Confirm everything healthy
sudo xhelixctl protect list
sudo xhelixctl posture lsm
```

The vulnerable Flask target lives at `/opt/vuln-app/app.py` and runs
under `vuln-app.service` (port 8000, loopback). Nginx vhost
`attack.nocgurus.com` proxies to it.

### On the attacker

```sh
# Tools
apt-get update && apt-get install -y curl nmap netcat-openbsd build-essential jq dnsutils

# Resolve attack.nocgurus.com without real DNS
echo '135.181.79.27 attack.nocgurus.com' | sudo tee -a /etc/hosts

# Drop the runner from the victim repo
# (run from victim, then scp the script + compiled PoC dir)
scp tests/redteam/run_remote_suite.sh root@135.181.79.13:/root/
scp -r tests/redteam/poc/         root@135.181.79.13:/tmp/xhe-poc

# Build PoCs on attacker (they need to be ELF for the victim arch)
ssh root@135.181.79.13 'cd /tmp/xhe-poc && make all'
```

---

## Running an attack

```sh
# From the attacker
TARGET=attack.nocgurus.com ATTACKER=135.181.79.13 \
  bash /root/run_remote_suite.sh all
```

Phases (run individually with the phase name as arg):

| Phase     | What it does                                                | What xhelix should see                                        |
|-----------|-------------------------------------------------------------|---------------------------------------------------------------|
| `recon`   | nmap, header probe, .git / .env hunt                         | netids: scan from new IP                                       |
| `rce`     | id / whoami / staged base64 / wget remote / reverse-shell    | exec tree (`nginx -> sh -> id`), DNS+outbound to attacker      |
| `lfi`     | Reads /etc/passwd, /etc/shadow, /root/.ssh/id_rsa            | FIM read-tap on sensitive paths; LSM file_open audit            |
| `memory`  | mmap RWX / mprotect W->X / memfd_exec / ptrace               | Tier-1 deterministic signals (RWX=95, memfd_exec=85, ptrace=85)|
| `persist` | authorized_keys / cron.d / ld.so.preload / systemd unit drop  | FIM write events on the 18 watched paths                       |
| `exfil`   | SSRF to 169.254.169.254 / DNS tunneling / base64 of passwd    | netids egress to new ASN; DGA-pattern DNS; cred-pattern bytes  |

---

## Reading what xhelix observed (on the victim)

```sh
# Live tail
sudo tail -F /var/log/xhelix/xhelix.out | grep -vE 'config knob|unwitnessed'

# Forensic IOCs harvested from Ring-2 deception layers
sudo xhelixctl forensic iocs

# Protected services current posture
sudo xhelixctl protect list
sudo xhelixctl protect deception

# Sinkhole / dnspoison captures
sudo tail -F /var/lib/xhelix/forensic/sinkhole.jsonl | jq .
sudo tail -F /var/lib/xhelix/forensic/dnspoison.jsonl | jq .

# Signed evidence chain — verify integrity end-to-end
sudo xhelix-verify --chain /var/lib/xhelix/chain --pub <your-pub-key>

# FIM database — which watched paths got touched?
sudo sqlite3 /var/lib/xhelix/fim.db 'select path, op, ts from changes order by ts desc limit 20;'
```

---

## What requires what

| You want to see           | Prerequisites                                                              |
|---------------------------|----------------------------------------------------------------------------|
| RCE exec tree             | eBPF programs deployed (`make ebpf` + `/usr/lib/xhelix/xhelix-progs.o`)    |
| Honey-sh capture          | `protected_services.services[].response.deception.fake_exec: true`         |
| Sinkhole DNS+TLS capture  | `deception.sinkhole: true` + tc redirect on egress (root)                  |
| DNS poison                | `deception.poison_dns: true` + dnspoison binary running                    |
| FIM persistence events    | Already on by default — runs against 18 paths                              |
| Memory-class signals      | eBPF programs deployed; kernel >= 5.15                                      |
| AppArmor refusals         | `xhelixctl posture lsm` shows apparmor enforce + profile loaded            |
| Takeover plans            | `takeover.active: true` (NOT default in monitor mode)                      |

In **monitor mode** (the default for testing) almost everything is
WATCH-only: refusals are observed but not applied, ActionPlans are
logged as "planner shadow" lines instead of executing.

---

## Troubleshooting

**The attack hits but xhelix log is silent.** Check:

```sh
sudo grep "sensor started" /var/log/xhelix/xhelix.out
```

If only `heartbeat` and `fim` started, eBPF programs aren't deployed.
Run `make ebpf` then restart xhelix.

**Sinkhole jsonl is empty even though the attacker tried outbound.**
That's correct in monitor mode — `deception.sinkhole=false`. Outbound
goes to the real internet, not the sinkhole socket.

**Forensic IOCs empty.** Honey-sh hasn't been invoked because
`deception.fake_exec=false`. The attacker is hitting the real Flask app
and getting real RCE.

---

## Cleanup

```sh
# On victim
sudo systemctl stop vuln-app
sudo systemctl disable vuln-app
sudo rm /etc/nginx/sites-enabled/attack.nocgurus.com
sudo systemctl reload nginx
sudo iptables -D INPUT -p tcp -s 135.181.79.13 --dport 80  -j ACCEPT 2>/dev/null
sudo iptables -D INPUT -p tcp -s 135.181.79.13 --dport 443 -j ACCEPT 2>/dev/null

# On attacker
ssh root@135.181.79.13 'sed -i /nocgurus/d /etc/hosts; rm -rf /tmp/xhe-poc /root/run_remote_suite.sh'
```
