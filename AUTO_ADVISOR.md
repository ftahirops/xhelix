# xhelix Auto Advisor

> Passive, advisory companion to xhelix. Watches every activity on a
> developer or operator machine — code changes, git events, CI/CD
> runs, container activity, web-server lifecycle, package installs,
> credential file touches, network configuration — and surfaces
> security + best-practice findings without blocking anything.
>
> Auto Advisor is the **education / awareness** layer of xhelix.
> The main xhelix engine is the **enforcement** layer. They share
> the event plane and audit chain; they differ in posture.
>
> Companions: [ARCHITECTURE.md](ARCHITECTURE.md),
> [ROADMAP.md](ROADMAP.md), [CI_CD_GUARD.md](CI_CD_GUARD.md),
> [SUPPLY_CHAIN_DEFENSE.md](SUPPLY_CHAIN_DEFENSE.md),
> [ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md).

---

## Contents

1. Purpose and product framing
2. Design principles
3. What it watches (source catalog)
4. Rule catalog (the best-practice library)
5. Output model — findings + posture score
6. Architecture
7. Integration with main xhelix
8. UX patterns (right and wrong)
9. Implementation phases (A1 – A8)
10. Engineering scope per phase
11. What it deliberately does NOT do

---

## 1. Purpose and product framing

### 1.1 The gap it fills

Developers and operators don't lack security tools. They lack
**continuous, contextual, actionable feedback** about their own
environment. Existing tools fragment this:

- Linters check code, not runtime
- Secret scanners check git, not CI
- CVE scanners check dependencies, not behaviour
- EDRs check execution, not configuration
- Compliance tools check checklists, not real-time state

xhelix Auto Advisor is one always-on observer that joins all of these
signals into a single advisory feed: *"here is what your machine is
doing right now, and here are the issues I see."*

### 1.2 One-line product description

> **xhelix Auto Advisor watches everything happening on your machine
> and tells you, in plain English, what's risky and how to fix it.
> No agents to integrate. No blocking. Just clear, contextual
> security advice as you work.**

### 1.3 Target audience

- Solo developers running personal dev / staging boxes
- Small teams shipping their own product without dedicated security staff
- Operators managing single hosts (VPS, SOHO, homelab)
- DevOps engineers who want continuous posture feedback
- Anyone who wants xhelix's visibility without xhelix's enforcement risk

---

## 2. Design principles

1. **Advisory, never enforcing.** Auto Advisor never blocks, kills,
   denies, or modifies anything. It only observes and recommends.
2. **Passive, no SDK.** No code modification required by the developer.
   Auto Advisor works against whatever software the developer is using.
3. **Holistic, not siloed.** Covers code, dependencies, CI/CD,
   containers, web servers, databases, network, credentials, and OS
   state — joined by xhelix's existing event plane.
4. **Concrete, never vague.** Every finding includes: what was
   observed, why it's a concern, exactly how to fix it (with command
   or config snippet), severity, and a reference link.
5. **Educational, not punitive.** Wording is helpful, not scolding.
   Findings teach the developer something useful even when they
   choose not to act.
6. **Read-only by default.** Auto Advisor reads `/proc`, `/sys`, file
   contents, config files, git logs — but writes only its own findings
   to a private output store.
7. **Quiet when nothing matters.** A clean posture should produce no
   notifications. Findings are surfaced only when there is something
   actionable.
8. **Deterministic rules, no model inference.** Like the main xhelix
   engine, advisory findings come from a curated rule catalog with
   exact matchers, not statistical classification.

---

## 3. What it watches (source catalog)

Auto Advisor's input signal sources, grouped by category. All are
read-only.

### 3.1 Filesystem

| Source | What it gives |
|---|---|
| Git repos (`inotify` on `.git/`) | Commits, branches, pushes, stashes, merges |
| Source files (`inotify` on tracked paths) | File changes, additions, deletions |
| `.env`, `.envrc`, `.npmrc`, `.aws/credentials`, `~/.ssh/*` | Credential file presence, mode bits, content patterns |
| `package.json`, `requirements.txt`, `Cargo.toml`, `Gemfile`, `composer.json` | Dependency state |
| `package-lock.json`, `yarn.lock`, `Cargo.lock` | Pinned dependency hashes |
| `Dockerfile`, `docker-compose.yml`, `Containerfile` | Container build instructions |
| `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `bitbucket-pipelines.yml` | CI/CD pipeline definitions |
| `nginx.conf`, `apache2.conf`, `httpd.conf` | Web-server configuration |
| `/etc/systemd/system/*.service` | Service unit definitions |
| `/etc/cron.*`, user crontabs | Scheduled tasks |

### 3.2 Process events (via xhelix eBPF plane)

| Event | What it gives |
|---|---|
| `sched_process_exec` | Every new process — what was run, by whom, with what args |
| `tcp_connect` | Outbound connections — destination, port, owning process |
| `file_open` (sensitive paths) | Credential or config reads |
| `setuid` / `capset` | Privilege transitions |
| `mount` / `unshare` / `pivot_root` | Container lifecycle |
| `bpf` / `module_load` | Kernel-level changes |

### 3.3 Application events (passive, no SDK required)

| Source | What it gives |
|---|---|
| `journald` subscription | systemd unit start/stop, sshd logins, sudo events |
| Web-server access logs (configurable path) | Request volume, error patterns, status codes |
| Docker socket events (if accessible) | Container start/stop/exec |
| `git hook` invocations (via wrapper) | Pre-commit, post-commit, pre-push triggers |

### 3.4 Network state

| Source | What it gives |
|---|---|
| `ss -tnp` snapshots | Active TCP sockets and their owning processes |
| `/proc/net/tcp` parsing | Listening ports, established connections |
| `nft list ruleset` snapshots | Active firewall configuration |
| Interface state from `/sys/class/net/` | NIC up/down, MTU, IP assignments |

### 3.5 Identity and auth

| Source | What it gives |
|---|---|
| `journalctl _COMM=sshd` | SSH login events with source IP |
| `journalctl _COMM=sudo` | Sudo invocations |
| `~/.ssh/authorized_keys`, `/etc/sudoers.d/*` | Authorisation configuration |
| `/etc/passwd`, `/etc/group` | User and group state |

### 3.6 Cloud / config artifacts

| Source | What it gives |
|---|---|
| `~/.aws/config`, `~/.aws/credentials` | AWS profiles and credential presence |
| `~/.kube/config` | Kubernetes contexts |
| `~/.docker/config.json` | Docker registry credentials |
| `~/.config/gh/hosts.yml` | GitHub CLI authentication state |

---

## 4. Rule catalog (the best-practice library)

The advisory engine matches observed state against a curated rule
catalog. Each rule has: a name, a severity, a matcher, a finding
message, a fix suggestion, and a reference. Rules are organised by
domain.

### 4.1 Credentials & secrets (~30 rules)

Examples:

- **Secret in commit** — Pattern-match for `AWS_SECRET`, `password=`, `BEGIN PRIVATE KEY`, etc. in any commit. Severity: critical.
- **Long-lived AWS access key present** — `~/.aws/credentials` contains static keys (not OIDC/SSO). Severity: high. Fix: use AWS SSO or OIDC role assumption.
- **Unencrypted SSH private key** — `~/.ssh/id_*` exists without passphrase. Severity: medium. Fix: `ssh-keygen -p -f ~/.ssh/id_ed25519`.
- **`.env` committed to git** — `.env` tracked by git. Severity: critical. Fix: `git rm --cached .env && echo .env >> .gitignore`.
- **World-readable credential file** — Mode bits permit world-read on `~/.aws/credentials` etc. Severity: high. Fix: `chmod 600`.

### 4.2 CI/CD configuration (~25 rules)

Examples:

- **Workflow with `permissions: write-all`** — GitHub Actions workflow grants full token scope. Severity: high. Fix: scope to least privilege.
- **Long-lived secret referenced in workflow** — `${{ secrets.NPM_TOKEN }}` used where OIDC could work. Severity: medium. Fix: see [CI_CD_GUARD.md](CI_CD_GUARD.md).
- **Workflow runs on unrestricted `pull_request` trigger** — Untrusted fork PRs can run secrets-laden jobs. Severity: high. Fix: `pull_request_target` with required reviewer.
- **Missing job-level `permissions` declaration** — Inherits repo-level token scope. Severity: low. Fix: declare minimum scope per job.
- **Self-hosted runner without ephemeral mode** — Reusable runner state. Severity: medium. Fix: enable `--ephemeral`.

### 4.3 Docker / container (~20 rules)

Examples:

- **Container running as root** — `Dockerfile` lacks `USER` directive or `USER root` explicit. Severity: medium. Fix: add `USER appuser`.
- **`docker.sock` mounted into container** — Compose file or run command mounts `/var/run/docker.sock`. Severity: critical. Fix: remove unless absolutely required; understand the privilege escalation.
- **Container with `--privileged`** — Severity: critical.
- **`FROM ubuntu:latest`** — Mutable base tag. Severity: low. Fix: pin to digest or specific version.
- **No HEALTHCHECK in Dockerfile** — Severity: info.
- **Image runs with full capabilities** — `--cap-add=ALL` or no `--cap-drop`. Severity: medium.

### 4.4 Web server (~15 rules)

Examples:

- **Directory listing enabled in nginx** — `autoindex on;`. Severity: medium.
- **Server header reveals version** — `server_tokens on;`. Severity: low.
- **No HSTS header** — Severity: medium for HTTPS sites.
- **No Content-Security-Policy** — Severity: medium.
- **`access_log off;` on a production-looking server** — Severity: low (forensic gap).
- **TLS with weak ciphers permitted** — Severity: medium.

### 4.5 Database (~10 rules)

Examples:

- **MySQL listening on `0.0.0.0`** — Bound to all interfaces. Severity: high if firewall doesn't restrict.
- **PostgreSQL with `trust` auth in `pg_hba.conf`** — Severity: critical.
- **MongoDB without authentication enabled** — Severity: critical.
- **Database without TLS for remote connections** — Severity: medium.

### 4.6 Network (~10 rules)

Examples:

- **SSH listening on public IP** — Severity: medium. Fix: bind to localhost + WireGuard / Tailscale.
- **`/etc/ssh/sshd_config` permits root login** — `PermitRootLogin yes`. Severity: high.
- **`/etc/ssh/sshd_config` permits password auth** — Severity: medium. Fix: keys only.
- **Unused listening port** — Process listening but no recent traffic. Severity: info.

### 4.7 Process & runtime (~10 rules)

Examples:

- **Web worker spawned a shell in normal mode** — Severity: high (already a main xhelix alert).
- **`npm install` reading SSH key** — Severity: critical (already a main xhelix alert).
- **Long-running process with no parent in process tree** — Possible daemonised malware. Severity: medium.

### 4.8 Git & repository hygiene (~10 rules)

Examples:

- **Large binary file committed** — > 10 MB binary in git history. Severity: info.
- **Branch without protection rules** — On a remote with branch-protection capability. Severity: low.
- **Force push to `main` / `master`** — Severity: medium.
- **Commits not signed** — Severity: low.

### 4.9 OS state (~10 rules)

Examples:

- **Kernel >180 days unpatched** — `uname -r` vs distro current. Severity: medium.
- **`unattended-upgrades` disabled** — On Debian-family. Severity: low.
- **Firewall (nft/iptables) has no rules** — Default-allow posture. Severity: medium.
- **No swap configured and memory pressure high** — Severity: info.

### 4.10 Cloud / IAM hygiene (~15 rules)

Examples:

- **AWS root account access keys present** — Severity: critical.
- **IAM user with `AdministratorAccess` policy** — Severity: high.
- **`kubeconfig` with long-lived service-account token** — Severity: medium.
- **Stored cloud credentials without MFA enforced** — Severity: medium.

**Catalog total**: ~155 rules across 10 domains. Tractable to curate
and maintain. Operators can extend with custom rules.

---

## 5. Output model — findings + posture score

### 5.1 Per-finding shape

```json
{
  "id": "advisor.cred.aws_static_keys",
  "severity": "high",
  "domain": "credentials",
  "title": "Long-lived AWS access keys detected",
  "observed": {
    "path": "~/.aws/credentials",
    "profile": "default",
    "key_id_prefix": "AKIA"
  },
  "why": "Static AWS access keys live forever once leaked. Modern AWS deployments use SSO or OIDC role-assumption for short-lived credentials.",
  "fix_command": "aws configure sso",
  "fix_doc_link": "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html",
  "first_seen": "2026-05-12T08:32:11Z",
  "last_seen": "2026-05-19T14:21:00Z",
  "acknowledged": false
}
```

### 5.2 Severity scale

| Severity | Meaning | Example |
|---|---|---|
| **critical** | Immediate compromise risk | Secret committed to public repo |
| **high** | Substantial risk; should be fixed within days | Static AWS keys present |
| **medium** | Real issue; fix in next routine maintenance | SSH password auth enabled |
| **low** | Best-practice gap | Server header reveals version |
| **info** | Awareness-only; usually no action | Large binary in git history |

### 5.3 Posture score

A single number 0–100 summarising overall machine health.

Computation:

```
score = 100
       - 25 × number_of_critical
       - 10 × number_of_high
       - 3  × number_of_medium
       - 1  × number_of_low
       (floor 0)
```

Tuned so a perfectly clean machine scores 100; a typical
unhardened-but-not-compromised machine scores 60–80; an obviously
broken machine scores < 40.

Posture score appears in three places:
- Daily digest email / notification
- Auto Advisor dashboard header
- (Optional) Shell prompt indicator

### 5.4 Output channels

| Channel | When |
|---|---|
| Real-time desktop notification | New critical or high finding |
| Daily digest | All open findings, grouped by severity |
| Weekly summary | Posture trend + new vs resolved findings |
| Dashboard (web UI on `127.0.0.1`) | Live state, always available |
| `xhelix-advisor list` CLI | Power-user shell access |
| `xhelix-advisor fix <id>` CLI | One-line apply of suggested fix (with confirmation) |

---

## 6. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Input signal sources                                         │
│ ─────────────────────                                        │
│  inotify on git repos + config dirs                          │
│  xhelix eBPF event plane (process/file/network)              │
│  journald subscription (sshd/sudo/systemd)                   │
│  /proc + /sys snapshots (network/firewall/kernel state)      │
│  CI/CD YAML parsers                                          │
│  Dockerfile / Compose parsers                                │
│  Web-server config parsers                                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Normalisation layer                                          │
│ Every input becomes a CanonicalObservation struct            │
│ (kind, source, target, time, details)                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Rule engine                                                  │
│ Matches observations against the curated rule catalog        │
│ Each rule fires zero or more findings                        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Finding store (SQLite)                                       │
│ Open findings, resolved findings, acknowledged findings      │
│ Dedupe by (rule.id, observed.identity)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┬──────────────┐
        ▼              ▼              ▼              ▼
   ┌─────────┐  ┌─────────────┐  ┌─────────┐  ┌──────────────┐
   │ Web UI  │  │ Notifier    │  │ CLI     │  │ Digest mailer│
   │ /helix  │  │ (desktop/   │  │ tool    │  │ (cron)       │
   │ advisor │  │  webhook)   │  │         │  │              │
   └─────────┘  └─────────────┘  └─────────┘  └──────────────┘
```

### 6.1 Shared event plane with main xhelix

The advisor reuses the main xhelix eBPF events. It does not run its
own kernel-side collectors. This:

- Eliminates duplicate kernel overhead
- Guarantees the advisor sees what the enforcer sees
- Allows correlation between advisory findings and enforcement events

### 6.2 Separate storage from main xhelix

The advisor has its own SQLite database for findings, distinct from
xhelix's audit chain. Findings are not security events; they're
advisory state.

### 6.3 Posture score is local-only by default

The score never leaves the host unless the operator explicitly opts
into a fleet roll-up (a Phase A8+ feature, out of MVP scope).

---

## 7. Integration with main xhelix

| Boundary | How they interact |
|---|---|
| Event plane | Advisor reads from the same eBPF event stream xhelix's main engine consumes |
| Storage | Separate SQLite database; advisor never writes to xhelix's audit chain |
| Notification | Advisor's notifier is independent; xhelix's verified alerts are higher-priority and route to a different UI |
| Disable independently | Operator can run main xhelix without Advisor or Advisor without main xhelix; they share code but have separate process lifecycles |
| Rule sharing | Advisor rules and main-xhelix rules live in different catalogs but can cross-reference (e.g., a main-xhelix verified alert can include "see also advisory finding X") |
| Posture score visible in main xhelix UI | Optional banner showing current advisory state — does not affect enforcement |

The two systems are deliberately **loosely coupled**. Main xhelix is
trust-critical; Advisor is awareness-helpful.

---

## 8. UX patterns (right and wrong)

### 8.1 Right

- **"You have 3 high-severity findings."** Specific count.
- **"Static AWS keys in `~/.aws/credentials`. Switch to SSO: `aws configure sso`."** Concrete fix.
- **"Acknowledge for 30 days"** — Time-bound dismissal with reason.
- **Weekly trend graph**: posture score over time.
- **"Why this matters"** expandable section per finding.
- **Severity icons** with semantic colour (critical = red, high = amber, etc.).

### 8.2 Wrong

- **"Your machine is insecure!"** — Vague, alarming, unhelpful.
- **"Click here to fix all issues"** — Implies enforcement; advisor never modifies.
- **"You scored 47/100. This is bad."** — Shame-based UI.
- **"Permanent dismiss"** — Findings should always be reviewable.
- **Push notifications every time anything changes** — Noise.
- **Cumulative "5 new findings since you last looked"** without showing what they are.

### 8.3 Notification policy

- Critical: real-time notification, dashboard banner
- High: daily digest, dashboard
- Medium / Low: dashboard only; surfaced only when operator opens it
- Info: dashboard only; available on request

This keeps the operator focused on what matters without training
them to ignore notifications.

---

## 9. Implementation phases

| Phase | Name | Days | Status |
|---|---|---:|---|
| **A1** | File watchers + canonical observations | 3 | planned |
| **A2** | CI/CD + Dockerfile + web-server config parsers | 4 | planned |
| **A3** | System event integration (journald + xhelix eBPF) | 2 | planned |
| **A4** | Rule catalog v1 (~155 rules across 10 domains) | 8 | planned |
| **A5** | Finding store + dedupe + acknowledge workflow | 2 | planned |
| **A6** | Advisory dashboard + CLI | 4 | planned |
| **A7** | Notifier + daily digest | 2 | planned |
| **A8** | Posture scoring + trend graph | 2 | planned |

**Total**: ~27 days for a complete v1. Most-valuable subset
(A1 + A2 + A4 + A5 + A6) is ~21 days and is shippable alone.

---

## 10. Engineering scope per phase

### 10.1 Phase A1 — File watchers + canonical observations (3 days)

- inotify-based watcher for configurable paths
- Canonical `Observation` struct: `{kind, source, target, time, details}`
- Per-source watchers: git repos, ~/.config dirs, /etc, /var
- Bounded queue, drop oldest on overflow

### 10.2 Phase A2 — Config parsers (4 days)

- YAML parser for `.github/workflows/`, `.gitlab-ci.yml`, `bitbucket-pipelines.yml`
- Dockerfile parser (no full Docker BuildKit; just directive extraction)
- nginx / apache config parser (header / location / server-block extraction)
- systemd unit parser (directive extraction)
- Each parser produces `Observation` records

### 10.3 Phase A3 — System event integration (2 days)

- Subscribe to xhelix's eBPF event channel (already exists)
- Subscribe to journald via sd-bus
- Map events to `Observation` records
- Filter early to reduce volume

### 10.4 Phase A4 — Rule catalog v1 (8 days)

- ~155 rules across 10 domains (Section 4)
- Each rule: matcher function + finding template + fix suggestion + reference
- Rules expressed in Go (compiled, fast) with YAML for finding text
- Test harness: every rule has at least one positive and one negative test case

### 10.5 Phase A5 — Finding store (2 days)

- SQLite schema: findings, acknowledgements, fix attempts, history
- Dedupe key: `(rule_id, observed.identity_hash)`
- Acknowledge with TTL; revoke acknowledgements
- Trend storage: daily snapshots of finding counts

### 10.6 Phase A6 — Dashboard + CLI (4 days)

- Web UI on localhost:11380 (separate from main xhelix UI)
- Sections: open findings, posture score, trends, settings, rule catalog
- CLI: `xhelix-advisor list`, `xhelix-advisor show <id>`, `xhelix-advisor ack <id> --ttl=30d`
- Optional: `xhelix-advisor fix <id>` — runs the suggested fix with confirmation

### 10.7 Phase A7 — Notifier + digest (2 days)

- Desktop notification via `notify-send` (Linux) or webhook (configurable)
- Daily digest via local mail or webhook
- Configurable notification severity threshold

### 10.8 Phase A8 — Posture scoring + trends (2 days)

- Score computation per Section 5.3
- 30-day rolling history
- Trend graph in dashboard
- Optional shell-prompt integration via `xhelix-advisor score`

---

## 11. What it deliberately does NOT do

To stay focused and trustworthy, Auto Advisor explicitly does not:

- **Block, kill, deny, or modify anything.** Ever. That's main xhelix's
  job. Advisor's value is undermined the moment it acts.
- **Phone home.** No telemetry to a SaaS by default. Posture data stays
  on the host unless the operator opts into fleet roll-up.
- **Auto-apply fixes without confirmation.** Every `fix` command
  shows the exact changes before applying.
- **Score-shame.** No "your machine is bad" language. Findings are
  educational.
- **Replace dedicated tools.** Advisor is a generalist; for deep
  static analysis use Semgrep / CodeQL; for secret scanning use
  TruffleHog / gitleaks; for CVE scanning use OSV / Snyk. Advisor
  complements; it doesn't compete.
- **Maintain a real-time vulnerability database.** Rules are
  curated and updated with the product; the advisor is not a CVE
  feed consumer.
- **Make security decisions on behalf of the operator.** It
  observes and recommends. The operator decides.

---

## 12. Verdict

xhelix Auto Advisor is the **observability + education layer** that
complements xhelix's **enforcement layer**. Together they cover the
two halves of operator security: knowing what's wrong (Advisor) and
preventing bad outcomes (xhelix main engine).

For developers and operators who aren't ready to deploy enforcement
mode, Advisor provides immediate value with zero risk of breakage. It
becomes the obvious on-ramp to the full xhelix posture.

The product positioning:

> **xhelix Auto Advisor watches your machine continuously and
> tells you, in plain English, what's risky and how to fix it.
> No agents to write. No blocking. Just clear, contextual security
> advice as you work.**

Total engineering scope: ~27 days for v1, of which ~21 days is the
shippable core. Reuses xhelix's event plane. Has its own storage,
its own UI, and its own lifecycle. Disable-independent from the
main engine.

This is the easiest xhelix product to adopt, the easiest to demo,
and the easiest to value-prop in one sentence.
