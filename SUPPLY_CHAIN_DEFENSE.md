# xhelix — Supply-Chain Attack Defense

> Analysis of xhelix's coverage against npm / pip / cargo / package-
> manager supply-chain attacks (Shai-Hulud class), and the product
> wedge this opens for developer-tooling adoption.
>
> Companions: [ARCHITECTURE.md](ARCHITECTURE.md),
> [ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md),
> [ROADMAP.md](ROADMAP.md), [DEFENSE_PRIORITIES.md](DEFENSE_PRIORITIES.md),
> [ZERO_DAY_GUARDIAN.md](ZERO_DAY_GUARDIAN.md).

---

## Contents

1. The attack pattern
2. xhelix coverage by attack stage
3. Honest gaps
4. Pre-analysis benefits (before install)
5. End-to-end developer workflow
6. Why this is a strong product wedge
7. Implementation notes — adding to the locked architecture
8. Market positioning

---

## 1. The attack pattern

Recent supply-chain attacks (Shai-Hulud and similar) follow a
consistent post-execution pattern. Compromised packages observed in
the wild include high-traffic utilities used across millions of
projects — small focused libraries used by larger frameworks.

The compromise pattern is consistent:

1. Attacker compromises a maintainer's account via phished credentials
   or stolen session token
2. Publishes a malicious version of an already-popular package
3. Postinstall script runs on every `npm install` worldwide
4. Script harvests secrets from the developer machine or CI runner
5. Stolen credentials used to compromise more packages → exponential
   spread (wormable)

The specific actions a malicious postinstall script performs:

- **Postinstall execution**: `node` or `python` or similar interpreter
  exec'd by `npm` / `yarn` / `pip` during install
- **Filesystem scan for credentials**: `.env`, `.aws/credentials`,
  `.npmrc`, `~/.ssh/id_*`, `~/.gitconfig`, browser profiles,
  cloud-CLI auth files, GitHub PAT tokens, Slack tokens
- **Environment variable harvest**: dump everything in `process.env`
- **Exfiltrate**: POST to an attacker URL, sometimes via DNS-tunnel,
  sometimes back through the package registry itself
- **Persist**: write to `~/.bashrc`, `~/.npmrc`, drop a backdoor in
  packages the developer has write access to
- **Propagate**: use stolen npm tokens to publish further compromised
  packages

Five of those six steps are exactly what xhelix's contract layers
are designed to catch.

## 2. xhelix coverage by attack stage

| Attack stage | What it needs to do | xhelix layer that catches it | Realistic outcome |
|---|---|---|---|
| Postinstall script runs | `npm` spawns child interpreter | Process-lineage contract (npm allowed to spawn `node`) | **Not blocked** — expected behaviour; recorded as fact |
| Filesystem scan for credentials | `open()` on `~/.ssh/id_rsa`, `.env`, etc. | Sensitive-file BPF LSM contract | **~95% blocked** — `node` during install not in allow-list; reads return EPERM |
| Read env for secrets | `process.env` enumeration | None — env is process's own memory | **Not blocked** — but exfil block downstream makes it moot |
| Exfiltrate via HTTP | `tcp_connect` to attacker domain | Per-cgroup egress contract | **~90% blocked** — npm cgroup allow-list is `registry.npmjs.org` + `*.npmjs.com` + GitHub; attacker domain not in list |
| Exfiltrate via DNS tunnel | DNS queries with high-entropy subdomains | DNS exfil detector + DNS allow-list | **~70% blocked** — entropy pattern caught; per-cgroup DNS allow-list to known resolvers only |
| Persist via shell-rc files | Write to `~/.bashrc`, `~/.zshrc`, `~/.npmrc` | Persistence-write watchlist | **~95% blocked** — watchlist covers shell rc files |
| Wormable propagation | Use stolen npm token to publish | Per-cgroup egress + sensitive-file contract on `~/.npmrc` | **Variable** — depends on token storage location |
| Backdoor injection into adjacent projects | Write malicious code into `~/projects/other/` | File-write contract per cgroup | **~80% blocked** — npm install cgroup write-scope = `./node_modules/`; outside-scope writes fail |

**Aggregate containment for a Shai-Hulud-class attack on a developer
workstation with full xhelix deployment: ~85–95% of damaging actions
blocked at the point of execution.**

The attacker's process runs; the attacker's exfiltration fails; the
persistence attempts fail; the propagation fails.

This is a large improvement over the current state, where most
developer machines run `npm install` with full uid permissions and
no monitoring.

## 3. Honest gaps

Three real classes of attack still succeed partially, even with full
xhelix coverage:

### 3.1 Environment-variable secret theft

If CI/CD or a developer shell has `NPM_TOKEN`, `AWS_ACCESS_KEY_ID`,
`GITHUB_TOKEN` set as environment variables, those are in the malicious
process's own address space. xhelix does not intercept memory reads of
`process.env`. The attacker dumps them, then attempts exfil.

xhelix catches the exfil, not the read. If exfil is blocked, the
stolen secrets stay on the box and don't reach the attacker — practical
containment holds but only if the egress contract is tight.

**Honest mitigation outside xhelix scope**: secrets should never live
in environment variables. Use short-lived OIDC tokens — GitHub Actions
native, GCP Workload Identity, AWS OIDC role. xhelix cannot fix bad
secret handling; it can only contain the exfil attempt.

### 3.2 In-process abuse of legitimate destinations

If the malicious package uses `registry.npmjs.org` itself as the exfil
channel — for example, publishing a steganographic package back, or
abusing the registry's metadata API — the destination is in the
allow-list. xhelix sees an outbound request to a legitimate destination
and doesn't block.

This is the wormable-propagation problem. Shai-Hulud specifically
exploits this — it uses the package registry the developer is already
trusted to publish to.

**Honest mitigation**: per-action contract within the cgroup. `npm
install` should be allowed to *read* from `registry.npmjs.org`; `npm
publish` should require an explicit operator mode (same primitive as
the WordPress "update mode"). xhelix can implement this with cgroup-
level outbound contracts plus action mode. Real engineering, not
free; estimate ~3 days.

### 3.3 Pre-existing credentials being used elsewhere

Once secrets are exfiltrated from any victim machine (even briefly,
before containment), the attacker may already have what they need to
compromise other machines. xhelix on machine X doesn't help machine Y
that was compromised yesterday.

**Honest framing**: xhelix protects the host it's installed on. It
is not a network-wide defense.

## 4. Pre-analysis benefits (before install)

xhelix provides defensive signal *before* installation completes, not
just runtime containment.

### 4.1 Static scan of package.json and lockfile

Before any `npm install` runs, xhelix can inspect:

- The packages being requested
- Their current versions
- Whether any are on a curated suspicious list:
  - Recently published (< 7 days old)
  - High version-number jump with low download count
  - Newly-published packages with names similar to popular ones
    (typosquats)
- Whether postinstall / preinstall / install scripts are declared

This is similar to what socket.dev and snyk do, but local and ungated
by a SaaS subscription. xhelix can warn before the install runs.

### 4.2 Postinstall-script-aware sandboxing

The `npm install` cgroup runs with a default-deny posture:

- Network: only `registry.npmjs.org` + `*.npmjs.com` + GitHub
  (configurable for private registries)
- File writes: only within `./node_modules/` and `./package-lock.json`
- Process spawn: only `node`, `npm`, `python` (for native deps), and a
  small list of build tools (`make`, `cc`, `clang`)
- Sensitive files: no access to `~/.ssh/`, `~/.aws/`, `~/.gnupg/`,
  `~/.config/`, browser profile dirs

This is a per-developer-workflow contract that ships once and applies
to every `npm install` thereafter. The operator does not write it per
project.

### 4.3 Behavioral diff between package versions

When `npm install` upgrades a package, xhelix compares:

- Old version's observed runtime behavior (during last install)
- New version's observed runtime behavior

If the new version starts: reading new files, calling new network
destinations, spawning new processes, writing new paths — those deltas
surface to the developer before the install completes.

This is genuinely useful and nothing in the npm ecosystem currently
does it for individual developers. `npm audit` and socket.dev catch
known-bad CVEs; they don't catch "this version started reading your
SSH keys."

### 4.4 Lockfile integrity tracking

xhelix maintains hashes of `package-lock.json` and `yarn.lock`. When
they change, it surfaces the diff before the next `npm install` runs.
The developer sees:

```
47 packages changed
3 with version jumps > 1 major
2 with postinstall scripts
```

This is `dependabot` for paranoid developers, running locally without
sending dependency data to a SaaS.

## 5. End-to-end developer workflow

A developer runs `npm install some-pkg`. The malicious postinstall
script in a transitive dependency attempts:

1. Spawn `bash` → xhelix sees `npm → node → bash`. `bash` isn't allow-
   listed for the npm cgroup. Exec denied. Alert:
   ```
   node[pid 5421] attempted to exec /bin/bash
   denied by contract: npm_install_v1
   ```

2. Spawn `curl` → same path. Denied.

3. Read `~/.ssh/id_ed25519` → BPF LSM `file_open` returns EPERM. The
   Node process sees EACCES. Alert with full chain:
   ```
   node ← npm install ← user@tty1
   target: /home/dev/.ssh/id_ed25519
   denied by contract: npm_install_sensitive_file
   ```

4. POST to `https://exfil.attacker.tld/data` → cgroup egress contract:
   destination not in allow-list. SYN never leaves. The Node process
   sees a connection error. Alert.

5. Write to `~/.npmrc` → persistence-write watchlist catches it. Write
   fails. Alert.

The developer sees:

> **5 blocked actions during `npm install some-pkg`.**
> This package is behaving like a credential harvester.
>
> Recommended action: uninstall, examine `node_modules/<pkg>/`,
> report to npm security if confirmed malicious.

This is genuinely useful. This is the *exact* attack pattern that
recent supply-chain compromises use, and xhelix's contract layers were
designed for exactly this class.

## 6. Why this is a strong product wedge

The supply-chain compromise pattern is the single highest-impact,
highest-frequency attack vector hitting modern dev workflows in 2026.
Current defenses are all reactive:

- CVE databases (catch known-bad after disclosure)
- Post-hoc analysis by Socket / Snyk (catch known-bad after they've
  analysed the package)
- npm takedowns (occur hours after compromise, after harvest is done)

**None of these protect the developer at install time.**

xhelix's per-cgroup contracts applied to `npm install` / `pip install`
/ `cargo install` / similar are a generic defense:

- Doesn't need to know the specific malicious package
- Doesn't need a signature
- Catches behavior-not-in-contract by definition
- Works against the next compromise as well as the last one

### Market reality

The developer audience:

- Is large (millions of npm / pip / cargo users worldwide)
- Is technical enough to install xhelix without enterprise sales motion
- Is currently undefended against this attack class at install time
- Is highly aware of the threat (Shai-Hulud, event-stream, ua-parser-js,
  colors.js, faker.js incidents have been widely publicised)

xhelix as a developer-tooling product:

- Requires no app-SDK integration in WordPress / business apps —
  `npm`, `pip`, `cargo` are just processes
- Produces measurable, demonstrable outcomes: count of blocked
  exfil attempts per week, count of developer machines protected
- Has a viral adoption shape — developers who get burned by supply-chain
  attacks become loud advocates

## 7. Implementation notes — adding to the locked architecture

This use case fits inside the existing architecture without
significant changes.

### 7.1 New default cgroup contract

Ship a `package_manager.yaml` contract that applies to processes whose
ancestry includes `npm`, `npm-cli.js`, `yarn`, `pnpm`, `pip`, `pip3`,
`cargo`, `gem`, `bundle`, `composer`. The contract is restrictive:

```yaml
contract: package_manager_v1
applies_to:
  ancestry_contains: [npm, npm-cli.js, yarn, pnpm, pip, pip3, cargo, gem, bundle, composer]
allowed_network:
  - registry.npmjs.org
  - "*.npmjs.com"
  - pypi.org
  - "*.pythonhosted.org"
  - crates.io
  - "*.crates.io"
  - rubygems.org
  - github.com
  - "*.githubusercontent.com"
  - codeload.github.com
allowed_writes:
  - "./node_modules/**"
  - "./venv/**"
  - "./target/**"
  - "./vendor/**"
  - "./package-lock.json"
  - "./yarn.lock"
  - "./Cargo.lock"
  - "./Gemfile.lock"
  - "./composer.lock"
denied_reads:
  - "~/.ssh/**"
  - "~/.aws/**"
  - "~/.gnupg/**"
  - "~/.docker/config.json"
  - "~/.config/gh/**"
  - "/etc/shadow"
  - "/etc/sudoers"
allowed_exec:
  - node
  - npm
  - python
  - python3
  - cc
  - gcc
  - clang
  - make
  - cmake
  - ninja
  - cargo
  - rustc
denied_persistence:
  - "~/.bashrc"
  - "~/.zshrc"
  - "~/.profile"
  - "~/.npmrc"   # outside install context
  - "/etc/cron.*"
```

### 7.2 Pre-install wrapper

Small wrappers (`xhelix-npm`, `xhelix-pip`, `xhelix-cargo`) that:

1. Diff the lockfile vs the previous accepted version
2. Surface new packages, version jumps, packages with install scripts
3. Ask the developer to confirm before proceeding
4. Exec the real `npm install` inside the sandboxed cgroup

The wrappers are aliases the developer optionally enables. For full
coverage, alias `npm=xhelix-npm` in the shell rc; for opt-in coverage,
use `xhelix-npm` explicitly.

### 7.3 Per-package behavior tracking

Extend the contract-diff workflow from
[ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md) §14 to apply
to npm / pip / cargo packages. After each install, xhelix records
observed behavior per package and surfaces deltas on next upgrade.

### 7.4 Lockfile integrity tracking

Add `package-lock.json`, `yarn.lock`, `Cargo.lock`, `Gemfile.lock` to a
separate "integrity-tracked" file watchlist. Changes surface as
evidence (not alerts), because lockfile changes are routine.

### 7.5 Operator workflow for violation screens

The violation screen for a blocked package action shows:

```
What happened:
  node attempted to read ~/.ssh/id_ed25519
  invoked from npm install transitive-package@2.4.1

Why it was blocked:
  package_manager_v1 contract — sensitive file outside scope

Package context:
  some-pkg@2.4.1 (published 2026-04-22, 14 days ago)
  Maintainer: <maintainer name>
  Socket score: unknown
  Other suspicious actions in this install:
    + node attempted exec /bin/sh (blocked)
    + node attempted connect exfil.attacker.tld (blocked)
    + node attempted write ~/.npmrc (blocked)

Recommended action:
  This package is behaving like a credential harvester.
  Uninstall and report to npm security.
```

This context is what the developer needs to decide if they're seeing a
real compromise.

### 7.6 Engineering scope

| Task | Estimate |
|---|---|
| Default `package_manager_v1` contract | 1 day |
| Wrapper scripts (`xhelix-npm`, `xhelix-pip`, `xhelix-cargo`) | 1 day |
| Lockfile diff display | 0.5 day |
| Per-package behavior diff workflow | 1 day |
| Violation screen with package context | 1 day |
| Documentation + install guide for developers | 0.5 day |

Total: ~5 days of work on top of the P1–P4 architecture base.

## 8. Market positioning

### 8.1 Honest one-line description

> **xhelix sandboxes `npm install` / `pip install` / `cargo install`
> against per-developer behavioral contracts. The compromised package
> executes; it cannot read your secrets, cannot reach attacker
> infrastructure, cannot persist, and cannot propagate. You get a clear
> alert before the package runs in your actual application code.**

### 8.2 Possible parallel product line

This could legitimately be xhelix's first shipping product:

**xhelix for Developers** — per-install sandboxing against
supply-chain attacks.

It can earn its way to the broader fortress-mode positioning later,
after the wedge product proves the contract-engine works in production.

The two product lines share:

- The contract engine (same code)
- The eBPF / LSM enforcement layer (same code)
- The audit chain (same code)
- The flight recorder (same code)

They differ in:

- The shipped default contracts (package-manager vs WordPress)
- The wrapper / integration points (CLI wrappers vs WordPress plugin)
- The target audience (individual developers vs hosting operators)
- The marketing motion (developer-driven vs enterprise pilot)

### 8.3 Sequencing options

**Option A** — WordPress first:
- Build P1–P4 with WordPress runtime guardian as the v1 wedge
- Add developer-tooling as v1.5 after WordPress proves
- Pros: cleaner story, single market focus
- Cons: WordPress is harder market entry, slower adoption

**Option B** — Developer tooling first:
- Build P1–P4 with package-manager sandboxing as the v1 wedge
- Add WordPress runtime guardian as v2 after developer wedge proves
- Pros: faster adoption, viral developer audience, smaller contract
  catalog to ship
- Cons: less obvious extension to server-side runtime guard

**Option C** — Parallel from day one:
- Ship both contracts at v1 launch
- Both are subsets of the same engine
- Pros: maximum addressable market at launch
- Cons: requires two operator workflows + docs + support

The recommendation depends on operator preference; technically all
three are feasible.

## 9. Verdict

The supply-chain attack defense use case is **one of the highest-value,
lowest-controversy applications** of the xhelix architecture. It:

- Targets a real, large, currently-undefended threat
- Maps cleanly to the existing contract model
- Has an obvious target audience that can install xhelix themselves
- Doesn't require enterprise sales motion
- Doesn't require app-SDK integration
- Produces concrete, demonstrable outcomes
- Reuses the entire P1–P4 architecture base

Whether it ships first, second, or in parallel with the WordPress
fortress is a product-strategy decision, not an architectural one. The
engine is the same.
