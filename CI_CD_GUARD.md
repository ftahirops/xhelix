# xhelix CI/CD Guard

> Phase-aware CI/CD supply-chain sandbox. Goes beyond runtime
> package-install sandboxing (covered in
> [SUPPLY_CHAIN_DEFENSE.md](SUPPLY_CHAIN_DEFENSE.md)) to enforce
> capability separation across the entire build → publish → deploy
> pipeline.
>
> Companions: [ARCHITECTURE.md](ARCHITECTURE.md),
> [SUPPLY_CHAIN_DEFENSE.md](SUPPLY_CHAIN_DEFENSE.md),
> [ENTERPRISE_ARCHITECTURE.md](ENTERPRISE_ARCHITECTURE.md),
> [AUTO_ADVISOR.md](AUTO_ADVISOR.md).

---

## Contents

1. The three real problems
2. Solution principle — remove the value, do not trust the process
3. CI job separation
4. xhelix-ci-guard module
5. Action-aware egress (the registry-abuse fix)
6. npm publish as an explicit mode
7. Stolen-credential org response
8. Pre-analysis (before install)
9. Dynamic sandbox + canary secrets
10. Capability-token broker
11. Concrete CI policy example
12. The one engineering rule
13. Final summary

---

## 1. The three real problems

### 1.1 Environment-variable secret theft

When a malicious npm package runs inside a CI job with:

```
NPM_TOKEN
GITHUB_TOKEN
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

…in the environment, the malicious code can read them from
`process.env`, `/proc/self/environ`, or its own memory. xhelix cannot
reliably stop the in-process read.

xhelix catches the exfil, not the read.

The real fix: **do not put valuable long-lived secrets in the build /
install process.** GitHub's OIDC model exists for exactly this — workflows
request short-lived cloud tokens at runtime instead of storing long-lived
credentials.

### 1.2 Legitimate destination abuse

`registry.npmjs.org` is in the allow-list because `npm install` needs
it. Malware can therefore exfiltrate by publishing a steganographic
package to the same registry. A destination-only allow-list does not
distinguish these:

- `npm install` = read packages (legitimate during install phase)
- `npm publish` = upload package (legitimate only during publish phase)
- `npm owner add` = change ownership (dangerous)
- `npm token create` = dangerous

The fix is action-aware egress, not destination-only.

### 1.3 Already-stolen credentials reused elsewhere

xhelix on host A cannot protect host B if host B was compromised
yesterday and the attacker already has the credentials. This is an
organisation-level problem, not a host problem.

---

## 2. Solution principle

> Make malicious dependency code run in a place where it has nothing
> valuable to steal and nowhere dangerous to send it.

| Bad model | Better model |
|---|---|
| `AWS_ACCESS_KEY_ID` in env | GitHub OIDC → short-lived AWS role |
| `NPM_TOKEN` in env | npm Trusted Publishing / OIDC |
| `GITHUB_TOKEN` visible to all steps | minimum `permissions:` per job |
| secrets present during `npm install` | no secrets during dependency install |
| same job installs and publishes | split install / build / test / publish jobs |

This is the most important shift: the runtime sandbox is the second
line of defence. The first line is removing the value before the
malicious code ever runs.

---

## 3. CI job separation

Do **not** run install + build + test + publish + deploy inside one
powerful job. Split into capability phases:

| Job | Secrets | Network | Publish | Cloud API |
|---|---|---|---|---|
| Dependency install | none | registry read-only | impossible | denied |
| Build / test | none or minimal | limited | impossible | denied |
| Publish | OIDC only | npm publish endpoint only | yes | denied |
| Deploy | OIDC cloud role | environment-scoped | denied | scoped to one env |

Each job is its own capability boundary. Compromise in the install
job cannot escalate to publish or deploy.

---

## 4. xhelix-ci-guard module

A dedicated CI subsystem with these components:

```
CI runner
  → xhelix phase controller
    → dependency sandbox
      → registry proxy
        → package scanner
          → egress firewall
            → secret broker
              → publish / deploy gate
```

| Component | Purpose |
|---|---|
| Phase controller | install / build / test / publish / deploy modes |
| Secret broker | secrets only released to approved phase |
| Registry proxy | download-only vs publish enforcement |
| Package pre-analyzer | inspect package before install |
| Sandbox runner | run install scripts with no real secrets |
| Egress firewall | no unknown outbound |
| Canary secrets | fake secrets to catch stealers |
| OIDC enforcer | no long-lived tokens |
| Provenance verifier | only trusted packages / builds |
| Policy compiler | per-repo / per-package rules |

---

## 5. Action-aware egress

OS-level eBPF normally sees only IP, port, process, bytes — TLS hides
HTTP method and path. To enforce action-aware registry rules:

| Method | Strength | Notes |
|---|---|---|
| npm wrapper | good | wrap `npm`, `pnpm`, `yarn` commands |
| Egress HTTP proxy | strong | sees method/path with CI client config |
| Registry mirror / proxy | very strong | CI only talks to controlled registry |
| OIDC publish-only job | very strong | publish impossible outside publish job |
| Domain allowlist only | weak | cannot distinguish install vs publish |

**Recommended architecture**:

```
CI job → xhelix registry proxy → npm registry
```

The proxy enforces:

- Install job can download only
- Publish job can publish only with OIDC and approved release context

---

## 6. npm publish as an explicit mode

Same primitive as the WordPress update mode:

| Phase | Behaviour |
|---|---|
| `npm install` mode | read registry only; no publish capability |
| `npm publish` mode | requires signed tag + release workflow + OIDC; no long-lived `NPM_TOKEN`; no arbitrary postinstall |

The rule: **`npm publish` is impossible unless CI is in publish
mode.** Not just: `registry.npmjs.org` is allowed.

npm Trusted Publishing (OIDC) is the canonical way to achieve this.

---

## 7. Stolen-credential org response

Single-host xhelix protects the host where installed. The
organisation-level mitigation:

| Problem | Mitigation |
|---|---|
| Old stolen npm token | Remove long-lived tokens; rotate everything |
| Old stolen AWS key | Disable IAM user; use OIDC roles |
| Stolen GitHub token | Reduce token permissions; rotate / revoke |
| Poisoned published package | Provenance verification; lockfile pinning; package allow-list |
| Infected CI runner | Ephemeral runners; clean images; no reused workspace |
| Lateral spread | Separate publish / deploy roles per repo / package |

GitHub Actions with AWS: create an OIDC identity provider and IAM role
so the runner assumes a role at runtime instead of using static keys.

---

## 8. Pre-analysis (before install)

Inspect each package before allowing install:

- `package.json` declarations
- Lifecycle scripts: `preinstall`, `install`, `postinstall`
- `bin` entries
- Network-call references in source
- Process-spawn references in source
- Filesystem paths referenced that look like secret stores
- Obfuscation markers
- New maintainer or unusual version anomaly
- Lockfile diff vs previously-accepted state
- Package provenance (SLSA / sigstore)

Example pre-analysis output:

```
Package: suspicious-lib@2.4.1

Risk findings:
  - new postinstall script added
  - source references process-spawn primitives
  - source reads process.env
  - source references AWS_ACCESS_KEY_ID
  - outbound URL not registry-related
  - maintainer changed recently
  - obfuscated JS payload

Recommended action:
  block install in CI
```

Useful before runtime, not only as runtime containment.

---

## 9. Dynamic sandbox + canary secrets

### 9.1 Run install in a fake environment first

Sandbox install with:

- No real secrets
- Fake AWS key
- Fake GitHub token
- Fake npm token
- Fake home directory
- Controlled network
- Temporary filesystem

If the package tries to:

- Read env secrets
- Connect to unknown domain
- Write GitHub workflow files
- Modify `package.json` in unexpected places
- Spawn shell utilities
- Publish package

…it is marked malicious before the real install runs.

### 9.2 Canary secrets

Inject fake secrets that should never appear in legitimate traffic:

```
AWS_ACCESS_KEY_ID=AKIA_FAKE_XHELIX_CANARY
NPM_TOKEN=npm_fake_xhelix_canary
GITHUB_TOKEN=ghp_fake_xhelix_canary
```

Any process that emits these values to the network is, by construction,
a confirmed stealer. Extremely low false-positive rate.

---

## 10. Capability-token broker

Instead of giving a job long-lived credentials, the job requests
capability at runtime:

```
Job → Broker:
  I am repo X
  Workflow Y
  Branch main
  Signed tag v1.2.3
  Phase deploy
  Need permission deploy-staging
```

Broker returns a short-lived token only if all conditions are met.

This makes secrets:

- Scoped (one specific action)
- Short-lived (minutes, not months)
- Phase-bound (only during deploy)
- Non-reusable (audit trail)

---

## 11. Concrete CI policy example

```yaml
repo: my-org/my-package

phases:
  dependency_install:
    secrets: none
    allow_network:
      - registry.npmjs.org:read
      - github.com:read
    deny:
      - npm_publish
      - git_push
      - cloud_api
      - unknown_outbound
      - read_home_secrets

  test:
    secrets: none
    allow_network: none

  publish:
    requires:
      - git_tag
      - protected_branch
      - OIDC
      - release_approval
    allow_network:
      - registry.npmjs.org:publish
    deny:
      - dependency_lifecycle_scripts
      - unknown_outbound

  deploy:
    requires:
      - OIDC
      - protected_environment
    allow_cloud_role:
      - deploy-staging-only
```

---

## 12. The one engineering rule

**Never let this happen**:

```
npm install
  + real secrets
  + publish token
  + cloud token
  + unrestricted network
```

That single combination is how wormable supply-chain attacks succeed.

**Correct posture**:

```
install phase:
  no secrets
  no publish permission
  read-only registry
  sandboxed filesystem
  controlled network
```

---

## 13. Final summary

The three real problems map to ten concrete mitigations:

1. Remove long-lived secrets from CI
2. Never expose real secrets during dependency install
3. Use OIDC / trusted publishing for npm and cloud providers
4. Split install / build / test / publish / deploy into capability phases
5. Make npm registry access action-aware, not just domain-aware
6. Use xhelix registry proxy or wrapper to distinguish install from publish
7. Sandbox packages before install with canary secrets
8. Enforce local egress blocks so stolen secrets cannot leave
9. Use short-lived scoped tokens from a broker
10. Treat xhelix as host / CI protection, not magic protection for machines compromised elsewhere

The strongest single xhelix feature for this attack class:

> **Phase-aware CI containment.**
>
> xhelix makes malicious dependency code run in a place where it has
> nothing valuable to steal and nowhere dangerous to send it.
