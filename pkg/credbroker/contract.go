package credbroker

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Contract is the per-binary policy that says "this image is
// allowed to receive credentials of these classes." It's the
// lineage-bound piece of the broker's decision input.
//
// Conceptually: the contract is the answer to "is the requesting
// process a thing we EXPECT to read this kind of credential?"
//
// Honest scope of USG.1b: contract is image-regex-based. USG.3
// upgrades the decision subject from "image" to "plugin/request/
// tenant" via the IDE/web/tenant bridges (the breakthrough that
// stops nx-console-class attacks — the COMPROMISED VS Code reads
// .aws/credentials and the contract says yes-to-code-but-no-to-
// nx-plugin because the plugin identity differs from the editor).
//
// USG.1b ships the image-regex baseline so the broker has SOME
// real policy today. The richer policy plugs into the same Match
// API later without changing the broker's call sites.
type Contract struct {
	Version  int            `yaml:"version"`
	Rules    []ContractRule `yaml:"rules"`
	// DefaultDeny when true means "any image not matched by a
	// Rule is denied." False means "fall through to allow with
	// audit" (USG.1b default for backward compat with the stub).
	DefaultDeny bool `yaml:"default_deny"`
}

// ContractRule is one allow rule for one binary class.
type ContractRule struct {
	Name           string   `yaml:"name"`
	// ImageRegex matches event.Image OR any ancestor Image in
	// the lineage. First-match-wins.
	ImageRegex string `yaml:"image_regex"`
	// AllowedClasses lists the credential classes this image may
	// receive. Class match is exact. Empty = no classes allowed.
	AllowedClasses []string `yaml:"allowed_classes"`
	// AttestRequired demands an out-of-band 2FA approval (Slack
	// interactive, phone push, etc.) for this rule. USG.1d wires
	// the channel; USG.1b records the bit so policy is forward-
	// compatible.
	AttestRequired bool `yaml:"attest_required"`
	// MaxFreshness — how recent the (future) Passport / Request
	// Contract must be. Zero means no freshness requirement.
	// USG.1b stub: we record but don't enforce; USG.3 wires.
	MaxFreshnessSeconds int `yaml:"max_freshness_seconds"`

	// Compiled regex (cached after Load).
	re *regexp.Regexp
}

// LoadContract reads a YAML contract from path. Missing file is
// not an error — returns the safe default (DefaultDeny=false,
// no rules — which matches the stubAllowAll behaviour).
func LoadContract(path string) (*Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Contract{Version: 1}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var c Contract
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// Compile regexes.
	for i := range c.Rules {
		r, err := regexp.Compile(c.Rules[i].ImageRegex)
		if err != nil {
			return nil, fmt.Errorf("rule %q image_regex: %w",
				c.Rules[i].Name, err)
		}
		c.Rules[i].re = r
	}
	return &c, nil
}

// MatchResult is what Match returns when looking up policy for a
// (lineage, class) pair.
type MatchResult struct {
	Matched        bool
	RuleName       string
	AttestRequired bool
	MaxFreshness   int
}

// Match looks up which rule (if any) authorises serving class to
// any binary in lineage. First-match-wins, searching root → leaf
// so an inner shell can't bypass an outer-process policy by
// matching only the inner shell's name.
func (c *Contract) Match(lineage []LineageNode, class Class) MatchResult {
	if c == nil {
		return MatchResult{}
	}
	for _, r := range c.Rules {
		if r.re == nil {
			continue
		}
		// Match any image in the lineage. We require the FIRST
		// (root-most) match to be the authoritative rule —
		// that's the design choice that prevents shell-in-shell
		// privilege smuggling.
		for _, n := range lineage {
			if r.re.MatchString(n.Image) || r.re.MatchString(n.Comm) {
				// Class check.
				for _, allowed := range r.AllowedClasses {
					if Class(allowed) == class {
						return MatchResult{
							Matched:        true,
							RuleName:       r.Name,
							AttestRequired: r.AttestRequired,
							MaxFreshness:   r.MaxFreshnessSeconds,
						}
					}
				}
				// Image matches but class isn't allowed. Don't
				// fall through to a less-specific rule.
				return MatchResult{Matched: false, RuleName: r.Name}
			}
		}
	}
	return MatchResult{}
}

// DefaultContract is the baked-in policy that ships with xhelix.
// Covers the common-case binaries that legitimately need
// credentials: aws-cli, gcloud, kubectl, helm, terraform, ansible,
// gh, git, ssh, docker, npm, pip, pipx, op (1Password CLI).
//
// Operators override or extend via /etc/xhelix/credbroker.yaml.
func DefaultContract() *Contract {
	return &Contract{
		Version:     1,
		DefaultDeny: false, // USG.1b: warn instead of deny by default
		Rules: []ContractRule{
			{
				Name:           "aws_cli",
				ImageRegex:     `(^|/)(aws|aws2)$`,
				AllowedClasses: []string{string(ClassAPIKey), string(ClassCredentials)},
			},
			{
				Name:           "gcloud",
				ImageRegex:     `(^|/)gcloud$`,
				AllowedClasses: []string{string(ClassAPIKey), string(ClassCredentials)},
			},
			{
				Name:           "kubectl",
				ImageRegex:     `(^|/)kubectl$`,
				AllowedClasses: []string{string(ClassAPIKey), string(ClassCredentials)},
			},
			{
				Name:           "github_cli",
				ImageRegex:     `(^|/)gh$`,
				AllowedClasses: []string{string(ClassAPIKey), string(ClassCredentials)},
			},
			{
				Name:           "terraform",
				ImageRegex:     `(^|/)terraform$`,
				AllowedClasses: []string{string(ClassAPIKey), string(ClassCredentials)},
				AttestRequired: true, // changes infra; require 2FA per doc §7.3
			},
			{
				Name:           "git",
				ImageRegex:     `(^|/)git$`,
				AllowedClasses: []string{string(ClassCredentials), string(ClassSourceCode)},
			},
			{
				Name:           "ssh_client",
				ImageRegex:     `(^|/)ssh$`,
				AllowedClasses: []string{string(ClassCredentials)},
			},
			{
				Name:           "docker_cli",
				ImageRegex:     `(^|/)docker$`,
				AllowedClasses: []string{string(ClassAPIKey), string(ClassCredentials)},
			},
			{
				Name:           "op_cli",
				ImageRegex:     `(^|/)op$`,
				AllowedClasses: []string{string(ClassAPIKey), string(ClassCredentials)},
				AttestRequired: true,
			},
			{
				Name:           "npm",
				ImageRegex:     `(^|/)npm$`,
				AllowedClasses: []string{string(ClassAPIKey)},
			},
			{
				Name:           "operator_xhelixctl",
				ImageRegex:     `xhelixctl$`,
				AllowedClasses: []string{
					string(ClassCredentials), string(ClassAPIKey),
					string(ClassBackup), string(ClassSourceCode),
				},
				AttestRequired: true,
			},
		},
	}
}
