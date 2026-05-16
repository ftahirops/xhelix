// Package explain turns a rule-id + match context into a
// human-readable "why this fired and why it matters" paragraph.
//
// Every working EDR ships these. Analysts need to know, in plain
// English: what behaviour triggered this, what attack class it
// belongs to, what to check next. Without it, every alert is
// "rule X fired" and the analyst burns minutes context-switching
// into the rulebook.
//
// The package is pure: a Registry of rule explanations + a
// Render(ruleID, ctx) function that fills templates with context
// values. Pure-Go text/template under the hood; no I/O.
package explain

import (
	"bytes"
	"sort"
	"sync"
	"text/template"
)

// Severity grades how seriously to treat an explanation. Mirrors
// the EDR-wide severity ladder for one-table joins.
type Severity uint8

const (
	SeverityInfo     Severity = 1
	SeverityNotice   Severity = 2
	SeverityWarn     Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

// String returns a stable lowercase token.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityNotice:
		return "notice"
	case SeverityWarn:
		return "warn"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// Rule describes one rule's explanation template.
type Rule struct {
	// ID matches the rule_id used in pkg/alert and pkg/alertdedupe.
	ID string

	// Title is one short line (≤80 chars) for the UI list view.
	Title string

	// Body is a Go text/template string rendered against the
	// caller's Context. Common pipes: {{.Exe}}, {{.DstIP}},
	// {{.Country}}, {{.QName}}, {{.Reason}}.
	Body string

	// Severity is the rule's default severity. Per-firing context
	// can still override via the resulting Severity field.
	Severity Severity

	// AttackPhase is the rough kill-chain phase: reconnaissance,
	// initial-access, execution, persistence, privesc, exfil, etc.
	AttackPhase string

	// Mitigation is one-line operator advice.
	Mitigation string
}

// Rendered is the resulting human-readable explanation.
type Rendered struct {
	RuleID      string
	Title       string
	Body        string
	Severity    Severity
	AttackPhase string
	Mitigation  string
}

// Registry holds rule explanations.
type Registry struct {
	mu    sync.RWMutex
	rules map[string]ruleEntry
}

type ruleEntry struct {
	rule Rule
	tmpl *template.Template
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{rules: map[string]ruleEntry{}}
}

// Register adds or replaces a rule. Returns an error when the
// Body template fails to parse.
func (r *Registry) Register(rule Rule) error {
	if rule.ID == "" {
		return errEmpty
	}
	tmpl, err := template.New(rule.ID).Parse(rule.Body)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.rules[rule.ID] = ruleEntry{rule: rule, tmpl: tmpl}
	r.mu.Unlock()
	return nil
}

// MustRegister is the panic-on-error variant for the bundled
// default registry initialisation.
func (r *Registry) MustRegister(rule Rule) {
	if err := r.Register(rule); err != nil {
		panic(err)
	}
}

// Render produces the explanation for ruleID. Unknown rule IDs
// fall back to a generic explanation derived from ctx so the UI
// always has *something* to show.
func (r *Registry) Render(ruleID string, ctx Context) Rendered {
	r.mu.RLock()
	e, ok := r.rules[ruleID]
	r.mu.RUnlock()
	if !ok {
		return Rendered{
			RuleID:   ruleID,
			Title:    ruleID + " fired",
			Body:     "No explanation registered for this rule.",
			Severity: SeverityNotice,
		}
	}
	var buf bytes.Buffer
	if err := e.tmpl.Execute(&buf, ctx); err != nil {
		return Rendered{
			RuleID:   ruleID,
			Title:    e.rule.Title,
			Body:     "(template render error: " + err.Error() + ")",
			Severity: e.rule.Severity,
		}
	}
	return Rendered{
		RuleID:      ruleID,
		Title:       e.rule.Title,
		Body:        buf.String(),
		Severity:    e.rule.Severity,
		AttackPhase: e.rule.AttackPhase,
		Mitigation:  e.rule.Mitigation,
	}
}

// IDs returns every registered rule id, sorted.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	out := make([]string, 0, len(r.rules))
	for id := range r.rules {
		out = append(out, id)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Len returns the rule count.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules)
}

// Context is the data passed to templates. Optional fields stay
// empty; templates that reference missing fields render as
// blanks rather than failing.
type Context struct {
	PID         uint32
	Comm        string
	Exe         string
	ExeSHA      string
	ParentExe   string
	DstIP       string
	DstPort     uint16
	Country     string
	ASN         string
	QName       string
	UserID      string
	CGroupClass string
	Reason      string
}

// ── default registry ──────────────────────────────────────────

// DefaultRegistry returns a Registry pre-loaded with the bundled
// xhelix rules. Each rule's Body is a single short paragraph
// suitable for the journal "Reasons" line.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	for _, rule := range bundled {
		r.MustRegister(rule)
	}
	return r
}

var bundled = []Rule{
	{
		ID: "beacon.periodic_callback",
		Title: "Periodic callback to a remote host — possible C2 beacon",
		Body: `Process {{.Comm}} ({{.Exe}}) has been making low-jitter periodic ` +
			`connections to {{.DstIP}}:{{.DstPort}}. This pattern matches Cobalt ` +
			`Strike / Sliver / Mythic / custom-Go RAT beaconing — the implant ` +
			`phones home on a fixed cadence so the operator's queue stays ` +
			`responsive. Independent of payload content, the rhythm itself is ` +
			`high signal.`,
		Severity: SeverityHigh, AttackPhase: "command-and-control",
		Mitigation: "Quarantine the process, snapshot forensics, block the destination IP.",
	},
	{
		ID: "intel.bad_ip",
		Title: "Connection to a known-malicious IP",
		Body: `{{.Comm}} contacted {{.DstIP}} which appears in a curated threat-` +
			`intel feed (Spamhaus DROP / Tor exits / FireHOL). {{.Reason}}`,
		Severity: SeverityHigh, AttackPhase: "command-and-control",
		Mitigation: "Investigate the connection's purpose; consider blocking the IP at the network edge.",
	},
	{
		ID: "netids.dga",
		Title: "DGA-shaped domain query",
		Body: `Query for {{.QName}} matches the statistical pattern of a Domain ` +
			`Generation Algorithm — high-entropy second-level labels, irregular ` +
			`vowel-consonant alternation. Commodity malware uses DGAs to outrun ` +
			`takedowns of fixed C2 domains.`,
		Severity: SeverityHigh, AttackPhase: "command-and-control",
		Mitigation: "Investigate the resolving process; check for new persistence near the time of the query.",
	},
	{
		ID: "dnsexfil.tunnel_pattern",
		Title: "DNS tunnelling traffic",
		Body: `{{.Comm}} resolved {{.QName}} as part of a DNS-tunnel-shaped ` +
			`exchange — many small queries to one registrable root, with high ` +
			`label entropy and an unusual TXT fraction. dnscat2 / iodine / ` +
			`custom DNS implants exfiltrate over this channel.`,
		Severity: SeverityHigh, AttackPhase: "exfiltration",
		Mitigation: "Block the registrable root at the DNS shim; check for staged data files.",
	},
	{
		ID: "country.first_contact",
		Title: "Process contacted a new destination country",
		Body: `{{.Comm}} ({{.Exe}}) reached {{.Country}} for the first time in ` +
			`its baseline window. Compare against expected behaviour — most ` +
			`binaries have a narrow country set.`,
		Severity: SeverityWarn, AttackPhase: "exfiltration",
		Mitigation: "Confirm whether the destination is legitimate (e.g., a CDN POP rotation) before alerting.",
	},
	{
		ID: "bandwidth.spike",
		Title: "Unusually large outbound transfer",
		Body: `{{.Comm}} ({{.Exe}}) sent bytes at a rate well above its rolling ` +
			`baseline. When the user is idle and the destination is unfamiliar, ` +
			`this is the textbook silent-exfil pattern.`,
		Severity: SeverityHigh, AttackPhase: "exfiltration",
		Mitigation: "Inspect the destination, check user session activity, consider SIGSTOP + snapshot.",
	},
	{
		ID: "lolbin.suspicious",
		Title: "Living-Off-The-Land binary used in suspicious context",
		Body: `{{.Comm}} (a LOLBin) was spawned by {{.ParentExe}}. Network ` +
			`daemons, mail processes, and web servers rarely launch downloaders ` +
			`or interpreters directly. {{.Reason}}`,
		Severity: SeverityHigh, AttackPhase: "execution",
		Mitigation: "Investigate the parent process; expect lateral movement or follow-on payload.",
	},
	{
		ID: "revshell.detected",
		Title: "Reverse-shell argv pattern matched",
		Body: `{{.Comm}} was invoked with argv matching a well-known reverse-` +
			`shell construct ({{.Reason}}). This is among the highest-confidence ` +
			`post-exploitation signals.`,
		Severity: SeverityCritical, AttackPhase: "execution",
		Mitigation: "Quarantine the process immediately; snapshot memory + filesystem state.",
	},
	{
		ID: "shm.exec",
		Title: "Execution from tmpfs",
		Body: `Binary at {{.Exe}} was executed from a tmpfs mount. Legitimate ` +
			`software almost never stages binaries on tmpfs; fileless droppers ` +
			`live here.`,
		Severity: SeverityHigh, AttackPhase: "execution",
		Mitigation: "SIGKILL the process; check for parent and persistence elsewhere.",
	},
	{
		ID: "persistence.added",
		Title: "New persistence mechanism added",
		Body: `A new persistence file appeared at {{.Reason}}. Cron / systemd ` +
			`units / ld.so.preload / PAM modules are top-tier backdoor surfaces.`,
		Severity: SeverityHigh, AttackPhase: "persistence",
		Mitigation: "Audit the new file's source; compare against the package owner.",
	},
	{
		ID: "cap.gained",
		Title: "Process gained dangerous capability",
		Body: `{{.Comm}} ({{.Exe}}) gained one or more capabilities ({{.Reason}}) ` +
			`via capset(2). CAP_SYS_ADMIN is near-root; CAP_SYS_MODULE allows ` +
			`kernel modification; CAP_BPF allows runtime kernel observation.`,
		Severity: SeverityCritical, AttackPhase: "privilege-escalation",
		Mitigation: "Investigate why the process needs this; benign use is rare.",
	},
	{
		ID: "container.privileged",
		Title: "Privileged container running",
		Body: `Container {{.Reason}} is running with privileged-class options. ` +
			`Privileged containers can escape to the host with little effort; ` +
			`legitimate use cases are narrow (docker-in-docker, debug shells).`,
		Severity: SeverityCritical, AttackPhase: "lateral-movement",
		Mitigation: "Verify the operator intent; tighten the spec if not required.",
	},
	{
		ID: "metadata.access_by_unexpected",
		Title: "Cloud metadata service touched by unexpected process",
		Body: `{{.Comm}} ({{.Exe}}) reached the cloud metadata service at ` +
			`{{.DstIP}}. The metadata service hands out short-lived IAM ` +
			`credentials; unexpected callers are usually SSRF or post-exploit ` +
			`harvesters.`,
		Severity: SeverityCritical, AttackPhase: "credential-access",
		Mitigation: "Rotate any credentials the caller could have retrieved; investigate the caller.",
	},
	{
		ID: "phishing.brand_lookalike",
		Title: "Brand-lookalike domain queried",
		Body: `Query for {{.QName}} matches a typo / homograph / combosquat of ` +
			`a known brand ({{.Reason}}). This is the credential-phishing signal: ` +
			`a user is about to be asked for credentials on a fake page.`,
		Severity: SeverityHigh, AttackPhase: "initial-access",
		Mitigation: "Banner the user; verify the request did not submit credentials.",
	},
	{
		ID: "hidden_proc.detected",
		Title: "Process hidden from userland enumeration",
		Body: `A pid was visible to the direct getdents64 syscall but absent ` +
			`from libc readdir — the signature of an LD_PRELOAD rootkit ` +
			`(Diamorphine, libprocesshider, etc.).`,
		Severity: SeverityCritical, AttackPhase: "defense-evasion",
		Mitigation: "Treat as a confirmed compromise; rebuild the host from known-clean media.",
	},
	{
		ID: "audit.framework_stopped",
		Title: "Audit framework stopped or rules flushed",
		Body: `auditd has stopped, or its rules were flushed. This is a classic ` +
			`anti-forensics step preceding the next stage of an attack.`,
		Severity: SeverityCritical, AttackPhase: "defense-evasion",
		Mitigation: "Restore the rules immediately; treat the timeline before this point as canonical.",
	},
}

// ── helpers ───────────────────────────────────────────────────

type sentinelErr string

func (s sentinelErr) Error() string { return string(s) }

const errEmpty sentinelErr = "explain: empty rule id"
