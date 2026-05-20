package forensic

import (
	"sort"
	"sync"
	"time"
)

// Co-occurrence rules — borrowed from IDE Shepherd's static-source-
// analysis layer (P-PS.20). When two independent IOC kinds appear
// from the same source (BeaconID / SessionID / pid-key) within a
// time window, the combination is a much stronger indicator than
// either alone. Examples (Shepherd → us):
//
//   download_and_execute   = URL + Command(exec/spawn equivalent)
//   reverse_shell          = IPv4/IPv6 raw socket + Command shell
//   eval_dynamic_payload   = Base64Payload + Command (eval-like)
//   detached_unref_pattern = Command + ChmodExec
//
// Single-signal misses the combo; two-signal-in-same-source +
// within-window catches the malicious composition with a low
// false-positive rate.

// CoRule defines one composite detection rule.
type CoRule struct {
	// ID is the human-readable rule identifier emitted in alerts.
	ID string
	// Need is the set of IOC kinds that must ALL be seen from the
	// same Source within Window for the rule to fire.
	Need []Kind
	// Window is the maximum age delta between the earliest and
	// latest contributing observation. Zero = unbounded.
	Window time.Duration
	// Severity carried into the Hit. Free-form so operators can
	// keep their own taxonomy.
	Severity string
	// Description is the human-readable text on a fire.
	Description string
}

// Hit is what the engine returns when a CoRule's predicate is
// satisfied. Caller decides what to do (emit an alert, escalate
// confidence on the contributing IOCs, etc).
type Hit struct {
	RuleID         string
	Source         string    // BeaconID / SessionID that linked the kinds
	At             time.Time // youngest contributing observation
	Severity       string
	Description    string
	Contributors   []KindValue // (kind, value) pairs that fired the rule
}

// KindValue is the (kind, value) tuple from one contributing IOC.
type KindValue struct {
	Kind  Kind
	Value string
	At    time.Time
}

// CoEngine evaluates CoRules against a stream of Observations. The
// engine maintains a per-source ring buffer of recent observations
// (one per kind we care about) and fires a Hit when the rule's
// Need set is fully covered within Window.
type CoEngine struct {
	mu    sync.Mutex
	rules []CoRule
	// per-source per-kind latest observation
	state map[string]map[Kind]Observation
}

// NewCoEngine returns an engine with the given rule set. Pass
// DefaultCoRules() for the standard set.
func NewCoEngine(rules []CoRule) *CoEngine {
	return &CoEngine{
		rules: rules,
		state: map[string]map[Kind]Observation{},
	}
}

// Observe ingests one observation and returns any Hit triggered by
// this observation in any rule. Returns nil if no rule fires.
//
// The engine is incremental: each Observe checks if the new
// observation completes any pending rule for its Source. It does
// NOT walk historic observations from other sources — by design,
// a rule's signals must come from one source (one session, one
// beacon, one lineage).
func (e *CoEngine) Observe(o Observation) []Hit {
	if o.Source == "" || o.Kind == "" {
		return nil
	}
	if o.At.IsZero() {
		o.At = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	bySrc, ok := e.state[o.Source]
	if !ok {
		bySrc = map[Kind]Observation{}
		e.state[o.Source] = bySrc
	}
	bySrc[o.Kind] = o

	var hits []Hit
	for _, r := range e.rules {
		if h, ok := e.evalLocked(r, o.Source); ok {
			hits = append(hits, h)
		}
	}
	return hits
}

// evalLocked runs one rule against one source's state. Caller
// holds e.mu.
func (e *CoEngine) evalLocked(r CoRule, source string) (Hit, bool) {
	bySrc, ok := e.state[source]
	if !ok {
		return Hit{}, false
	}
	contributors := make([]KindValue, 0, len(r.Need))
	var youngest, oldest time.Time
	for i, k := range r.Need {
		obs, ok := bySrc[k]
		if !ok {
			return Hit{}, false
		}
		contributors = append(contributors, KindValue{
			Kind: obs.Kind, Value: obs.Value, At: obs.At,
		})
		if i == 0 || obs.At.After(youngest) {
			youngest = obs.At
		}
		if i == 0 || obs.At.Before(oldest) {
			oldest = obs.At
		}
	}
	if r.Window > 0 && youngest.Sub(oldest) > r.Window {
		return Hit{}, false
	}
	return Hit{
		RuleID:       r.ID,
		Source:       source,
		At:           youngest,
		Severity:     r.Severity,
		Description:  r.Description,
		Contributors: contributors,
	}, true
}

// Forget drops all state for a source. Caller invokes after a
// session ends / a beacon connection closes.
func (e *CoEngine) Forget(source string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.state, source)
}

// Sources returns every source the engine is tracking. Mainly for
// dashboards.
func (e *CoEngine) Sources() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, 0, len(e.state))
	for s := range e.state {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// DefaultCoRules returns the standard rule set adapted from
// IDE Shepherd's static-source-analysis layer (P-PS.20 borrows).
//
// These rules fire when xhelix's deception layers capture two
// independent indicators FROM THE SAME ATTACKER SESSION within a
// reasonable window. The combinations are far stronger signals
// than either kind alone.
func DefaultCoRules() []CoRule {
	return []CoRule{
		{
			ID:          "cooccur.download_and_execute",
			Need:        []Kind{KindURL, KindCommand},
			Window:      5 * time.Minute,
			Severity:    "high",
			Description: "Attacker fetched a remote URL AND executed a command within one session — RCE payload-delivery pattern",
		},
		{
			ID:          "cooccur.reverse_shell",
			Need:        []Kind{KindIPv4, KindCommand},
			Window:      5 * time.Minute,
			Severity:    "high",
			Description: "Attacker opened raw outbound to a remote IP AND ran shell commands — reverse-shell composition",
		},
		{
			ID:          "cooccur.eval_dynamic_payload",
			Need:        []Kind{KindBase64, KindCommand},
			Window:      2 * time.Minute,
			Severity:    "high",
			Description: "Attacker decoded a base64 payload AND ran a command — obfuscated-payload-execution pattern",
		},
		{
			ID:          "cooccur.cred_exfil_chain",
			Need:        []Kind{KindAWSKey, KindURL},
			Window:      10 * time.Minute,
			Severity:    "high",
			Description: "AWS access key surfaced AND outbound URL referenced — credential exfiltration pattern",
		},
		{
			ID:          "cooccur.c2_command_chain",
			Need:        []Kind{KindBeaconHost, KindCommand},
			Window:      10 * time.Minute,
			Severity:    "high",
			Description: "Sinkholed beacon target observed AND shell command run — C2 → command-execution chain",
		},
		{
			ID:          "cooccur.fingerprinted_callback",
			Need:        []Kind{KindJA3, KindBeaconHost},
			Window:      5 * time.Minute,
			Severity:    "high",
			Description: "Distinct JA3 fingerprint AND beacon target captured from same session — confirms malware family",
		},
	}
}
