package correlator

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/xhelix/xhelix/pkg/model"
)

// Rule is a parsed correlation rule.
type Rule struct {
	ID          string         `yaml:"id"`
	Desc        string         `yaml:"desc"`
	SeverityRaw string         `yaml:"severity"`
	Severity    model.Severity `yaml:"-"`
	Mitre       []string       `yaml:"mitre"`
	Window      time.Duration  `yaml:"window"`
	GroupBy     []string       `yaml:"group_by"`
	Steps       []Step         `yaml:"steps"`
	Remediation string         `yaml:"remediation"`
	Narrative   string         `yaml:"narrative"`
}

// Step is one stage in a sequence-style correlation rule.
type Step struct {
	Select string        `yaml:"select"`
	Within time.Duration `yaml:"within"`
}

// Normalize parses the textual severity into a typed severity. The
// caller passes Rules into Engine.Load after Normalize.
func (r *Rule) Normalize() error {
	if s, ok := model.ParseSeverity(r.SeverityRaw); ok {
		r.Severity = s
	} else if r.SeverityRaw != "" {
		return fmt.Errorf("rule %s: invalid severity %q", r.ID, r.SeverityRaw)
	}
	return nil
}

type compiledRule struct {
	Rule     *Rule
	Compiled []cel.Program
}

func (e *Engine) compile(r *Rule) (*compiledRule, error) {
	if err := r.Normalize(); err != nil {
		return nil, err
	}
	out := make([]cel.Program, len(r.Steps))
	for i, s := range r.Steps {
		ast, iss := e.env.Compile(s.Select)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("step %d: %w", i, iss.Err())
		}
		prg, err := e.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
		if err != nil {
			return nil, fmt.Errorf("step %d program: %w", i, err)
		}
		out[i] = prg
	}
	return &compiledRule{Rule: r, Compiled: out}, nil
}

func buildEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("event", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("group", cel.MapType(cel.StringType, cel.StringType)),
	)
}
