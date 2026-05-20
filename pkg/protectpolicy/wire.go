package protectpolicy

import (
	"github.com/xhelix/xhelix/pkg/profiles/serviceid"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
	"github.com/xhelix/xhelix/pkg/takeover"
)

// SignalSink is the narrow contract this package needs from a
// Planner. takeover.Planner satisfies it via OnSignal.
type SignalSink interface {
	OnSignal(s takeover.Signal)
}

// Wire is the standard dispatch glue: matcher → evaluator → planner.
// One Wire per daemon. All methods safe for concurrent use.
type Wire struct {
	Matcher *serviceid.Matcher
	Eval    *Evaluator
	Sink    SignalSink

	// OnDiscrepancy, if set, is called for every identity discrepancy
	// detected by the matcher — even though the original refusal
	// wasn't a RefuseIdentity. Lets the dispatcher log the
	// binary-swap details independently of the signal emission.
	OnDiscrepancy func(serviceName, discrepancy string)
}

// NewWire returns a Wire ready to plug into the dispatch loop.
func NewWire(m *serviceid.Matcher, sink SignalSink) *Wire {
	return &Wire{
		Matcher: m,
		Eval:    NewEvaluator(),
		Sink:    sink,
	}
}

// Handle resolves the refusal to a ProtectedService via the matcher,
// classifies it into a Signal, and pushes it into the planner.
// Returns the emitted signal (zero-value if none) so callers can
// log/trace.
func (w *Wire) Handle(rf RefusalEvent) takeover.Signal {
	var svc = w.resolve(rf)

	// Matcher-detected identity discrepancy is itself an attack
	// signal. Synthesize a RefuseIdentity event if the original
	// refusal kind wasn't already that — so a binary swap that
	// caused some OTHER refusal still emits the identity signal.
	if rf.Discrepancy != "" && rf.Kind != RefuseIdentity {
		if w.OnDiscrepancy != nil {
			w.OnDiscrepancy(rf.ServiceName, rf.Discrepancy)
		}
		idRf := rf
		idRf.Kind = RefuseIdentity
		if s := w.Eval.Evaluate(idRf, svc); s.Kind != "" && w.Sink != nil {
			w.Sink.OnSignal(s)
		}
	}

	sig := w.Eval.Evaluate(rf, svc)
	if sig.Kind == "" {
		return sig
	}
	if sig.Source == "" && rf.ServiceName != "" {
		sig.Source = "protectpolicy:" + rf.ServiceName
	}
	if w.Sink != nil {
		w.Sink.OnSignal(sig)
	}
	return sig
}

// resolve consults the matcher when the refusal doesn't already
// carry a resolved ServiceName. We trust prefilled names (eBPF
// programs often populate them from a cgroup_id lookup table).
func (w *Wire) resolve(rf RefusalEvent) *protectedsvc.ProtectedService {
	if w.Matcher == nil {
		return nil
	}
	if rf.PID == 0 && rf.CGroupID == 0 {
		return nil
	}
	v := w.Matcher.MatchPID(rf.PID, rf.CGroupID)
	if !v.Matched {
		// Non-empty Discrepancy on a non-match means the matcher saw
		// the cgroup/unit but the verifier rejected it (binary swap,
		// uid change). Surface to OnDiscrepancy for logging.
		if v.Discrepancy != "" && w.OnDiscrepancy != nil {
			name := ""
			if v.Service != nil {
				name = v.Service.Name
			}
			w.OnDiscrepancy(name, v.Discrepancy)
		}
		return nil
	}
	return v.Service
}
