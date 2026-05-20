package crashloop

import (
	"github.com/xhelix/xhelix/pkg/takeover"
)

// SignalSink is the narrow interface this sensor needs from a
// Planner. takeover.Planner satisfies it via OnSignal.
type SignalSink interface {
	OnSignal(s takeover.Signal)
}

// Halter is called when a crash loop fires. Caller implements it
// to systemctl-stop + mask the unit so it doesn't auto-restart back
// into the exploit. nil = skip the halt step (signal still fires).
type Halter interface {
	HaltService(serviceName, unitName string, decision *Decision) error
}

// HalterFunc adapts a function to the Halter interface.
type HalterFunc func(serviceName, unitName string, decision *Decision) error

// HaltService implements Halter.
func (f HalterFunc) HaltService(svc, unit string, d *Decision) error { return f(svc, unit, d) }

// Wire is the standard glue: Observe(crash) → emit signal + halt.
type Wire struct {
	Det    *Detector
	Sink   SignalSink
	Halter Halter

	// OnFire is invoked on each fire for logging/audit. Optional.
	OnFire func(*Decision)
	// OnHaltError is invoked when Halter returns non-nil. Optional.
	OnHaltError func(decision *Decision, err error)
}

// NewWire constructs a Wire. cfg is for the Detector.
func NewWire(cfg Config, sink SignalSink, halter Halter) *Wire {
	return &Wire{
		Det:    New(cfg),
		Sink:   sink,
		Halter: halter,
	}
}

// Handle observes the crash event. If it crosses the threshold,
// emits the takeover signal and halts the service. Returns the
// Decision (nil if no fire).
func (w *Wire) Handle(ev CrashEvent) *Decision {
	d := w.Det.Observe(ev)
	if d == nil {
		return nil
	}
	if w.Sink != nil {
		w.Sink.OnSignal(d.Signal)
	}
	if w.OnFire != nil {
		w.OnFire(d)
	}
	if w.Halter != nil {
		if err := w.Halter.HaltService(d.ServiceName, d.UnitName, d); err != nil && w.OnHaltError != nil {
			w.OnHaltError(d, err)
		}
	}
	return d
}

// Forget — see Detector.Forget.
func (w *Wire) Forget(svc string) { w.Det.Forget(svc) }
