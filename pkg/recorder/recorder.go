package recorder

import (
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Recorder gates on SP-2's learnable flag, accumulates chains, and flushes
// them to the store on Tick. Nil-safe at the call site (pipeline guards nil).
type Recorder struct {
	acc *Accumulator
	st  *Store
}

func New(acc *Accumulator, st *Store) *Recorder { return &Recorder{acc: acc, st: st} }

// Observe records only learnable events (SP-2 flag encodes the full
// three-decision rule). Everything else is ignored.
func (r *Recorder) Observe(ev model.Event) {
	if ev.Tags["learnable"] != "true" {
		return
	}
	r.acc.Observe(ev)
}

// Tick flushes idle chains into the store and prunes old shapes. Driven by a
// ticker in run.go.
//
// All chains returned by FlushIdle are attempted regardless of store errors:
// FlushIdle has already removed them from the accumulator, so an early return
// would silently drop the remaining chains. The first error encountered is
// returned after all chains have been attempted.
func (r *Recorder) Tick(now time.Time) error {
	var firstErr error
	for _, c := range r.acc.FlushIdle(now) {
		if err := r.st.RecordChain(c); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if _, err := r.st.DropOld(now); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
