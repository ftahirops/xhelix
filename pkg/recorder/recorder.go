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
func (r *Recorder) Tick(now time.Time) error {
	for _, c := range r.acc.FlushIdle(now) {
		if err := r.st.RecordChain(c); err != nil {
			return err
		}
	}
	_, err := r.st.DropOld(now)
	return err
}
