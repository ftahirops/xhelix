package synth

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xhelix/xhelix/pkg/contractpropose"
)

// ErrNoData means the app has no recorded shapes yet — nothing to synthesize.
var ErrNoData = errors.New("synth: no recorded shapes for app")

// ErrInsufficientSamples means the app has SOME recorded behavior but below the
// sample-count gate — too thin to propose a trustworthy profile from. A single
// observation of an app over-fits to one run; the operator should wait for the
// behavior to recur before a candidate is worth reviewing.
var ErrInsufficientSamples = errors.New("synth: below minimum sample count")

// Propose gathers an app's recorded behavior, builds a candidate profile, and
// files it as a PENDING proposal for operator review. It never signs or loads.
// minSamples gates the proposal: an app whose total observation count is below
// it returns ErrInsufficientSamples (nothing filed) — so single-shot, over-fit
// candidates don't pollute the review queue. minSamples <= 1 disables the gate.
func Propose(r ShapeReader, store *contractpropose.Store, appID string, globThreshold, minSamples int) (contractpropose.Proposal, error) {
	o, err := Gather(r, appID)
	if err != nil {
		return contractpropose.Proposal{}, err
	}
	if o.SampleCount == 0 {
		return contractpropose.Proposal{}, ErrNoData
	}
	if minSamples > 1 && o.SampleCount < minSamples {
		return contractpropose.Proposal{}, ErrInsufficientSamples
	}
	prof := BuildProfile(o, globThreshold)
	js, err := json.Marshal(prof)
	if err != nil {
		return contractpropose.Proposal{}, err
	}
	return store.Create(contractpropose.Proposal{
		App:       appID,
		Status:    contractpropose.StatusPending,
		Submitter: "synthesizer",
		Reason: fmt.Sprintf("synthesized from %d observations: %d exec, %d egress hosts, %d write roots",
			o.SampleCount, len(prof.Behavior.ExecAllowed), len(prof.Behavior.UpstreamHosts), len(prof.Behavior.WriteRoots)),
		DeclarationJSON: js,
	})
}
