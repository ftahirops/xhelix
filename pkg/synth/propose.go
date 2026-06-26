package synth

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xhelix/xhelix/pkg/contractpropose"
)

// ErrNoData means the app has no recorded shapes yet — nothing to synthesize.
var ErrNoData = errors.New("synth: no recorded shapes for app")

// Propose gathers an app's recorded behavior, builds a candidate profile, and
// files it as a PENDING proposal for operator review. It never signs or loads.
func Propose(r ShapeReader, store *contractpropose.Store, appID string, globThreshold int) (contractpropose.Proposal, error) {
	o, err := Gather(r, appID)
	if err != nil {
		return contractpropose.Proposal{}, err
	}
	if o.SampleCount == 0 {
		return contractpropose.Proposal{}, ErrNoData
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
