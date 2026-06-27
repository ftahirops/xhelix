package synth

import (
	"github.com/xhelix/xhelix/pkg/brp"
	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

// BuildProfile assembles a CANDIDATE profile from observed behavior. It is
// always ConfidenceUnprofiled — a learned candidate, never a minted strict
// profile. ListenPorts/ReadRoots are left empty (not synthesizable from
// recorder data) and that limit is recorded in ParseWarnings.
func BuildProfile(o Observed, globThreshold int) brp.Profile {
	beh := parser.ConfigDerivedBehavior{
		ExecAllowed:   GeneralizeExecPaths(ExecEnvelope(o)),
		UpstreamHosts: EgressHosts(o),
		WriteRoots:    GeneralizeWriteRoots(o, globThreshold),
		ParseWarnings: []string{
			"synthesized from observed behavior; ListenPorts and ReadRoots are not " +
				"derivable from recorder data (no listen/read edges) and were left empty",
		},
	}
	return brp.Profile{
		SchemaVersion: 1,
		ProfileID:     "synth-" + o.App,
		Confidence:    brp.ConfidenceUnprofiled,
		SampleCount:   o.SampleCount,
		Key:           parser.ProfileKey{App: o.App},
		Behavior:      beh,
	}
}
