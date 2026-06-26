// Package recorder persists clean, attributable observed behavior as workflow
// chains grouped by (app_id, chain_id), deduplicated to a canonical shape with
// bounded raw exemplars per shape. It records only events SP-2 marked
// learnable. Pure observation: no alerts, no enforcement. SP-4 (Recorder).
package recorder

import (
	"path"
	"strings"

	"github.com/xhelix/xhelix/pkg/model"
)

type EdgeKind string

const (
	EdgeExec   EdgeKind = "exec"
	EdgeEgress EdgeKind = "egress"
	EdgeWrite  EdgeKind = "write"
	EdgeRead   EdgeKind = "read"
)

// Edge is one typed action in a workflow. Key is the coarsened identity used
// for the shape hash (so "same workflow, different leaf file" groups together);
// Raw is the full observed detail kept in exemplars for the Cycle-2 generalizer.
type Edge struct {
	Kind EdgeKind
	Key  string
	Raw  string
}

// EdgeFromEvent maps an event to a recordable edge, or ok=false if it is not
// one. Sensor names match those emitted in the pipeline (ebpf.spawn/proc,
// ebpf.net/net_connect, fim.drift).
func EdgeFromEvent(e model.Event) (Edge, bool) {
	switch e.Sensor {
	case "ebpf.spawn", "ebpf.proc":
		child := e.Comm
		if child == "" && e.Image != "" {
			child = path.Base(e.Image)
		}
		if child == "" {
			return Edge{}, false
		}
		return Edge{Kind: EdgeExec, Key: child, Raw: e.Image}, true
	case "ebpf.net", "net_connect":
		host := e.Tags["sni"]
		if host == "" {
			host = e.Tags["dst_ip"]
		}
		if host == "" {
			return Edge{}, false
		}
		port := e.Tags["dst_port"]
		key := host
		if port != "" {
			key = host + ":" + port
		}
		return Edge{Kind: EdgeEgress, Key: key, Raw: key}, true
	case "fim.drift":
		p := e.Tags["path"]
		if p == "" {
			return Edge{}, false
		}
		dir := path.Dir(p)
		return Edge{Kind: EdgeWrite, Key: dir, Raw: p}, true
	}
	return Edge{}, false
}

// edgeID is the stable string form of an edge's canonical identity, used when
// building a shape hash. Kept private; Task 2 consumes it.
func edgeID(e Edge) string { return string(e.Kind) + ":" + e.Key }

var _ = strings.TrimSpace // reserved for path normalization in later tasks
