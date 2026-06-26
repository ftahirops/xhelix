// Package recorder persists clean, attributable observed behavior as workflow
// chains grouped by (app_id, chain_id), deduplicated to a canonical shape with
// bounded raw exemplars per shape. It records only events SP-2 marked
// learnable. Pure observation: no alerts, no enforcement. SP-4 (Recorder).
package recorder

import (
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"path"
	"sort"

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

// ShapeHash is the order-independent, dedup-by-canonical-Key signature of a
// chain's edge-set. FNV-64a over the sorted unique edge IDs — an identity
// hash, not security. Same workflow structure → same hash regardless of leaf
// detail (Raw) or event order.
func ShapeHash(edges []Edge) string {
	seen := make(map[string]struct{}, len(edges))
	ids := make([]string, 0, len(edges))
	for _, e := range edges {
		id := edgeID(e)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := fnv.New64a()
	for _, id := range ids {
		_, _ = h.Write([]byte(id))
		_, _ = h.Write([]byte{0}) // separator: avoid "a"+"bc" == "ab"+"c"
	}
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], h.Sum64())
	return hex.EncodeToString(out[:])
}
