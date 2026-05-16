// Package hub is the fleet-baseline server. Agents (xhelix) ship
// their per-binary feature aggregates here every few minutes; the hub
// computes cross-fleet "rare endpoint" lists and serves them back to
// agents.
//
// Wire format is identical to baseline.Window — agents Marshal these
// directly. The hub doesn't try to be clever; it appends to a per-day
// JSONL file and computes simple aggregates on demand.
//
// Phase 3 scope: ingest + rare-endpoint cross-fleet detection. ML and
// k-means clustering are explicitly Phase 4.
package baselinehub

import (
	"time"

	"github.com/xhelix/xhelix/pkg/baseline"
)

// Upload is the wire-format payload an agent POSTs to /api/upload.
//
// We use a thin envelope (host metadata + array of windows) rather
// than one POST per window so agents on slow networks don't drown
// the hub in connections.
type Upload struct {
	HostTag    string             `json:"host_tag"`
	RoleTag    string             `json:"role_tag,omitempty"`
	HostnameOS string             `json:"hostname_os,omitempty"`
	XhelixVer  string             `json:"xhelix_ver,omitempty"`
	UploadedAt time.Time          `json:"uploaded_at"`
	Windows    []*baseline.Window `json:"windows"`
}

// IngestStats reports counters surfaced by GET /api/stats.
type IngestStats struct {
	UploadsTotal  uint64    `json:"uploads_total"`
	WindowsTotal  uint64    `json:"windows_total"`
	BytesTotal    uint64    `json:"bytes_total"`
	UniqueHosts   int       `json:"unique_hosts"`
	UniqueBinaries int      `json:"unique_binaries"`
	OldestWindow  time.Time `json:"oldest_window"`
	NewestWindow  time.Time `json:"newest_window"`
}

// RareEndpoint is one cross-fleet aggregate row.
type RareEndpoint struct {
	Binary   string `json:"binary"`
	Endpoint string `json:"endpoint"` // "203.0.113.0/16:443"
	HostsSeen int   `json:"hosts_seen"`
	TotalHosts int  `json:"total_hosts"`
	Rarity    float64 `json:"rarity"` // 1.0 - hosts_seen/total_hosts
}

// RareList is what GET /api/rare/<binary> returns. Agents pull this
// and compare against their own baseline; endpoints in the rare list
// that are also in the agent's per-host new-endpoint output get
// elevated to higher severity (statistical confidence from the fleet
// view).
type RareList struct {
	Binary    string         `json:"binary"`
	GeneratedAt time.Time    `json:"generated_at"`
	TotalHosts int           `json:"total_hosts"`
	RarityCutoff float64     `json:"rarity_cutoff"` // entries returned have rarity >= this
	Rare      []RareEndpoint `json:"rare"`
}
