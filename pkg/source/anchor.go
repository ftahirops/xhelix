// Package source implements the v2 SourceAnchor attribution substrate.
//
// A SourceAnchor is the persisted, parent-linked record of an
// authenticated or scheduled entry point on this host. Every event in
// the xhelix pipeline gets attributed to one or more anchors via
// pkg/lineage chains and the CausalSet model.
//
// Anchors are minted at trusted ingress points:
//
//   - sshd accept
//   - PAM session open
//   - sudo / su transition
//   - cron timer fire
//   - systemd unit start
//
// Each anchor carries a ParentAnchorID. A direct SSH login has parent=0.
// A sudo inside that session has parent=<ssh anchor id>. This forms the
// pivot chain that the source-graph query layer (T04) traverses to
// answer "everything this entry point caused".
//
// This package owns the persistent store; the in-memory lineage.Origin
// in pkg/lineage is still the hot-path identity record. Anchors are
// derived from Origins at mint time and persisted for offline / restart
// survival and graph queries.
package source

import (
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// Kind classifies the authenticated/scheduled ingress that minted the
// anchor. Kept independent of lineage.RootType so the source plane can
// evolve its taxonomy without breaking lineage semantics.
type Kind uint8

const (
	KindUnknown Kind = 0
	KindSSH     Kind = 1
	KindPAM     Kind = 2
	KindSudo    Kind = 3
	KindCron    Kind = 4
	KindSystemd Kind = 5
)

// String returns a stable short token used in CLI output and logs.
func (k Kind) String() string {
	switch k {
	case KindSSH:
		return "ssh"
	case KindPAM:
		return "pam"
	case KindSudo:
		return "sudo"
	case KindCron:
		return "cron"
	case KindSystemd:
		return "systemd"
	}
	return "unknown"
}

// KindFromRootType maps a lineage.RootType to the source.Kind taxonomy.
// Unknown / web / container / kernel / local map to KindUnknown so
// callers can decide whether to skip persistence for those.
func KindFromRootType(r lineage.RootType) Kind {
	switch r {
	case lineage.RootSSH:
		return KindSSH
	case lineage.RootPAM:
		return KindPAM
	case lineage.RootSudo:
		return KindSudo
	case lineage.RootCron:
		return KindCron
	case lineage.RootSystemd:
		return KindSystemd
	}
	return KindUnknown
}

// Anchor is the persisted v2 SourceAnchor.
//
// Field meaning is Kind-dependent. SourceIP/SourcePort/SSHKeyHash are
// populated for KindSSH. Unit is populated for KindSystemd and KindCron.
// Detail is a JSON-encoded blob for fields specific to less-common kinds.
type Anchor struct {
	ID             lineage.LineageID
	Kind           Kind
	ParentAnchorID lineage.LineageID
	CreatedAt      time.Time
	Host           string
	Actor          string // user name / unit name / cron entry
	UID            uint32
	LoginUID       uint32
	SourceIP       string
	SourcePort     uint16
	SSHKeyHash     string
	Unit           string
	Detail         string // JSON, may be ""
}

// FromOrigin builds an Anchor from a lineage.Origin. Returns an Anchor
// whose Kind is KindUnknown if the Origin's RootType doesn't map.
// parent is the upstream anchor id (0 for root).
func FromOrigin(o lineage.Origin, parent lineage.LineageID) Anchor {
	a := Anchor{
		ID:             o.ID,
		Kind:           KindFromRootType(o.Type),
		ParentAnchorID: parent,
		CreatedAt:      o.CreatedAt,
		Actor:          o.UserName,
		UID:            o.UID,
		LoginUID:       o.LoginUID,
		SourceIP:       o.SourceIP,
		SourcePort:     o.SourcePort,
		SSHKeyHash:     o.SSHKeyHash,
		Unit:           o.SystemdUnit,
	}
	if a.Kind == KindCron && o.CronEntry != "" {
		a.Unit = o.CronEntry
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	return a
}
