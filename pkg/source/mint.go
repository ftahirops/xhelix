package source

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/model"
)

// Minter mints SourceAnchors from identity events.
//
// It composes three already-existing collaborators:
//
//   - lineage.Minter — allocates fresh LineageIDs (process-monotonic)
//   - lineage.Store  — in-memory hot-path Origin records used by the
//     rule engine and correlator
//   - source.Store   — persistent SourceAnchor store on SQLite
//
// MintFromEvent inspects an identity event and decides whether it
// represents a mintable ingress (sshd accept success, PAM session open,
// sudo / su success, cron fire, systemd unit start). If so it allocates
// a LineageID, writes the corresponding Origin and Anchor records, and
// returns the new anchor ID. Non-mintable events return 0 with no error.
type Minter struct {
	store   *Store
	ids     *lineage.Minter
	origins *lineage.Store
	host    string
}

// NewMinter returns a Minter wired against the three collaborators.
// store may be nil for tests that only care about the in-memory side.
func NewMinter(store *Store, ids *lineage.Minter, origins *lineage.Store, host string) *Minter {
	if ids == nil {
		ids = lineage.NewMinter()
	}
	if origins == nil {
		origins = lineage.NewStore()
	}
	return &Minter{store: store, ids: ids, origins: origins, host: host}
}

// MintFromEvent looks at ev and mints an anchor if appropriate.
//
// The decision uses the tag conventions established by sensors/identity:
//
//   - service=sshd outcome=success                → KindSSH
//   - service=pam pam_type=session_open           → KindPAM
//   - service=sudo (with target_user)             → KindSudo
//   - service=su   (with target_user)             → KindSudo (treated equivalently)
//   - service=cron                                → KindCron
//   - service=systemd unit_action=start           → KindSystemd
//
// Anything else returns 0,nil.
//
// Parent resolution for sudo/su looks up the most recent non-sudo
// anchor for the same actor within ParentLookbackWindow.
func (m *Minter) MintFromEvent(ctx context.Context, ev model.Event) (lineage.LineageID, error) {
	kind, ok := kindFromEventTags(ev.Tags)
	if !ok {
		return 0, nil
	}

	actor := ev.Tags["user"]
	parent := lineage.LineageID(0)

	if kind == KindSudo {
		// sudo escalates; preserve outer anchor.
		from := actor
		if from == "" {
			from = ev.Tags["from_user"]
		}
		p, _ := m.findRecentParent(ctx, from)
		parent = p
		// Identify *target* user as the actor of the new sudo anchor.
		if t := ev.Tags["target_user"]; t != "" {
			actor = t
		}
	}

	id := m.ids.New()
	origin := lineage.Origin{
		ID:        id,
		Type:      rootTypeForKind(kind),
		CreatedAt: ev.Time,
		UserName:  actor,
		UID:       ev.UID,
		LoginUID:  ev.UID, // close-enough default; refined by audit later
	}
	if ip := ev.Tags["src_ip"]; ip != "" {
		origin.SourceIP = ip
	}
	if portStr := ev.Tags["src_port"]; portStr != "" {
		if n, err := strconv.ParseUint(portStr, 10, 16); err == nil {
			origin.SourcePort = uint16(n)
		}
	}
	if kf := ev.Tags["key_fp"]; kf != "" {
		origin.SSHKeyHash = kf
	}
	if u := ev.Tags["unit"]; u != "" {
		origin.SystemdUnit = u
	}
	if c := ev.Tags["cron_entry"]; c != "" {
		origin.CronEntry = c
	}
	if kind == KindSudo {
		origin.EscalatedFromName = ev.Tags["user"]
	}

	m.origins.Put(origin)

	if m.store != nil {
		a := FromOrigin(origin, parent)
		if a.Host == "" {
			a.Host = m.host
		}
		if err := m.store.Put(ctx, a); err != nil {
			return id, fmt.Errorf("mint: persist anchor: %w", err)
		}
	}
	return id, nil
}

// ParentLookbackWindow is how far back findRecentParent searches when
// resolving a sudo/su parent. 24h matches typical interactive-session
// lifetime; outside this window we treat sudo as a root anchor.
var ParentLookbackWindow = 24 * time.Hour

// findRecentParent returns the most recent non-sudo anchor for actor
// within ParentLookbackWindow. Returns (0,nil) if none found and (0,err)
// on database error.
func (m *Minter) findRecentParent(ctx context.Context, actor string) (lineage.LineageID, error) {
	if m.store == nil || actor == "" {
		return 0, nil
	}
	cutoffNs := time.Now().Add(-ParentLookbackWindow).UnixNano()
	row := m.store.db.QueryRowContext(ctx, `
		SELECT id FROM source_anchors
		WHERE actor = ? AND kind != ? AND created_ns >= ?
		ORDER BY created_ns DESC LIMIT 1
	`, actor, uint8(KindSudo), cutoffNs)
	var idOut uint64
	if err := row.Scan(&idOut); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return lineage.LineageID(idOut), nil
}

// kindFromEventTags maps an identity event's tag set to a Kind.
// Returns (KindUnknown,false) for non-identity / non-mintable events.
func kindFromEventTags(tags map[string]string) (Kind, bool) {
	if len(tags) == 0 {
		return KindUnknown, false
	}
	switch tags["service"] {
	case "sshd":
		if tags["outcome"] == "success" {
			return KindSSH, true
		}
	case "pam":
		if tags["pam_type"] == "session_open" {
			return KindPAM, true
		}
	case "sudo", "su":
		// sensors/identity emits these only on success patterns; treat
		// presence of target_user as the sentinel.
		if tags["target_user"] != "" {
			return KindSudo, true
		}
	case "cron":
		return KindCron, true
	case "systemd":
		if tags["unit_action"] == "start" {
			return KindSystemd, true
		}
	}
	return KindUnknown, false
}

func rootTypeForKind(k Kind) lineage.RootType {
	switch k {
	case KindSSH:
		return lineage.RootSSH
	case KindPAM:
		return lineage.RootPAM
	case KindSudo:
		return lineage.RootSudo
	case KindCron:
		return lineage.RootCron
	case KindSystemd:
		return lineage.RootSystemd
	}
	return lineage.RootUnknown
}
