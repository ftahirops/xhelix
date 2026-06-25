// Package workflowchain stamps every observed event with a unified
// workflow-chain identity so downstream consumers (Recorder, Synthesizer,
// BRP) can group events by which workflow produced them and decide whether
// that workflow may become "normal." It is pure computation: no I/O, no
// goroutines, no enforcement. SP-2, build-order item 3.
package workflowchain

import (
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"strconv"

	"github.com/xhelix/xhelix/pkg/lineage"
)

// Inputs carries everything Compute needs, gathered by the caller from data
// already on the event at the stamp point. Keeping this a plain struct makes
// the engine fully unit-testable without a live pipeline.
type Inputs struct {
	AppID            string            // ev.Tags["app_id"]; "" when unattributed
	RootID           lineage.LineageID // proctree.SourceOf(pid); 0 when no root
	RootType         lineage.RootType  // lineage.Store.Get(RootID).Type
	RequestID        string            // ev.Tags["request_id"]; "" server-side until L7 emitter
	JobID            string            // ev.Tags["job_id"]; "" unless a queue/cron root stamped it
	AdminShell       bool              // interactive ssh/sudo/pam root → admin noise, never learnable
	RedZone          bool              // event hit a red-zone signal
	RecordWindowOpen bool              // operator-asserted clean record window (NOT self-certified)
}

// Result is the stamp. Apply writes it onto an event's Tags.
type Result struct {
	ChainID   string
	RootID    string
	RootType  string
	RequestID string
	JobID     string
	Phase     string
	Learnable bool
	Fidelity  string
}

// Compute derives the chain stamp. Deterministic for identical inputs.
func Compute(in Inputs) Result {
	reqOrJob := in.RequestID
	if reqOrJob == "" {
		reqOrJob = in.JobID
	}
	return Result{
		ChainID:   chainID(in.RootID, reqOrJob),
		RootID:    strconv.FormatUint(uint64(in.RootID), 10),
		RootType:  in.RootType.String(),
		RequestID: in.RequestID,
		JobID:     in.JobID,
		Phase:     phase(in.RootType, in.RequestID != "", in.JobID != ""),
		Learnable: in.AppID != "" && in.RootID != 0 && !in.RedZone && !in.AdminShell && in.RecordWindowOpen,
		Fidelity:  fidelity(in.RequestID),
	}
}

// chainID (Decision A2): hash(root_id [+ "|" + reqOrJob]). With a request/job
// id it separates per-request workflows within one worker; without one it
// degrades to lineage granularity (one chain per root). FNV-64a is stable,
// fast, and dependency-free — this is an identity tag, not a security hash.
func chainID(rootID lineage.LineageID, reqOrJob string) string {
	h := fnv.New64a()
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(rootID))
	_, _ = h.Write(b[:])
	if reqOrJob != "" {
		_, _ = h.Write([]byte{'|'})
		_, _ = h.Write([]byte(reqOrJob))
	}
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], h.Sum64())
	return hex.EncodeToString(out[:])
}

// phase maps a root type (plus presence of request/job ids) to a workflow phase.
func phase(rt lineage.RootType, hasReq, hasJob bool) string {
	switch rt {
	case lineage.RootWeb:
		return "request"
	case lineage.RootCron:
		return "job"
	case lineage.RootSystemd, lineage.RootContainer:
		return "startup"
	case lineage.RootSSH, lineage.RootSudo, lineage.RootPAM:
		return "admin"
	}
	if hasReq {
		return "request"
	}
	if hasJob {
		return "job"
	}
	return "background"
}

// fidelity is "precise" only when an L7 request id backs the event; otherwise
// "coarse." Never claims precision the kernel cannot supply (scope-lock §6).
func fidelity(requestID string) string {
	if requestID != "" {
		return "precise"
	}
	return "coarse"
}
