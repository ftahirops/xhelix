// Package protectsvcapi registers LocalAPI handlers for the
// Protected Services subsystem. Lets xhelixctl (and any other
// local-socket client) query which services are protected, inspect
// their resolved contracts, and report deception-layer coverage.
//
// Read-only. Mutation (config reload, deception toggle) is a
// separate phase; this package only surfaces state.
//
// See PROTECTED_SERVICES_TRAP.md §13 (operator surfaces).
package protectsvcapi

import (
	"context"
	"encoding/json"
	"errors"
	"sort"

	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// API holds the dependencies the handlers need.
type API struct {
	Reg *protectedsvc.Registry
}

// Register wires the handlers onto a LocalAPI Server. Methods:
//
//   protected.list            → []ServiceSummary
//   protected.contract        → ContractView         (param: {"name": "<svc>"})
//   protected.deception_cov   → []DeceptionCoverage
//   protected.residual_risk   → ResidualRisk         (param: {"name": "<svc>"})
func (a *API) Register(s *localapi.Server) {
	s.RegisterHandler("protected.list", a.handleList)
	s.RegisterHandler("protected.contract", a.handleContract)
	s.RegisterHandler("protected.deception_cov", a.handleDeceptionCoverage)
	s.RegisterHandler("protected.residual_risk", a.handleResidualRisk)
}

// --- response shapes ---

// ServiceSummary is one row in `xhelixctl protect list`.
type ServiceSummary struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	Role            string `json:"role"`
	Unit            string `json:"unit,omitempty"`
	ExecPath        string `json:"exec_path"`
	CgroupPrefix    string `json:"cgroup_prefix,omitempty"`
	StrictReadOnly  bool   `json:"strict_read_only"`
	WriteRootsCount int    `json:"write_roots"`
	UpstreamsCount  int    `json:"upstreams"`
	DeceptionMode   string `json:"deception_mode"` // "trap" / "refuse" / "off"
	LearnEnabled    bool   `json:"learn_enabled"`
}

// ContractView is the resolved (built-in ∪ override) contract for
// one service.
type ContractView struct {
	Name     string                       `json:"name"`
	Contract protectedsvc.ServiceContract `json:"contract"`
	// Convenience fields — pre-computed counts for the UX.
	DenyExecCount     int `json:"deny_exec_count"`
	AllowExecCount    int `json:"allow_exec_count"`
	DenySyscallCount  int `json:"deny_syscall_count"`
	NeverLearnedCount int `json:"never_learned_count"`
}

// DeceptionCoverage shows which Ring 2 layers are active per service.
type DeceptionCoverage struct {
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	FakeExec  bool   `json:"fake_exec"`
	Sinkhole  bool   `json:"sinkhole"`
	DecoyFS   bool   `json:"decoy_fs"`
	PoisonDNS bool   `json:"poison_dns"`
	Score     int    `json:"score"` // 0-4 — count of active layers
}

// ResidualRisk surfaces what the operator can't fully lock down
// even after the contract takes effect. Honest non-promises.
type ResidualRisk struct {
	Name           string   `json:"name"`
	ReadablePaths  []string `json:"readable_paths,omitempty"`
	ReachableUpstreams []string `json:"reachable_upstreams,omitempty"`
	WritableRoots  []string `json:"writable_roots,omitempty"`
	DisabledLayers []string `json:"disabled_layers,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// --- handlers ---

func (a *API) handleList(ctx context.Context, _ json.RawMessage) (any, error) {
	if a.Reg == nil {
		return nil, errors.New("protectsvcapi: nil registry")
	}
	svcs := a.Reg.All()
	out := make([]ServiceSummary, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, summarize(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type nameParam struct {
	Name string `json:"name"`
}

func (a *API) handleContract(ctx context.Context, raw json.RawMessage) (any, error) {
	if a.Reg == nil {
		return nil, errors.New("protectsvcapi: nil registry")
	}
	var p nameParam
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Name == "" {
		return nil, errors.New("name required")
	}
	svc := a.Reg.ByName(p.Name)
	if svc == nil {
		return nil, errors.New("service not found")
	}
	return ContractView{
		Name:              svc.Name,
		Contract:          svc.Contract,
		DenyExecCount:     len(svc.Contract.DenyExecPaths),
		AllowExecCount:    len(svc.Contract.AllowExecPaths),
		DenySyscallCount:  len(svc.Contract.DenySyscalls),
		NeverLearnedCount: len(contracts.NeverLearnableExec),
	}, nil
}

func (a *API) handleDeceptionCoverage(ctx context.Context, _ json.RawMessage) (any, error) {
	if a.Reg == nil {
		return nil, errors.New("protectsvcapi: nil registry")
	}
	svcs := a.Reg.All()
	out := make([]DeceptionCoverage, 0, len(svcs))
	for _, s := range svcs {
		d := s.Response.Deception
		score := 0
		for _, on := range []bool{d.FakeExec, d.Sinkhole, d.DecoyFS, d.PoisonDNS} {
			if d.Enabled && on {
				score++
			}
		}
		out = append(out, DeceptionCoverage{
			Name:      s.Name,
			Enabled:   d.Enabled,
			FakeExec:  d.FakeExec,
			Sinkhole:  d.Sinkhole,
			DecoyFS:   d.DecoyFS,
			PoisonDNS: d.PoisonDNS,
			Score:     score,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (a *API) handleResidualRisk(ctx context.Context, raw json.RawMessage) (any, error) {
	if a.Reg == nil {
		return nil, errors.New("protectsvcapi: nil registry")
	}
	var p nameParam
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	svc := a.Reg.ByName(p.Name)
	if svc == nil {
		return nil, errors.New("service not found")
	}
	return computeResidualRisk(svc), nil
}

// --- helpers ---

func summarize(s *protectedsvc.ProtectedService) ServiceSummary {
	mode := "off"
	if s.Response.Deception.Enabled {
		mode = "refuse"
		// "trap" if ANY Ring-2 layer is on.
		if s.Response.Deception.FakeExec || s.Response.Deception.Sinkhole ||
			s.Response.Deception.DecoyFS || s.Response.Deception.PoisonDNS {
			mode = "trap"
		}
	}
	return ServiceSummary{
		Name:            s.Name,
		Kind:            string(s.Kind),
		Role:            string(s.Role),
		Unit:            s.Unit,
		ExecPath:        s.ExecPath,
		CgroupPrefix:    s.CgroupPrefix,
		StrictReadOnly:  s.Contract.StrictReadOnly,
		WriteRootsCount: len(s.Contract.WriteRoots),
		UpstreamsCount:  len(s.Contract.UpstreamCIDRs),
		DeceptionMode:   mode,
		LearnEnabled:    s.Learn.Enabled,
	}
}

func computeResidualRisk(s *protectedsvc.ProtectedService) ResidualRisk {
	rr := ResidualRisk{
		Name:               s.Name,
		WritableRoots:      append([]string(nil), s.Contract.WriteRoots...),
		ReachableUpstreams: append([]string(nil), s.Contract.UpstreamCIDRs...),
	}

	// Sensitive paths the service is NOT explicitly denied from
	// reading — under default AppArmor profile, only WriteRoots are
	// confined; reads are broad. Operators rarely declare
	// ReadSensitiveRoots, so we surface common-case risk explicitly.
	if len(s.Contract.ReadSensitiveRoots) == 0 {
		rr.ReadablePaths = []string{
			"/etc/shadow", "/etc/sudoers", "/root/**", "/home/*/.ssh/**",
		}
		rr.Notes = append(rr.Notes,
			"ReadSensitiveRoots empty — service can read /etc and /home recursively. "+
				"Enable Deception.DecoyFS to overlay watermarked fakes.")
	}

	// Disabled deception layers.
	if !s.Response.Deception.Enabled {
		rr.DisabledLayers = append(rr.DisabledLayers, "deception (master switch)")
	} else {
		if !s.Response.Deception.FakeExec {
			rr.DisabledLayers = append(rr.DisabledLayers, "fake_exec (forbidden exec → refuse instead of honey-sh)")
		}
		if !s.Response.Deception.Sinkhole {
			rr.DisabledLayers = append(rr.DisabledLayers, "sinkhole (forbidden connect → refuse instead of fake C2)")
		}
		if !s.Response.Deception.DecoyFS {
			rr.DisabledLayers = append(rr.DisabledLayers, "decoy_fs (sensitive read → real file, not honey)")
		}
		if !s.Response.Deception.PoisonDNS {
			rr.DisabledLayers = append(rr.DisabledLayers, "poison_dns (C2 domain → real resolver, not sinkhole IP)")
		}
	}

	// Catalogue what we don't (yet) protect.
	rr.Notes = append(rr.Notes,
		"In-process exploitation that doesn't trip a forbidden primitive is NOT detected — "+
			"see PROTECTED_SERVICES_TRAP.md §15 \"What This Design Does NOT Do\".")

	return rr
}
