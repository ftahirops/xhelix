package main

import (
	"encoding/json"
	"fmt"

	"github.com/xhelix/xhelix/pkg/policy"
)

// policyGet returns the current on-disk policy plus runtime settings.
func policyGet(vctx *verdictCtx) (any, error) {
	if vctx == nil || vctx.source == nil {
		return map[string]any{
			"yaml":            "",
			"block_telemetry": false,
			"path":            "",
			"note":            "no policy file loaded",
		}, nil
	}
	fd := vctx.source.Current()
	b, err := policy.SerialiseYAML(fd)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"yaml":            string(b),
		"block_telemetry": fd.Settings.BlockTelemetry,
		"path":            vctx.source.Path,
	}, nil
}

// policySave writes the supplied YAML back to disk after parse
// validation, then forces an immediate reload.
func policySave(vctx *verdictCtx, raw json.RawMessage) (any, error) {
	if vctx == nil || vctx.source == nil {
		return nil, fmt.Errorf("policy: no source attached")
	}
	var req struct {
		YAML string `json:"yaml"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	fd, err := policy.ParseYAML([]byte(req.YAML))
	if err != nil {
		return nil, err
	}
	if err := vctx.source.Save(fd); err != nil {
		return nil, err
	}
	// Force a re-load so the change applies before the next poll tick.
	if _, err := vctx.source.Load(); err != nil {
		return nil, err
	}
	vctx.applySource()
	// Invalidate verdict cache so saved rules apply to every flow.
	vctx.mu.Lock()
	vctx.cache = make(map[string]cachedVerdict, vctx.cacheCap)
	vctx.mu.Unlock()
	return map[string]any{"ok": true, "block_telemetry": fd.Settings.BlockTelemetry}, nil
}

// policyUpsertApp adds or replaces one per-app rule in the active
// policy. Identifier match is exe-path-first, falls back to comm.
// Body shape mirrors policy.AppRules.
func policyUpsertApp(vctx *verdictCtx, raw json.RawMessage) (any, error) {
	if vctx == nil || vctx.source == nil {
		return nil, fmt.Errorf("policy: no source attached")
	}
	var in struct {
		Exe              string   `json:"exe"`
		Comm             string   `json:"comm"`
		ExeSHA           string   `json:"exe_sha"`
		AllowOnlyDomains []string `json:"allow_only_domains"`
		AllowCountries   []string `json:"allow_countries"`
		AllowASNs        []uint32 `json:"allow_asns"`
		DenyDomains      []string `json:"deny_domains"`
		DenyCountries    []string `json:"deny_countries"`
		DenyASNs         []uint32 `json:"deny_asns"`
		DenyPorts        []uint16 `json:"deny_ports"`
		Remove           bool     `json:"remove"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	if in.Exe == "" && in.Comm == "" && in.ExeSHA == "" {
		return nil, fmt.Errorf("policy.upsert_app: need at least one of exe / comm / exe_sha")
	}
	fd := vctx.source.Current()
	if fd == nil {
		fd = &policy.FullDocument{}
	}
	// Locate and replace any existing rule with the same identifier.
	matches := func(a policy.AppRules) bool {
		if in.ExeSHA != "" && a.Match.ExeSHA == in.ExeSHA {
			return true
		}
		if in.Exe != "" && a.Match.Exe == in.Exe {
			return true
		}
		if in.Comm != "" && a.Match.Comm == in.Comm {
			return true
		}
		return false
	}
	kept := fd.Doc.Apps[:0]
	for _, a := range fd.Doc.Apps {
		if !matches(a) {
			kept = append(kept, a)
		}
	}
	fd.Doc.Apps = kept
	if !in.Remove {
		fd.Doc.Apps = append(fd.Doc.Apps, policy.AppRules{
			Match: policy.AppKey{Exe: in.Exe, Comm: in.Comm, ExeSHA: in.ExeSHA},
			AllowOnlyDomains: in.AllowOnlyDomains,
			AllowCountries:   in.AllowCountries,
			AllowASNs:        in.AllowASNs,
			DenyDomains:      in.DenyDomains,
			DenyCountries:    in.DenyCountries,
			DenyASNs:         in.DenyASNs,
			DenyPorts:        in.DenyPorts,
		})
	}
	if err := vctx.source.Save(fd); err != nil {
		return nil, err
	}
	if _, err := vctx.source.Load(); err != nil {
		return nil, err
	}
	vctx.applySource()
	vctx.mu.Lock()
	vctx.cache = make(map[string]cachedVerdict, vctx.cacheCap)
	vctx.mu.Unlock()
	return map[string]any{"ok": true, "rules": len(fd.Doc.Apps)}, nil
}

// policyToggleTelemetry flips the block_telemetry flag and persists
// the change to disk so reboots keep the operator's choice.
func policyToggleTelemetry(vctx *verdictCtx, raw json.RawMessage) (any, error) {
	if vctx == nil || vctx.source == nil {
		return nil, fmt.Errorf("policy: no source attached")
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, err
	}
	fd := vctx.source.Current()
	if fd == nil {
		fd = &policy.FullDocument{}
	}
	fd.Settings.BlockTelemetry = req.Enabled
	if err := vctx.source.Save(fd); err != nil {
		return nil, err
	}
	if _, err := vctx.source.Load(); err != nil {
		return nil, err
	}
	vctx.applySource()
	vctx.mu.Lock()
	vctx.cache = make(map[string]cachedVerdict, vctx.cacheCap)
	vctx.mu.Unlock()
	return map[string]any{"ok": true, "block_telemetry": vctx.blockTelemetry.Load()}, nil
}
