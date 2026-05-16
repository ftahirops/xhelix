package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// enforceStatus returns the current arm state + soak progress + counters.
func enforceStatus(enf *enforceCtx) (any, error) {
	if enf == nil {
		return map[string]any{"armed": false, "note": "enforcement unavailable"}, nil
	}
	return enf.Status(), nil
}

// enforceArm installs nft + starts queue consumer with a soak window.
// Body: {"soak_seconds": int (optional, default 30)}.
func enforceArm(ctx context.Context, enf *enforceCtx, raw json.RawMessage) (any, error) {
	if enf == nil {
		return nil, fmt.Errorf("enforcement unavailable")
	}
	var req struct {
		SoakSeconds int    `json:"soak_seconds"`
		Mode        string `json:"mode"` // "soft" or "hard"
	}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &req)
	}
	if req.SoakSeconds <= 0 {
		req.SoakSeconds = 30
	}
	if req.SoakSeconds > 600 {
		req.SoakSeconds = 600
	}
	if req.Mode == "" {
		req.Mode = "soft" // default to safe mode
	}
	if err := enf.Arm(ctx, time.Duration(req.SoakSeconds)*time.Second, req.Mode); err != nil {
		return nil, err
	}
	return enf.Status(), nil
}

// enforceDisarm tears nft rules down and stops the queue. Fast,
// idempotent, never blocks the operator's network.
func enforceDisarm(enf *enforceCtx) (any, error) {
	if enf == nil {
		return map[string]any{"armed": false}, nil
	}
	enf.Disarm()
	return enf.Status(), nil
}
