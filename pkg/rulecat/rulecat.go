// Package rulecat resolves a rule_id to its model.Category by merging
// two sources: the categories declared on loaded YAML rules, and a
// runtime-rule registry (ruleset/runtime_categories.yaml) for rule_ids
// emitted directly by Go code with no YAML entry. Rule ids in neither
// source resolve to CategoryWeakSignal — safe, because weak_signal is
// suppressed in visibility mode.
package rulecat

import (
	"fmt"
	"os"

	"github.com/xhelix/xhelix/pkg/model"
	"gopkg.in/yaml.v3"
)

// Resolver maps rule_id -> Category (and its evidence weight).
type Resolver struct {
	cats    map[string]model.Category
	weights map[string]int
}

// NewResolver returns an empty resolver.
func NewResolver() *Resolver {
	return &Resolver{
		cats:    make(map[string]model.Category),
		weights: make(map[string]int),
	}
}

// AddRules merges the categories of the supplied YAML rules.
// A rule whose CategoryRaw is empty is skipped (it was never classified;
// it will resolve to the weak_signal default).
func (r *Resolver) AddRules(rules []model.Rule) {
	for _, rule := range rules {
		if rule.ID == "" || rule.CategoryRaw == "" {
			continue
		}
		r.cats[rule.ID] = rule.Category
		r.weights[rule.ID] = rule.EffectiveWeight()
	}
}

// AddRuntimeFile merges rule_id->category entries from a
// runtime_categories.yaml file (top-level "categories" map). Missing
// file is not an error (returns nil) so the daemon degrades gracefully.
func (r *Resolver) AddRuntimeFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("rulecat: read %s: %w", path, err)
	}
	var doc struct {
		Categories map[string]string `yaml:"categories"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("rulecat: parse %s: %w", path, err)
	}
	for id, raw := range doc.Categories {
		cat, ok := model.ParseCategory(raw)
		if !ok {
			return fmt.Errorf("rulecat: %s: rule %q has invalid category %q", path, id, raw)
		}
		r.cats[id] = cat
		r.weights[id] = model.DefaultWeight(cat)
	}
	return nil
}

// Category returns the category for ruleID, or CategoryWeakSignal if
// the rule_id is unknown (safe default — suppressed in visibility mode).
func (r *Resolver) Category(ruleID string) model.Category {
	if c, ok := r.cats[ruleID]; ok {
		return c
	}
	return model.CategoryWeakSignal
}

// Weight returns the evidence weight for ruleID: the rule's effective
// weight if classified, else the weak_signal default (the same default
// Category() falls back to). Used by the verdict engine.
func (r *Resolver) Weight(ruleID string) int {
	if w, ok := r.weights[ruleID]; ok {
		return w
	}
	return model.DefaultWeight(model.CategoryWeakSignal)
}

// Len returns the number of classified rule_ids (for diagnostics).
func (r *Resolver) Len() int { return len(r.cats) }

// Known reports whether ruleID has an explicit classification (as
// opposed to falling back to the weak_signal default).
func (r *Resolver) Known(ruleID string) bool {
	_, ok := r.cats[ruleID]
	return ok
}

// ShouldEmit reports whether an alert of the given category should be
// emitted under the supplied AlertMode.
//
//	detection  — emit everything.
//	visibility — emit only hard_deny and incident; suppress fact and
//	             weak_signal.
func ShouldEmit(cat model.Category, mode string) bool {
	if mode == "detection" {
		return true
	}
	// visibility (and any unknown mode → fail safe to visibility)
	return cat == model.CategoryHardDeny || cat == model.CategoryIncident
}

// Gate returns an alert predicate for the given AlertMode, suitable for
// alert.Bus.SetGate. It resolves the alert's RuleID to a category and
// applies ShouldEmit.
func (r *Resolver) Gate(mode string) func(model.Alert) bool {
	return func(a model.Alert) bool {
		return ShouldEmit(r.Category(a.RuleID), mode)
	}
}
