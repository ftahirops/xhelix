// Package configaudit prevents the "config knob accepted but not
// consumed" class of bug, logged three times in ERRORS.md:
//
//   1. alerts.jsonl FileSink rotation (rotate_size_mb declared, never
//      wired — 3.8 GB log file in production)
//   2. lineage.Store mutex (sync.Mutex pattern declared, no actual
//      lock — 100-goroutine race detector caught it)
//   3. storage.hot.* retention (retention_hours + max_size_mb
//      declared, no pruner — 14 GB hot.db on production)
//
// The pattern: operator reads xhelix.yaml, sees retention/cap/rotation
// declared, assumes enforcement at runtime, ships to production. No
// error at startup says otherwise. Bug manifests when disk fills.
//
// Lock: every code path that consumes a config field must Witness()
// the field's dotted key. At startup completion, Audit() walks the
// known-consumable-keys set, compares against witnessed keys, and
// emits warnings (or errors in strict mode) for any unwitnessed key
// whose value is non-default.
//
// Usage:
//
//   var a = configaudit.New()
//
//   // At each consumer site:
//   a.Witness("storage.hot.retention_hours", "runHotPruner")
//   a.Witness("storage.hot.max_size_mb",     "runHotPruner")
//
//   // After all subsystems are started:
//   findings := a.Audit(cfg)
//   for _, f := range findings {
//       log.Warn("config knob declared but no consumer", "key", f.Key,
//                "value", f.Value, "issue", f.Issue)
//   }
//   if strictMode && len(findings) > 0 {
//       return errors.New("strict config audit failed; see warnings")
//   }
//
// The package is small on purpose — it is the *policy* not the
// *enforcement*. The enforcement is operator habit: search for the
// witness when adding a config field, fail review if it's missing.
package configaudit

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// Audit tracks which config keys have a registered consumer.
// Concurrent-safe.
type Audit struct {
	mu      sync.Mutex
	witness map[string]string // dotted-key -> consumer-name (last writer wins)
	// known is the explicit list of keys that the operator *expects*
	// to be enforced. If you add a config field, add its dotted-key
	// here. The audit fails closed: an unknown key with a non-default
	// value is a warning even if it has a witness.
	known map[string]struct{}
}

// New constructs an empty Audit.
func New() *Audit {
	return &Audit{
		witness: make(map[string]string),
		known:   make(map[string]struct{}),
	}
}

// Witness records that `consumer` consumes the config value at
// `dottedKey`. Idempotent — multiple witnesses for the same key
// are allowed (last writer recorded for diagnostics).
func (a *Audit) Witness(dottedKey, consumer string) {
	a.mu.Lock()
	a.witness[dottedKey] = consumer
	a.known[dottedKey] = struct{}{}
	a.mu.Unlock()
}

// Declare adds a key to the known set without claiming a consumer
// for it. Used in tests and for keys that are intentionally
// info-only (no enforcement needed, e.g. `version`).
func (a *Audit) Declare(dottedKey string) {
	a.mu.Lock()
	a.known[dottedKey] = struct{}{}
	a.mu.Unlock()
}

// Finding describes one audit result. Issue is one of:
//   "unwitnessed-nondefault" — value differs from zero/default but
//                              nothing claimed to consume it
//   "unknown-key"             — value present in the config struct
//                              but no code has ever Witness'd or
//                              Declare'd it (likely a new field
//                              someone forgot to wire)
type Finding struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Issue string `json:"issue"`
}

// Audit walks cfg by reflection, building dotted keys from `yaml` tags,
// and returns findings. Operator chooses what to do with them (log,
// strict-fail, etc).
//
// A field is "non-default" if it isn't the zero value of its type.
// Operator config that's intentionally zero / disabled is silently
// fine.
func (a *Audit) Audit(cfg any) []Finding {
	a.mu.Lock()
	witnessed := make(map[string]string, len(a.witness))
	for k, v := range a.witness {
		witnessed[k] = v
	}
	known := make(map[string]struct{}, len(a.known))
	for k := range a.known {
		known[k] = struct{}{}
	}
	a.mu.Unlock()

	var findings []Finding
	walk(reflect.ValueOf(cfg), "", &findings, witnessed, known)
	return findings
}

// walk recursively visits struct fields, building dotted keys.
// Treats anonymous embedded fields as path-transparent. Stops at
// unexported / interface / func / chan fields.
func walk(v reflect.Value, prefix string, out *[]Finding, witnessed map[string]string, known map[string]struct{}) {
	v = derefValue(v)
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			sf := t.Field(i)
			if !sf.IsExported() {
				continue
			}
			fv := v.Field(i)
			key := fieldKey(sf, prefix)
			if key == "" {
				continue
			}
			if isCompositeKind(fv.Kind()) {
				walk(fv, key, out, witnessed, known)
				continue
			}
			if fv.IsZero() {
				// Default value → nothing to audit.
				continue
			}
			if _, ok := witnessed[key]; ok {
				continue
			}
			if _, ok := known[key]; !ok {
				*out = append(*out, Finding{
					Key:   key,
					Value: fmt.Sprintf("%v", fv.Interface()),
					Issue: "unknown-key",
				})
				continue
			}
			*out = append(*out, Finding{
				Key:   key,
				Value: fmt.Sprintf("%v", fv.Interface()),
				Issue: "unwitnessed-nondefault",
			})
		}
	case reflect.Slice, reflect.Array:
		// For slices of structs (e.g., []SinkConfig), walk each
		// element with an indexed prefix so nested fields can be
		// audited. Slices of scalars are leaf values; check the
		// whole slice's witness.
		if v.Len() == 0 {
			return
		}
		elemKind := v.Type().Elem().Kind()
		if elemKind == reflect.Struct ||
			elemKind == reflect.Ptr ||
			elemKind == reflect.Interface {
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), fmt.Sprintf("%s[%d]", prefix, i), out, witnessed, known)
			}
			return
		}
		// Scalar slice: treat like a leaf.
		if _, ok := witnessed[prefix]; ok {
			return
		}
		if _, ok := known[prefix]; !ok {
			*out = append(*out, Finding{
				Key:   prefix,
				Value: fmt.Sprintf("%v", v.Interface()),
				Issue: "unknown-key",
			})
		} else {
			*out = append(*out, Finding{
				Key:   prefix,
				Value: fmt.Sprintf("%v", v.Interface()),
				Issue: "unwitnessed-nondefault",
			})
		}
	case reflect.Map:
		// Maps aren't typical in xhelix config; if encountered,
		// treat as a single leaf.
		if v.Len() == 0 {
			return
		}
		if _, ok := witnessed[prefix]; ok {
			return
		}
		if _, ok := known[prefix]; !ok {
			*out = append(*out, Finding{
				Key:   prefix,
				Value: fmt.Sprintf("%v", v.Interface()),
				Issue: "unknown-key",
			})
		}
	}
}

func fieldKey(sf reflect.StructField, prefix string) string {
	tag := sf.Tag.Get("yaml")
	if tag == "" {
		// No yaml tag — use lowercased field name as a reasonable
		// default. Skip embedded fields (anonymous) by inheriting
		// the prefix.
		if sf.Anonymous {
			return prefix
		}
		tag = strings.ToLower(sf.Name)
	}
	if i := strings.Index(tag, ","); i >= 0 {
		tag = tag[:i]
	}
	if tag == "-" {
		return ""
	}
	if prefix == "" {
		return tag
	}
	return prefix + "." + tag
}

func isCompositeKind(k reflect.Kind) bool {
	switch k {
	case reflect.Struct, reflect.Ptr, reflect.Slice, reflect.Array, reflect.Map, reflect.Interface:
		return true
	}
	return false
}

func derefValue(v reflect.Value) reflect.Value {
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

// Witnessed reports whether a key has been registered as consumed.
// Used by tests that want to assert consumer registration.
func (a *Audit) Witnessed(dottedKey string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.witness[dottedKey]
	return ok
}

// Stats returns counters for the LocalAPI surface and tests.
type Stats struct {
	Witnessed int `json:"witnessed"`
	Known     int `json:"known"`
}

// Stats returns counter snapshot.
func (a *Audit) Stats() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return Stats{Witnessed: len(a.witness), Known: len(a.known)}
}
