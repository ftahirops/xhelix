package correlator

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadFromDir reads every *.yaml / *.yml file under dir, parses them
// as correlator.Rule definitions, and returns the union. One file may
// contain multiple rules separated by YAML `---` document delimiters
// (matching the existing rule ruleset/core/*.yaml convention).
//
// Missing dir is NOT an error — it's logged by the caller and treated
// as an empty ruleset, the safe default.
//
// Per-file or per-rule errors are returned as a single multi-error so
// the caller can decide whether to fail-fast or proceed with the
// rules that did parse.
func LoadFromDir(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("correlator.LoadFromDir: %w", err)
	}
	// Deterministic order: filename-sorted.
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		paths = append(paths, filepath.Join(dir, name))
	}
	sort.Strings(paths)
	var (
		out  []Rule
		errs []error
	)
	for _, p := range paths {
		rules, err := loadFile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		out = append(out, rules...)
	}
	if len(errs) > 0 {
		return out, errors.Join(errs...)
	}
	return out, nil
}

// loadFile parses one YAML file into Rule(s). A file with multiple
// `---`-separated documents yields multiple rules.
func loadFile(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	var out []Rule
	for {
		var r Rule
		if err := dec.Decode(&r); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return out, fmt.Errorf("decode: %w", err)
		}
		// Skip empty document (e.g. trailing ---)
		if r.ID == "" {
			continue
		}
		if err := r.Normalize(); err != nil {
			return out, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, nil
}
