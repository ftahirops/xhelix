package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/xhelix/xhelix/pkg/model"
)

// LoadDir reads every *.yaml / *.yml file in dir as a stream of YAML
// documents and returns the parsed Rule values.
//
// Empty documents (e.g., trailing `---`) are skipped. Each rule is
// Normalize-d before being returned; any normalisation failure aborts
// the whole load with an error so partial loads don't leave the
// engine in an unknown state.
func LoadDir(dir string) ([]model.Rule, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := filepath.Ext(p)
		if ext == ".yaml" || ext == ".yml" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", dir, err)
	}

	var rules []model.Rule
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", f, err)
		}
		fileRules, err := LoadBytes(body)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		rules = append(rules, fileRules...)
	}
	return rules, nil
}

// LoadBytes parses one YAML document stream into a slice of rules.
// Exposed so callers can load from any source (and so the loader is
// fuzz-friendly).
func LoadBytes(body []byte) ([]model.Rule, error) {
	var rules []model.Rule
	dec := yaml.NewDecoder(bytes.NewReader(body))
	for {
		var r model.Rule
		err := dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if r.ID == "" && r.Match == "" && r.SeverityRaw == "" {
			continue
		}
		if err := r.Normalize(); err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		if r.ID == "" {
			return nil, errors.New("rule with empty id")
		}
		rules = append(rules, r)
	}
	return rules, nil
}
