package rules

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/xhelix/xhelix/pkg/model"
)

// ClassMap is the parsed form of ruleset/core/class_map.yaml.
// Loaded separately from rule files (yaml structure differs).
type ClassMap struct {
	Class1 []string `yaml:"class_1"`
	Class2 []string `yaml:"class_2"`
	// Anything not in Class1 or Class2 defaults to Class 3.
}

// Lookup returns the class for ruleID, defaulting to 3.
func (c *ClassMap) Lookup(ruleID string) int {
	if c == nil {
		return 3
	}
	for _, id := range c.Class1 {
		if id == ruleID {
			return 1
		}
	}
	for _, id := range c.Class2 {
		if id == ruleID {
			return 2
		}
	}
	return 3
}

// LoadClassMap reads class_map.yaml from dir. Missing file is not
// an error — every rule defaults to class 3.
func LoadClassMap(dir string) (*ClassMap, error) {
	path := filepath.Join(dir, "class_map.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ClassMap{}, nil
		}
		return nil, err
	}
	var m ClassMap
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ApplyTo stamps the class on every rule in the slice (in place).
// Rules whose YAML already declared a class keep it; empty classes
// get the class-map lookup.
func (c *ClassMap) ApplyTo(rs []model.Rule) {
	if c == nil {
		return
	}
	for i := range rs {
		if rs[i].Class == 0 {
			rs[i].Class = c.Lookup(rs[i].ID)
		}
	}
}
