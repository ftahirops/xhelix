package intel

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// staticFile is the on-disk YAML shape for ruleset/iocs/static.yaml.
type staticFile struct {
	Version     int      `yaml:"version"`
	Description string   `yaml:"description"`
	IPs         []string `yaml:"ips"`
}

// LoadStaticFile reads a YAML IOC file and returns the IP list.
// Missing file is not an error — fresh installs get an empty list.
func LoadStaticFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var f staticFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return f.IPs, nil
}
