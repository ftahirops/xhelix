package policy

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// yamlDocument is the on-disk shape. We keep it separate from
// Document so the runtime type isn't forced to carry yaml tags.
type yamlDocument struct {
	BlockTelemetry bool          `yaml:"block_telemetry"`
	Global         yamlGlobal    `yaml:"global"`
	Apps           []yamlAppRule `yaml:"apps"`
}

type yamlGlobal struct {
	DenyDomains   []string `yaml:"deny_domains"`
	DenyCountries []string `yaml:"deny_countries"`
	DenyASNs      []uint32 `yaml:"deny_asns"`
	DenyIPCIDRs   []string `yaml:"deny_cidrs"`
}

type yamlAppRule struct {
	Match            yamlAppMatch `yaml:"match"`
	AllowOnlyDomains []string     `yaml:"allow_only_domains"`
	AllowCountries   []string     `yaml:"allow_countries"`
	AllowASNs        []uint32     `yaml:"allow_asns"`
	DenyDomains      []string     `yaml:"deny_domains"`
	DenyCountries    []string     `yaml:"deny_countries"`
	DenyASNs         []uint32     `yaml:"deny_asns"`
	DenyPorts        []uint16     `yaml:"deny_ports"`
}

type yamlAppMatch struct {
	ExeSHA string `yaml:"exe_sha"`
	Exe    string `yaml:"exe"`
	Comm   string `yaml:"comm"`
	Unit   string `yaml:"unit"`
}

// Settings carries non-rule flags (e.g. block_telemetry). Decoupled
// from Document so the verdict layer doesn't need to know.
type Settings struct {
	BlockTelemetry bool
}

// FullDocument bundles rules + settings — what the loader returns.
type FullDocument struct {
	Doc      Document
	Settings Settings
}

// ParseYAML decodes a YAML byte slice into a FullDocument.
func ParseYAML(b []byte) (*FullDocument, error) {
	var y yamlDocument
	if len(b) == 0 {
		return &FullDocument{}, nil
	}
	if err := yaml.Unmarshal(b, &y); err != nil {
		return nil, fmt.Errorf("policy yaml: %w", err)
	}
	fd := &FullDocument{
		Settings: Settings{BlockTelemetry: y.BlockTelemetry},
		Doc: Document{
			Global: Global{
				DenyDomains:   y.Global.DenyDomains,
				DenyCountries: y.Global.DenyCountries,
				DenyASNs:      y.Global.DenyASNs,
				DenyIPCIDRs:   y.Global.DenyIPCIDRs,
			},
		},
	}
	for _, a := range y.Apps {
		fd.Doc.Apps = append(fd.Doc.Apps, AppRules{
			Match: AppKey{
				ExeSHA: a.Match.ExeSHA,
				Exe:    a.Match.Exe,
				Comm:   a.Match.Comm,
				Unit:   a.Match.Unit,
			},
			AllowOnlyDomains: a.AllowOnlyDomains,
			AllowCountries:   a.AllowCountries,
			AllowASNs:        a.AllowASNs,
			DenyDomains:      a.DenyDomains,
			DenyCountries:    a.DenyCountries,
			DenyASNs:         a.DenyASNs,
			DenyPorts:        a.DenyPorts,
		})
	}
	return fd, nil
}

// SerialiseYAML returns a YAML representation of the policy +
// settings; suitable for round-tripping through the UI.
func SerialiseYAML(fd *FullDocument) ([]byte, error) {
	if fd == nil {
		return []byte{}, nil
	}
	y := yamlDocument{
		BlockTelemetry: fd.Settings.BlockTelemetry,
		Global: yamlGlobal{
			DenyDomains:   fd.Doc.Global.DenyDomains,
			DenyCountries: fd.Doc.Global.DenyCountries,
			DenyASNs:      fd.Doc.Global.DenyASNs,
			DenyIPCIDRs:   fd.Doc.Global.DenyIPCIDRs,
		},
	}
	for _, a := range fd.Doc.Apps {
		y.Apps = append(y.Apps, yamlAppRule{
			Match: yamlAppMatch{
				ExeSHA: a.Match.ExeSHA, Exe: a.Match.Exe,
				Comm: a.Match.Comm, Unit: a.Match.Unit,
			},
			AllowOnlyDomains: a.AllowOnlyDomains,
			AllowCountries:   a.AllowCountries,
			AllowASNs:        a.AllowASNs,
			DenyDomains:      a.DenyDomains,
			DenyCountries:    a.DenyCountries,
			DenyASNs:         a.DenyASNs,
			DenyPorts:        a.DenyPorts,
		})
	}
	return yaml.Marshal(&y)
}

// FileSource is the canonical on-disk policy loader: reads a file,
// keeps the parsed FullDocument in an atomic pointer, and polls for
// changes every Interval. Cheap and predictable; avoids the
// fsnotify dep.
type FileSource struct {
	Path     string
	Interval time.Duration

	mu    sync.Mutex
	cur   atomic.Pointer[FullDocument]
	lastM time.Time

	OnChange func(*FullDocument)
}

// Load reads the file once and parses it. If the file doesn't exist,
// returns an empty FullDocument (not an error — the operator may not
// have written one yet).
func (s *FileSource) Load() (*FullDocument, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			fd := &FullDocument{}
			s.cur.Store(fd)
			return fd, nil
		}
		return nil, fmt.Errorf("policy: read %s: %w", s.Path, err)
	}
	fd, err := ParseYAML(b)
	if err != nil {
		return nil, err
	}
	s.cur.Store(fd)
	st, _ := os.Stat(s.Path)
	if st != nil {
		s.lastM = st.ModTime()
	}
	return fd, nil
}

// Watch polls the file at Interval; on mtime change it re-loads and
// fires OnChange (if set). Returns when ctx is done.
func (s *FileSource) Watch(stop <-chan struct{}) {
	if s.Interval <= 0 {
		s.Interval = 2 * time.Second
	}
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			st, err := os.Stat(s.Path)
			if err != nil {
				continue
			}
			if !st.ModTime().After(s.lastM) {
				continue
			}
			fd, err := s.Load()
			if err != nil {
				continue
			}
			if s.OnChange != nil {
				s.OnChange(fd)
			}
		}
	}
}

// Save writes the FullDocument back to the file with mode 0644. The
// caller's modification time is preserved by re-touching the file
// after Save so the watcher's mtime check fires on the next tick.
func (s *FileSource) Save(fd *FullDocument) error {
	b, err := SerialiseYAML(fd)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.WriteFile(s.Path, b, 0o644); err != nil {
		return err
	}
	s.lastM = time.Time{} // force re-read on next poll
	return nil
}

// Current returns the last-loaded policy.
func (s *FileSource) Current() *FullDocument {
	if p := s.cur.Load(); p != nil {
		return p
	}
	return &FullDocument{}
}
