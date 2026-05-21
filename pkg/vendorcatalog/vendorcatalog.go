// Package vendorcatalog auto-detects known control-panel / hosting
// stacks at xhelix startup and returns the binary patterns each
// stack legitimately runs.
//
// Problem this solves: hand-curated allowlists don't scale. A
// Plesk host has different paths than a cPanel host has different
// paths than a DirectAdmin host. Operators don't want to file a
// support ticket every time they install xhelix on a new server
// just to be told which paths their control panel uses.
//
// Solution: xhelix ships a small catalog of well-known vendors,
// each defined by:
//   - a few `detect` paths whose existence confirms the vendor
//     (e.g. /opt/psa/version → Plesk)
//   - a list of binary globs the vendor legitimately runs
//
// At daemon startup we run AutoDetect, find which vendors are
// installed, and feed their binary patterns into runtimeallow.
//
// Adding a new vendor: drop a YAML file into
// /usr/share/xhelix/vendors/ (or alongside the binary), or use
// `xhelixctl posture set-vendor <name>` to point xhelix at a
// custom catalog entry.
package vendorcatalog

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// Vendor is one detectable hosting/control-panel stack.
type Vendor struct {
	Name string `yaml:"name"`
	// Detect: any path whose existence confirms this vendor is
	// installed. ANY match → vendor detected.
	Detect []string `yaml:"detect"`
	// Binaries: glob patterns of binaries this vendor runs that
	// xhelix should treat as legitimate userland runtimes.
	Binaries []string `yaml:"binaries"`
	// Description: human-readable, shown in xhelixctl posture
	// output.
	Description string `yaml:"description,omitempty"`
}

// Catalog is the loaded vendor set.
type Catalog struct {
	Vendors []Vendor
}

// Default returns the baked-in catalog covering the most-common
// Linux hosting stacks. Operators extend by dropping additional
// YAML files into /usr/share/xhelix/vendors/.
func Default() *Catalog {
	return &Catalog{
		Vendors: []Vendor{
			{
				Name:        "plesk",
				Description: "Plesk control panel (paid)",
				Detect: []string{
					"/opt/psa/version",
					"/opt/plesk/psa/version",
					"/usr/local/psa/version",
				},
				Binaries: []string{
					"/opt/plesk/php/*/sbin/*",
					"/opt/plesk/php/*/bin/*",
					"/opt/plesk/admin/*",
					"/opt/psa/admin/sbin/*",
					"/opt/psa/admin/bin/*",
					"/opt/psa/bin/*",
					"/usr/lib/plesk-9.0/*",
					"/usr/local/psa/admin/sbin/*",
					"/usr/local/psa/admin/bin/*",
					"/usr/local/psa/bin/*",
				},
			},
			{
				Name:        "cpanel",
				Description: "cPanel control panel (paid)",
				Detect: []string{
					"/usr/local/cpanel/version",
					"/usr/local/cpanel/cpanel",
				},
				Binaries: []string{
					"/usr/local/cpanel/3rdparty/bin/*",
					"/usr/local/cpanel/3rdparty/sbin/*",
					"/usr/local/cpanel/bin/*",
					"/usr/local/cpanel/sbin/*",
					"/usr/local/cpanel/scripts/*",
					"/usr/local/cpanel/3rdparty/php/*/bin/*",
					"/usr/local/cpanel/3rdparty/php/*/sbin/*",
					"/usr/local/cpanel/Cpanel/*",
					"/var/cpanel/scripts/*",
				},
			},
			{
				Name:        "directadmin",
				Description: "DirectAdmin control panel (paid)",
				Detect: []string{
					"/usr/local/directadmin/directadmin",
					"/usr/local/directadmin/conf/directadmin.conf",
				},
				Binaries: []string{
					"/usr/local/directadmin/*",
					"/usr/local/directadmin/scripts/*",
					"/usr/local/directadmin/custombuild/*",
					"/usr/local/directadmin/data/users/*/scripts/*",
				},
			},
			{
				Name:        "webmin",
				Description: "Webmin (free) + Virtualmin",
				Detect: []string{
					"/etc/webmin/version",
					"/usr/share/webmin",
				},
				Binaries: []string{
					"/usr/libexec/webmin/*",
					"/usr/share/webmin/*",
					"/etc/webmin/*.cgi",
				},
			},
			{
				Name:        "ispconfig",
				Description: "ISPConfig (free)",
				Detect: []string{
					"/usr/local/ispconfig/server/lib/config.inc.php",
					"/usr/local/ispconfig/server/server.sh",
				},
				Binaries: []string{
					"/usr/local/ispconfig/server/*",
					"/usr/local/ispconfig/interface/*",
				},
			},
			{
				Name:        "imunify360",
				Description: "Imunify360 + ImunifyAV security suite",
				Detect: []string{
					"/etc/imunify360/imunify360.config",
					"/opt/imunify360/venv/bin/python",
					"/usr/sbin/imunify-notifier",
				},
				Binaries: []string{
					"/opt/imunify360/*",
					"/opt/imunify-av/*",
					"/usr/lib/imunify360/*",
					"/usr/sbin/imunify-notifier",
					"/usr/libexec/imunify-notifier/*",
					"/usr/share/imunify360/*",
				},
			},
			{
				Name:        "bitninja",
				Description: "BitNinja Server Security",
				Detect: []string{
					"/etc/bitninja",
					"/opt/bitninja/version",
				},
				Binaries: []string{
					"/opt/bitninja/*",
					"/usr/sbin/bitninja-*",
				},
			},
			{
				Name:        "configserver-csf",
				Description: "ConfigServer Security & Firewall (CSF)",
				Detect: []string{
					"/etc/csf/csf.conf",
					"/usr/sbin/csf",
				},
				Binaries: []string{
					"/usr/sbin/csf",
					"/usr/sbin/lfd",
					"/usr/local/csf/bin/*",
					"/etc/csf/*.pl",
				},
			},
			{
				Name:        "ai-engine-ollama",
				Description: "Ollama / local LLM stack",
				Detect: []string{
					"/usr/local/bin/ollama",
					"/usr/bin/ollama",
				},
				Binaries: []string{
					"/usr/local/bin/ollama",
					"/usr/bin/ollama",
					"/root/.ollama/*",
				},
			},
			{
				Name:        "docker-engine",
				Description: "Docker engine + containerd",
				Detect: []string{
					"/usr/bin/docker",
					"/usr/bin/dockerd",
					"/var/run/docker.sock",
				},
				Binaries: []string{
					"/usr/bin/docker*",
					"/usr/sbin/docker*",
					"/usr/bin/containerd*",
					"/usr/bin/runc",
					"/usr/bin/ctr",
					"/var/lib/docker/*",
				},
			},
			{
				Name:        "k8s-kubelet",
				Description: "Kubernetes worker node",
				Detect: []string{
					"/var/lib/kubelet/config.yaml",
					"/etc/kubernetes/kubelet.conf",
					"/usr/bin/kubelet",
				},
				Binaries: []string{
					"/usr/bin/kubelet",
					"/usr/bin/kubeadm",
					"/usr/bin/kubectl",
					"/usr/local/bin/kubelet",
				},
			},
			{
				Name:        "hetzner-cloud",
				Description: "Hetzner cloud node tooling",
				Detect: []string{
					"/etc/hc-net-ifup",
					"/usr/sbin/hc-net-ifup",
				},
				Binaries: []string{
					"/usr/sbin/hc-net-ifup",
					"/usr/bin/qemu-ga",
					"/usr/sbin/qemu-ga",
				},
			},
		},
	}
}

// LoadFile reads a single vendor YAML.
func LoadFile(path string) (*Vendor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vendor
	if err := yaml.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if v.Name == "" {
		return nil, fmt.Errorf("%s: vendor.name required", path)
	}
	return &v, nil
}

// LoadDir reads every *.yaml in dir as one Vendor and returns a
// Catalog overlaying them on Default.
//
// Missing dir is not an error — Default() is returned.
func LoadDir(dir string) (*Catalog, error) {
	cat := Default()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return cat, nil
		}
		return cat, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".yaml" && filepath.Ext(name) != ".yml" {
			continue
		}
		v, err := LoadFile(filepath.Join(dir, name))
		if err != nil {
			// Skip malformed file; surface via warning channel
			// upstream (caller passes a logger).
			continue
		}
		cat.Vendors = append(cat.Vendors, *v)
	}
	return cat, nil
}

// Detection records what AutoDetect found.
type Detection struct {
	Vendor   string   // Vendor.Name
	Reason   string   // which Detect path matched
	Binaries []string // copy of Vendor.Binaries
}

// AutoDetect returns the set of vendors whose Detect paths exist
// on the host. Result is sorted by vendor name for stable
// reporting.
func (c *Catalog) AutoDetect() []Detection {
	var out []Detection
	for _, v := range c.Vendors {
		for _, p := range v.Detect {
			if _, err := os.Stat(p); err == nil {
				out = append(out, Detection{
					Vendor:   v.Name,
					Reason:   p,
					Binaries: append([]string(nil), v.Binaries...),
				})
				break // first hit is enough
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Vendor < out[j].Vendor })
	return out
}

// AllBinaries returns the concatenated binary pattern list from a
// set of detections. Use to feed runtimeallow.Set.
func AllBinaries(dets []Detection) []string {
	var out []string
	for _, d := range dets {
		out = append(out, d.Binaries...)
	}
	return out
}
