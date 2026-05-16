// Package container resolves cgroup IDs and container IDs to a human
// container name + image:tag.
//
// We support three discovery paths in order:
//
//   - Docker REST socket at /var/run/docker.sock
//   - containerd CRI socket at /run/containerd/containerd.sock
//   - cgroup-v2 path heuristic (k8s pod ID extraction)
//
// Lookups are cached for 30s so a busy host doesn't hit the runtime
// API on every event.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Resolver maps cgroup_id / container_id -> container info.
type Resolver struct {
	mu     sync.RWMutex
	cache  map[string]cacheEntry
	ttl    time.Duration
	docker *http.Client
}

type cacheEntry struct {
	info    Info
	expires time.Time
}

// Info describes a running container.
type Info struct {
	ID      string
	Name    string
	Image   string
	ImageID string
	PodName string // k8s
	Labels  map[string]string
}

// New returns a Resolver with sensible defaults.
func New() *Resolver {
	return &Resolver{
		cache: map[string]cacheEntry{},
		ttl:   30 * time.Second,
		docker: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.DialTimeout("unix", "/var/run/docker.sock", time.Second)
				},
			},
		},
	}
}

// Resolve returns container info for cgroup_id, or zero value when no
// container can be identified.
//
// cgroupPath is the contents of /proc/<pid>/cgroup for the originating
// pid; the resolver extracts the container ID from it. Empty
// cgroupPath triggers the cache lookup but no fresh resolution.
func (r *Resolver) Resolve(cgroupPath string) Info {
	id := extractContainerID(cgroupPath)
	if id == "" {
		return Info{}
	}
	r.mu.RLock()
	if e, ok := r.cache[id]; ok && time.Now().Before(e.expires) {
		r.mu.RUnlock()
		return e.info
	}
	r.mu.RUnlock()

	info := r.lookup(id)
	r.mu.Lock()
	r.cache[id] = cacheEntry{info: info, expires: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return info
}

// ResolvePID is a convenience that reads /proc/<pid>/cgroup itself.
func (r *Resolver) ResolvePID(pid uint32) Info {
	body, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup"))
	if err != nil {
		return Info{}
	}
	return r.Resolve(string(body))
}

// extractContainerID parses the cgroup path. Recognised forms:
//   - "/docker/<full-id>"
//   - "/system.slice/docker-<id>.scope"
//   - "/kubepods/.../<pod-id>/<container-id>"
//   - "/system.slice/containerd-<id>.scope"
func extractContainerID(s string) string {
	for _, line := range strings.Split(s, "\n") {
		// /proc/<pid>/cgroup format: "0::/system.slice/..."
		if i := strings.LastIndex(line, "::"); i >= 0 {
			line = line[i+2:]
		}
		if i := strings.LastIndex(line, ":"); i >= 0 {
			line = line[i+1:]
		}
		// Try docker-<id>.scope
		if idx := strings.Index(line, "docker-"); idx >= 0 {
			rest := line[idx+len("docker-"):]
			if dot := strings.Index(rest, "."); dot > 0 {
				if isContainerID(rest[:dot]) {
					return rest[:dot]
				}
			}
			if isContainerID(rest) {
				return rest
			}
		}
		// Try containerd-<id>.scope
		if idx := strings.Index(line, "cri-containerd-"); idx >= 0 {
			rest := line[idx+len("cri-containerd-"):]
			if dot := strings.Index(rest, "."); dot > 0 {
				if isContainerID(rest[:dot]) {
					return rest[:dot]
				}
			}
		}
		// Try plain trailing id (k8s pods)
		seg := lastSegment(line)
		if isContainerID(seg) {
			return seg
		}
	}
	return ""
}

func lastSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// isContainerID accepts 12+ hex chars (Docker short or full ID).
func isContainerID(s string) bool {
	if len(s) < 12 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// lookup hits the docker socket. Future revisions will fall back to
// containerd; for v0.0.x docker is the dominant runtime.
func (r *Resolver) lookup(id string) Info {
	if info, ok := r.dockerInspect(id); ok {
		return info
	}
	// Last-ditch: return what we know from the ID alone.
	return Info{ID: id}
}

func (r *Resolver) dockerInspect(id string) (Info, bool) {
	url := "http://docker/containers/" + id + "/json"
	resp, err := r.docker.Get(url)
	if err != nil {
		return Info{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Info{}, false
	}
	var raw struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		Image string `json:"Image"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Info{}, false
	}
	name := strings.TrimPrefix(raw.Name, "/")
	return Info{
		ID:      raw.ID,
		Name:    name,
		Image:   raw.Config.Image,
		ImageID: raw.Image,
		Labels:  raw.Config.Labels,
		PodName: raw.Config.Labels["io.kubernetes.pod.name"],
	}, true
}
