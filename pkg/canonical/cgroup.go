package canonical

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// CgroupInfo describes the cgroup membership of a process.
//
// On cgroup-v2 hosts, a process has exactly one cgroup path. On
// hybrid cgroup-v1 + v2 hosts, the v2 path is in the entry with
// hierarchy ID "0" and controller list "". Container IDs are
// parsed heuristically from the path components.
type CgroupInfo struct {
	// Path is the cgroup-v2 (unified) path if available, else the
	// most-specific v1 path. Always absolute, starts with "/".
	Path string

	// ContainerID is parsed from the path when a container-runtime
	// pattern is recognised (docker, containerd, podman, lxc,
	// kubernetes / kubepods). Empty when no container is detected.
	ContainerID string

	// ContainerRuntime identifies which runtime owns the container,
	// when detected. One of: docker, containerd, podman, lxc, crio,
	// kubernetes, "".
	ContainerRuntime string

	// SystemdUnit is set when the path contains a *.service segment
	// and the process is running under systemd. Empty otherwise.
	SystemdUnit string
}

// IsContainerised returns true when ContainerID is non-empty.
func (c CgroupInfo) IsContainerised() bool { return c.ContainerID != "" }

// ReadCgroup parses /proc/PID/cgroup for the given pid and returns
// the canonical CgroupInfo. Returns PathNotFound if the process has
// exited.
func ReadCgroup(pid uint32) (CgroupInfo, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		if os.IsNotExist(err) {
			return CgroupInfo{}, ProcKeyNotFound{PID: pid}
		}
		return CgroupInfo{}, fmt.Errorf("canonical: open cgroup for pid %d: %w", pid, err)
	}
	defer f.Close()
	return parseCgroupFile(f)
}

// ParseCgroupLine extracts the cgroup path from a single
// /proc/PID/cgroup line. The format is `id:controller:path`.
// Returns ("","") for malformed lines.
func ParseCgroupLine(line string) (id, controller, path string) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) != 3 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[2]
}

func parseCgroupFile(r interface {
	Read(p []byte) (int, error)
}) (CgroupInfo, error) {
	sc := bufio.NewScanner(r)
	// First v2 line (id=0, controller="") wins; otherwise pick the
	// most specific (longest) v1 path.
	var v2Path, deepestV1Path string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		id, controller, path := ParseCgroupLine(line)
		if id == "" {
			continue
		}
		if id == "0" && controller == "" {
			v2Path = path
			continue
		}
		if len(path) > len(deepestV1Path) {
			deepestV1Path = path
		}
	}
	if err := sc.Err(); err != nil {
		return CgroupInfo{}, fmt.Errorf("canonical: scan cgroup: %w", err)
	}

	path := v2Path
	if path == "" {
		path = deepestV1Path
	}
	if path == "" {
		return CgroupInfo{Path: "/"}, nil
	}

	info := CgroupInfo{Path: path}
	info.ContainerRuntime, info.ContainerID = detectContainer(path)
	info.SystemdUnit = detectSystemdUnit(path)
	return info, nil
}

// detectContainer recognises the common container-runtime patterns
// in a cgroup path. Returns the runtime name and container id, or
// ("", "") when no container is detected.
//
// Patterns recognised:
//   docker:        /docker/<64-hex>
//                  /system.slice/docker-<64-hex>.scope
//   containerd:    /system.slice/containerd-<64-hex>.scope
//                  /containerd.io/.../sandboxes/<id>
//   podman:        /machine.slice/libpod-<64-hex>.scope
//   lxc:           /lxc/<name>
//                  /lxc.payload/<name>
//   crio:          /system.slice/crio-<64-hex>.scope
//   kubernetes:    /kubepods/.../<pod-uid>/<container-id>
//                  /kubepods.slice/kubepods-pod<uid>.slice/cri-containerd-<id>.scope
func detectContainer(path string) (runtime, id string) {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "kubepods"):
		// Take the last 64-hex-ish segment as the container id.
		return "kubernetes", lastHexSegment(path, 8)
	case strings.Contains(lower, "/docker-") || strings.Contains(lower, "/docker/"):
		return "docker", lastHexSegment(path, 12)
	case strings.Contains(lower, "containerd-") || strings.Contains(lower, "cri-containerd"):
		return "containerd", lastHexSegment(path, 12)
	case strings.Contains(lower, "libpod-") || strings.Contains(lower, "/machine.slice/"):
		return "podman", lastHexSegment(path, 12)
	case strings.Contains(lower, "crio-"):
		return "crio", lastHexSegment(path, 12)
	case strings.Contains(lower, "/lxc/") || strings.Contains(lower, "/lxc.payload/"):
		return "lxc", lastSegment(path)
	}
	return "", ""
}

// lastHexSegment returns the last "/-_"-separated chunk that's at
// least `minHex` hex characters long. Used to extract container ids
// from paths regardless of the prefix scheme.
func lastHexSegment(path string, minHex int) string {
	// Walk back through "/-_." separators.
	splitters := func(r rune) bool {
		return r == '/' || r == '-' || r == '_' || r == '.'
	}
	parts := strings.FieldsFunc(path, splitters)
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if isHex(p) && len(p) >= minHex {
			return p
		}
		// Strip a "scope" suffix and try again.
		if strings.HasSuffix(p, "scope") {
			// already split by '.' so this rarely matters
		}
	}
	return ""
}

func lastSegment(path string) string {
	idx := strings.LastIndex(path, "/")
	if idx < 0 || idx == len(path)-1 {
		return ""
	}
	return path[idx+1:]
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// detectSystemdUnit returns the most-specific *.service / *.scope /
// *.slice segment from a cgroup path, or "" when none is present.
func detectSystemdUnit(path string) string {
	parts := strings.Split(path, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if strings.HasSuffix(p, ".service") ||
			strings.HasSuffix(p, ".scope") ||
			strings.HasSuffix(p, ".slice") {
			return p
		}
	}
	return ""
}
