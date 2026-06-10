//go:build linux

package appregistry

import (
	"os"
	"path/filepath"
	"strings"
)

// DiscoveredService represents a running process group that could become
// an app service. It is returned by Discover() for display in the
// "new app" wizard.
type DiscoveredService struct {
	CgroupPath  string      `json:"cgroup_path"`
	UnitName    string      `json:"unit_name"`
	BinaryPath  string      `json:"binary_path"`
	ServiceType ServiceType `json:"service_type"`
	PIDs        []int32     `json:"pids"`
	SampleComm  string      `json:"sample_comm"`
}

// Discover scans /proc for running processes and groups them by their
// cgroup v2 path. Returns one DiscoveredService per unique cgroup,
// populated with the most common binary among the group's PIDs.
//
// Requires read access to /proc — call as root or with CAP_SYS_PTRACE.
func Discover() ([]DiscoveredService, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	type pidInfo struct {
		pid    int32
		cgroup string
		binary string
		comm   string
	}

	var pids []pidInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Only numeric entries are PID directories.
		name := e.Name()
		if !isNumeric(name) {
			continue
		}
		pid := parsePID(name)
		if pid == 0 {
			continue
		}
		cgroup := readCgroupV2("/proc/" + name + "/cgroup")
		if cgroup == "" || cgroup == "/" {
			continue
		}
		binary, _ := os.Readlink("/proc/" + name + "/exe")
		comm, _ := os.ReadFile("/proc/" + name + "/comm")
		pids = append(pids, pidInfo{
			pid:    pid,
			cgroup: cgroup,
			binary: strings.TrimSpace(binary),
			comm:   strings.TrimSpace(string(comm)),
		})
	}

	// Group by cgroup. Use map: cgroup → first binary seen.
	type group struct {
		binary string
		comm   string
		pids   []int32
	}
	groups := make(map[string]*group)
	for _, p := range pids {
		g, ok := groups[p.cgroup]
		if !ok {
			g = &group{binary: p.binary, comm: p.comm}
			groups[p.cgroup] = g
		}
		g.pids = append(g.pids, p.pid)
	}

	out := make([]DiscoveredService, 0, len(groups))
	for cgroupPath, g := range groups {
		svc := DiscoveredService{
			CgroupPath:  cgroupPath,
			UnitName:    unitFromCgroup(cgroupPath),
			BinaryPath:  g.binary,
			ServiceType: detectServiceType(g.binary, g.comm),
			PIDs:        g.pids,
			SampleComm:  g.comm,
		}
		out = append(out, svc)
	}
	return out, nil
}

// unitFromCgroup extracts the systemd unit name from a cgroup path.
// /system.slice/php-fpm.service → php-fpm.service
// /system.slice/nginx.service/... → nginx.service
func unitFromCgroup(cgroupPath string) string {
	parts := strings.Split(strings.TrimPrefix(cgroupPath, "/"), "/")
	for _, p := range parts {
		if strings.HasSuffix(p, ".service") ||
			strings.HasSuffix(p, ".scope") ||
			strings.HasSuffix(p, ".slice") {
			return p
		}
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// detectServiceType maps a binary path or comm name to a ServiceType.
func detectServiceType(binary, comm string) ServiceType {
	check := func(s string) ServiceType {
		s = strings.ToLower(filepath.Base(s))
		switch {
		case strings.HasPrefix(s, "nginx"):
			return ServiceNginx
		case strings.HasPrefix(s, "apache"), strings.HasPrefix(s, "httpd"):
			return ServiceApache
		case strings.HasPrefix(s, "php-fpm"), s == "php":
			return ServicePhpFpm
		case strings.HasPrefix(s, "mysqld"), strings.HasPrefix(s, "mariadb"):
			return ServiceMySQL
		case strings.HasPrefix(s, "postgres"):
			return ServicePostgres
		case strings.HasPrefix(s, "redis"):
			return ServiceRedis
		case s == "node", strings.HasPrefix(s, "node "):
			return ServiceNode
		case strings.HasPrefix(s, "python"), strings.HasPrefix(s, "python3"),
			strings.HasPrefix(s, "gunicorn"), strings.HasPrefix(s, "uvicorn"),
			strings.HasPrefix(s, "uwsgi"):
			return ServicePython
		}
		return ""
	}
	if t := check(binary); t != "" {
		return t
	}
	if t := check(comm); t != "" {
		return t
	}
	return ServiceCustom
}

// readCgroupV2 reads the cgroup v2 unified path from a /proc/<pid>/cgroup
// file. Looks for the "0::" prefix line.
func readCgroupV2(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return strings.TrimPrefix(line, "0::")
		}
	}
	return ""
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parsePID(s string) int32 {
	var n int32
	for _, c := range s {
		n = n*10 + int32(c-'0')
	}
	return n
}
