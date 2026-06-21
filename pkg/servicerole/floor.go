package servicerole

import (
	"strings"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
)

// DenyExec reports whether a process in cgroupPath, classified to a
// protected service role, must be denied execve(binaryPath) by that role's
// built-in DenyExecPaths. Tighten-only: ok=false (no classification) yields
// deny=false, so this never blocks unclassified processes.
func DenyExec(cgroupPath, binaryPath string) (bool, string) {
	if binaryPath == "" {
		return false, ""
	}
	kind, role, ok := ClassifyByCgroup(cgroupPath)
	if !ok {
		return false, ""
	}
	sc, err := contracts.Builtin(kind, role)
	if err != nil {
		return false, ""
	}
	for _, deny := range sc.DenyExecPaths {
		if matchExecPath(deny, binaryPath) {
			return true, "service-role:" + string(kind) + " deny exec " + binaryPath
		}
	}
	return false, ""
}

// matchExecPath matches a DenyExecPaths entry against a binary path. A
// trailing '*' is a prefix wildcard (e.g. "/usr/bin/python*"); otherwise
// the match is exact.
func matchExecPath(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	if pattern[len(pattern)-1] == '*' {
		return strings.HasPrefix(path, pattern[:len(pattern)-1])
	}
	return pattern == path
}
