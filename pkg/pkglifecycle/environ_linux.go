//go:build linux

package pkglifecycle

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// platformReadEnviron reads /proc/<pid>/environ and returns only the
// npm_* environment variables (filtering minimises map allocation on
// the hot path — most processes have no npm vars at all).
//
// Returns nil, nil when the process has already exited (ENOENT / ESRCH)
// — this is a normal race and not worth logging.
func platformReadEnviron(pid uint32) (map[string]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		// Process already exited — normal race on fast-lived helpers.
		return nil, nil
	}
	env := make(map[string]string, 8)
	for _, kv := range bytes.Split(data, []byte{0}) {
		if idx := bytes.IndexByte(kv, '='); idx > 0 {
			key := string(kv[:idx])
			if strings.HasPrefix(key, "npm_") {
				env[key] = string(kv[idx+1:])
			}
		}
	}
	return env, nil
}
