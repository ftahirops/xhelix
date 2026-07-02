//go:build linux

package enforce

import (
	"os"
	"strconv"
	"strings"
)

// procStartTicks reads field 22 (starttime, in clock ticks since boot) from
// /proc/<pid>/stat. It is the kernel's per-process boot-relative start time and
// is the cheapest stable identity we can compare to detect pid reuse: a pid
// recycled onto a different process will have a different start time.
//
// The comm field (field 2) can contain spaces and parentheses, so we parse the
// numeric fields from after the final ')'.
func procStartTicks(pid uint32) (uint64, bool) {
	data, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, false
	}
	s := string(data)
	rparen := strings.LastIndexByte(s, ')')
	if rparen < 0 || rparen+2 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[rparen+2:])
	// After ')', field 3 (state) is index 0, so starttime (field 22) is index 19.
	if len(fields) <= 19 {
		return 0, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false
	}
	return ticks, true
}
