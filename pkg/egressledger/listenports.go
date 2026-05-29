// Host-wide listening-port set, refreshed periodically from
// /proc/net/tcp{,6}. Used by inferRole to authoritatively decide
// whether a flow's local src_port is a listening server port —
// covering custom apps on non-standard ports that the static
// well-known-port table cannot recognize.
//
// Maintained inside the ledger so the pipeline observe path can
// consult it without a new dependency.
package egressledger

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type listenSet struct {
	v atomic.Value // map[uint16]struct{}
}

func (s *listenSet) has(port uint16) bool {
	m, _ := s.v.Load().(map[uint16]struct{})
	if m == nil {
		return false
	}
	_, ok := m[port]
	return ok
}

func (s *listenSet) replace(m map[uint16]struct{}) {
	s.v.Store(m)
}

// listenSetGlobal is the process-wide singleton. Inferring role
// happens at Observe time which is called from the pipeline — and
// the pipeline only constructs one ledger per daemon. A singleton
// is simpler than threading the set through Options + Event.
var (
	listenSetGlobal     = &listenSet{}
	listenSetOnce       sync.Once
	listenSetStopCancel context.CancelFunc
)

// startListenSetRefresher starts a goroutine that re-scans /proc/net/tcp
// every refreshEvery and updates listenSetGlobal. Stops on ctx cancel.
// Safe to call multiple times — only one refresher ever runs.
func startListenSetRefresher(ctx context.Context, refreshEvery time.Duration) {
	listenSetOnce.Do(func() {
		c, cancel := context.WithCancel(ctx)
		listenSetStopCancel = cancel
		if refreshEvery <= 0 {
			refreshEvery = 15 * time.Second
		}
		// Prime immediately so the first events get accurate role.
		listenSetGlobal.replace(scanListenPorts())
		go func() {
			t := time.NewTicker(refreshEvery)
			defer t.Stop()
			for {
				select {
				case <-c.Done():
					return
				case <-t.C:
					listenSetGlobal.replace(scanListenPorts())
				}
			}
		}()
	})
}

// scanListenPorts reads /proc/net/tcp and /proc/net/tcp6, returning
// the set of local TCP ports currently in LISTEN (state=0A).
func scanListenPorts() map[uint16]struct{} {
	out := map[uint16]struct{}{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		lines := strings.Split(string(body), "\n")
		for i, line := range lines {
			if i == 0 {
				continue
			}
			fs := strings.Fields(line)
			if len(fs) < 4 || fs[3] != "0A" {
				continue
			}
			la := fs[1]
			c := strings.IndexByte(la, ':')
			if c < 0 {
				continue
			}
			pv, err := strconv.ParseUint(la[c+1:], 16, 16)
			if err != nil {
				continue
			}
			out[uint16(pv)] = struct{}{}
		}
	}
	return out
}

// localPortIsListening returns true if port appears in the cached
// host-wide listening set. Used by inferRole.
func localPortIsListening(port uint16) bool {
	return listenSetGlobal.has(port)
}
