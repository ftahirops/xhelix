//go:build linux

package main

import (
	"net"
	"os"
	"strconv"
	"time"
)

// notifyReady sends sd_notify(READY=1) to systemd if NOTIFY_SOCKET is
// set, and (if WATCHDOG_USEC is set) launches a goroutine that pings
// WATCHDOG=1 at half the watchdog interval. Pure stdlib, no CGO.
//
// Without the watchdog ping, systemd's WatchdogSec= in the unit file
// kills the daemon every interval as "hung". The unit ships with
// WatchdogSec=30s, so we ping every 15s.
func notifyReady() {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	send := func(payload string) {
		conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(payload))
	}
	send("READY=1\nSTATUS=xhelix daemon up\n")

	// WATCHDOG_USEC is the µs interval set by WatchdogSec=. Half it.
	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return
	}
	usec, err := strconv.ParseInt(usecStr, 10, 64)
	if err != nil || usec <= 0 {
		return
	}
	tick := time.Duration(usec) * time.Microsecond / 2
	if tick < 5*time.Second {
		tick = 5 * time.Second
	}
	// Watchdog ping goroutine. There is no graceful-shutdown path —
	// it runs for the lifetime of the process. The previous version
	// created a context.WithCancel that nothing external ever
	// cancelled, giving the false impression the goroutine was
	// stoppable. Be honest: tick forever.
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for range t.C {
			send("WATCHDOG=1\n")
		}
	}()
}
