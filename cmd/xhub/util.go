package main

import (
	"context"
	"net"
	"os"
	"time"
)

// cmd_ctx_root returns a background context. Kept as a thin helper so
// the main runHub flow reads cleanly and we have one place to plug in
// per-test contexts later.
func cmd_ctx_root() context.Context { return context.Background() }

// contextWithTimeout is a tiny wrapper to reduce import noise in main.
func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// notifyReady mirrors xhelix's sd_notify(READY=1) behaviour so xhub
// can run under systemd Type=notify (with periodic WATCHDOG=1 keepalive
// when WATCHDOG_USEC is set).
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
	send("READY=1\nSTATUS=xhub up\n")

	usecStr := os.Getenv("WATCHDOG_USEC")
	if usecStr == "" {
		return
	}
	var usec int64
	for _, c := range []byte(usecStr) {
		if c < '0' || c > '9' {
			return
		}
		usec = usec*10 + int64(c-'0')
	}
	if usec <= 0 {
		return
	}
	tick := time.Duration(usec) * time.Microsecond / 2
	if tick < 5*time.Second {
		tick = 5 * time.Second
	}
	// Watchdog ping goroutine — runs for the lifetime of the process.
	// There is no graceful-shutdown path; pretending otherwise would
	// require plumbing a ctx into notifyReady from runHub.
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for range t.C {
			send("WATCHDOG=1\n")
		}
	}()
}
