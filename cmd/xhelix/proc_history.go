package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/connstate"
)

// procHistory keeps a small time-series of per-pid bytes-in/bytes-out
// totals so the UI drill panel can render a sparkline.
//
// Sampling cadence: every 5 seconds. Retention: last 120 samples =
// 10 minutes of history. Bounded by maxPIDs to keep memory tight on
// busy hosts.
type procHistory struct {
	mu     sync.RWMutex
	series map[uint32]*pidSeries
	maxPID int

	// Last snapshot of bytes per pid — used to compute deltas so the
	// sparkline shows rate (bytes per sample interval), not absolute
	// counters that climb forever.
	last map[uint32]bytesPair
}

type pidSeries struct {
	comm      string
	samples   []pidSample
	lastSeen  time.Time
}

type pidSample struct {
	At        time.Time
	BytesIn   uint64 // network bytes from connstate (per-flow)
	BytesOut  uint64
	IORead    uint64 // syscall read bytes from /proc/PID/io (rchar delta)
	IOWrite   uint64 // syscall write bytes (wchar delta) — includes net + file
	LiveFlows int
}

type bytesPair struct {
	In, Out  uint64
	IORd, IOWr uint64
}

const (
	historySamples = 120
	historyMaxPIDs = 512
	historyTick    = 5 * time.Second
)

func newProcHistory() *procHistory {
	return &procHistory{
		series: make(map[uint32]*pidSeries, 64),
		last:   make(map[uint32]bytesPair, 64),
		maxPID: historyMaxPIDs,
	}
}

// Run samples the table forever; exits on ctx.Done.
func (h *procHistory) Run(ctx context.Context, tab *connstate.Table) {
	t := time.NewTicker(historyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			h.sample(tab, now)
		}
	}
}

func (h *procHistory) sample(tab *connstate.Table, now time.Time) {
	if tab == nil {
		return
	}
	type acc struct {
		comm  string
		bIn   uint64
		bOut  uint64
		flows int
		ioRd  uint64
		ioWr  uint64
	}
	per := map[uint32]*acc{}
	for _, c := range tab.Snapshot() {
		a := per[c.PID]
		if a == nil {
			a = &acc{comm: c.Comm}
			per[c.PID] = a
		}
		a.bIn += c.BytesIn
		a.bOut += c.BytesOut
		a.flows++
	}
	// Pull /proc/PID/io for each tracked pid. rchar/wchar are
	// cumulative syscall byte counters — we take deltas below.
	for pid, a := range per {
		rd, wr, ok := readProcIO(pid)
		if ok {
			a.ioRd = rd
			a.ioWr = wr
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	seenPIDs := make(map[uint32]struct{}, len(per))
	for pid, a := range per {
		seenPIDs[pid] = struct{}{}
		s, ok := h.series[pid]
		if !ok {
			if len(h.series) >= h.maxPID {
				h.evictLRULocked(now)
			}
			s = &pidSeries{comm: a.comm}
			h.series[pid] = s
		}
		prev := h.last[pid]
		var dIn, dOut, dRd, dWr uint64
		if a.bIn >= prev.In {
			dIn = a.bIn - prev.In
		}
		if a.bOut >= prev.Out {
			dOut = a.bOut - prev.Out
		}
		// Treat first observation as zero so an old process doesn't
		// spike the sparkline with its lifetime totals.
		if prev.IORd > 0 && a.ioRd >= prev.IORd {
			dRd = a.ioRd - prev.IORd
		}
		if prev.IOWr > 0 && a.ioWr >= prev.IOWr {
			dWr = a.ioWr - prev.IOWr
		}
		s.samples = append(s.samples, pidSample{
			At: now, BytesIn: dIn, BytesOut: dOut,
			IORead: dRd, IOWrite: dWr, LiveFlows: a.flows,
		})
		if len(s.samples) > historySamples {
			s.samples = s.samples[len(s.samples)-historySamples:]
		}
		s.lastSeen = now
		h.last[pid] = bytesPair{In: a.bIn, Out: a.bOut, IORd: a.ioRd, IOWr: a.ioWr}
	}
	// Drop series for pids we haven't seen in the last 30 samples.
	cutoff := now.Add(-time.Duration(historySamples/4) * historyTick)
	for pid, s := range h.series {
		if _, alive := seenPIDs[pid]; alive {
			continue
		}
		if s.lastSeen.Before(cutoff) {
			delete(h.series, pid)
			delete(h.last, pid)
		}
	}
}

// evictLRULocked drops the 32 oldest series. Caller holds the lock.
func (h *procHistory) evictLRULocked(now time.Time) {
	type pair struct {
		pid uint32
		at  time.Time
	}
	all := make([]pair, 0, len(h.series))
	for pid, s := range h.series {
		all = append(all, pair{pid, s.lastSeen})
	}
	// Partial sort — find the 32 oldest.
	keep := 32
	if len(all) <= keep {
		return
	}
	// Simple selection: repeatedly find oldest and remove.
	for i := 0; i < keep; i++ {
		oldestIdx := 0
		for j := 1; j < len(all); j++ {
			if all[j].at.Before(all[oldestIdx].at) {
				oldestIdx = j
			}
		}
		delete(h.series, all[oldestIdx].pid)
		delete(h.last, all[oldestIdx].pid)
		all = append(all[:oldestIdx], all[oldestIdx+1:]...)
	}
}

// Snapshot returns a copy of the series for one pid. nil = unknown.
func (h *procHistory) Snapshot(pid uint32) []pidSample {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.series[pid]
	if s == nil {
		return nil
	}
	out := make([]pidSample, len(s.samples))
	copy(out, s.samples)
	return out
}

// RecentRate returns the sum of recent activity over `over`. Falls
// back to IO syscall deltas when per-flow byte counts are zero (the
// common case until tcp_sendmsg/tcp_recvmsg eBPF probes land).
func (h *procHistory) RecentRate(pid uint32, over time.Duration) uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := h.series[pid]
	if s == nil || len(s.samples) == 0 {
		return 0
	}
	cutoff := time.Now().Add(-over)
	var net, io uint64
	for i := len(s.samples) - 1; i >= 0; i-- {
		if s.samples[i].At.Before(cutoff) {
			break
		}
		net += s.samples[i].BytesIn + s.samples[i].BytesOut
		io += s.samples[i].IORead + s.samples[i].IOWrite
	}
	if net > 0 {
		return net
	}
	return io
}

// readProcIO returns (rchar, wchar, ok) from /proc/PID/io. rchar/
// wchar are cumulative bytes the kernel observed across all read()/
// write() syscalls — includes network and file IO. Cheap (one open,
// few hundred bytes read).
func readProcIO(pid uint32) (rd, wr uint64, ok bool) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/io", pid))
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		k, v, kvOk := strings.Cut(line, ": ")
		if !kvOk {
			continue
		}
		switch k {
		case "rchar":
			rd, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		case "wchar":
			wr, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
		}
	}
	return rd, wr, true
}
