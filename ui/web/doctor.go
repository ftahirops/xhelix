package web

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/doctor"
)

// DoctorRunner is invoked by the UI when the operator opens the
// Doctor page. The daemon supplies it via EnterpriseConfig.DoctorRunner;
// supplying nil disables the page.
type DoctorRunner func(ctx context.Context) doctor.Report

// doctorState caches the most recent run so refreshing the page
// doesn't re-scan every time. The operator triggers a new scan
// explicitly via ?refresh=1.
//
// `running` debounces concurrent scans: without it, two simultaneous
// requests that both see stale=true each launch their own ~3-second
// 60-check audit, doubling CPU. Concurrent ?refresh=1 calls all wait
// on the same in-flight scan instead.
type doctorState struct {
	mu       sync.Mutex
	report   *doctor.Report
	cachedAt time.Time
	running  bool
	wakeCh   chan struct{} // closed when the in-flight scan finishes
}

// doctor handler — registered as /ui/doctor when DoctorRunner is set.
func (p *enterprisePages) doctor(w http.ResponseWriter, r *http.Request) {
	if p.doctorRunner == nil {
		http.Error(w, "doctor not enabled (no runner configured)", http.StatusServiceUnavailable)
		return
	}
	wantRefresh := r.URL.Query().Get("refresh") == "1"

	p.doctorState.mu.Lock()
	rep := p.doctorState.report
	cached := p.doctorState.cachedAt
	stale := rep == nil || time.Since(cached) > 30*time.Minute

	if wantRefresh || stale {
		if p.doctorState.running {
			// A scan is already in flight; wait for it instead of
			// launching another. Snapshot the channel before unlocking
			// so we don't race with the runner closing+nilling it.
			ch := p.doctorState.wakeCh
			p.doctorState.mu.Unlock()
			if ch != nil {
				<-ch
			}
			p.doctorState.mu.Lock()
			rep = p.doctorState.report
			cached = p.doctorState.cachedAt
			p.doctorState.mu.Unlock()
		} else {
			p.doctorState.running = true
			p.doctorState.wakeCh = make(chan struct{})
			ch := p.doctorState.wakeCh
			p.doctorState.mu.Unlock()

			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			newRep := p.doctorRunner(ctx)
			cancel()

			p.doctorState.mu.Lock()
			p.doctorState.report = &newRep
			p.doctorState.cachedAt = time.Now()
			p.doctorState.running = false
			p.doctorState.wakeCh = nil
			rep = &newRep
			cached = p.doctorState.cachedAt
			p.doctorState.mu.Unlock()
			close(ch)
		}
	} else {
		p.doctorState.mu.Unlock()
	}

	// Format download formats out-of-band.
	switch r.URL.Query().Get("fmt") {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		_ = doctor.FormatJSON(w, *rep)
		return
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="xhelix-doctor.html"`)
		_ = doctor.FormatHTML(w, *rep)
		return
	}

	// Render the in-page report using the existing enterprise template.
	failed := rep.FailedFindings()
	data := map[string]any{
		"Title":     "Doctor",
		"Active":    "doctor",
		"Report":    rep,
		"Failed":    failed,
		"CachedAt":  cached,
		"AgeStr":    time.Since(cached).Round(time.Second).String(),
	}
	p.render(w, "doctor", data)
}
