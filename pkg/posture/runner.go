// Package posture provides a scheduled runner that executes posture
// scans and emits findings as model.Events.
package posture

import (
	"context"
	"log/slog"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Runner executes scans on an interval and projects findings to events.
type Runner struct {
	interval time.Duration
	log      *slog.Logger
	host     string
	stateDir string

	sshBaseline map[string]map[string]struct{}
}

// NewRunner creates a posture runner.
func NewRunner(interval time.Duration, host, stateDir string, log *slog.Logger) *Runner {
	if interval == 0 {
		interval = 1 * time.Hour
	}
	return &Runner{
		interval:    interval,
		log:         log,
		host:        host,
		stateDir:    stateDir,
		sshBaseline: map[string]map[string]struct{}{},
	}
}

// Start begins the scheduled scan loop. Blocks until ctx is cancelled.
func (r *Runner) Start(ctx context.Context, out chan<- model.Event) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Immediate first scan
	r.run(ctx, out)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.run(ctx, out)
		}
	}
}

func (r *Runner) run(ctx context.Context, out chan<- model.Event) {
	findings := r.scanAll()
	for _, f := range findings {
		ev := findingToEvent(f, r.host)
		select {
		case out <- ev:
		case <-ctx.Done():
			return
		}
	}
	if len(findings) > 0 {
		r.log.Info("posture scan complete", "findings", len(findings))
	}
}

func (r *Runner) scanAll() []Finding {
	var all []Finding

	if f, err := LDPreload(""); err == nil {
		all = append(all, f...)
	}

	paths := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"}
	if f, err := SUIDDrift(paths); err == nil {
		all = append(all, f...)
	}

	homes := []string{"/root"}
	if f, err := AuthorizedKeysDiff(homes, r.sshBaseline); err == nil {
		all = append(all, f...)
	}

	webRoots := []string{"/var/www", "/usr/share/nginx/html", "/srv"}
	if f, err := WebshellHeuristic(webRoots); err == nil {
		all = append(all, f...)
	}

	return all
}

func findingToEvent(f Finding, host string) model.Event {
	sev := model.SeverityNotice
	switch f.Severity {
	case "warn":
		sev = model.SeverityWarn
	case "high":
		sev = model.SeverityHigh
	case "critical":
		sev = model.SeverityCritical
	}
	ev := model.NewEvent("posture."+f.Scan, sev)
	ev.Time = time.Now().UTC()
	ev.Host = host
	ev.Tags["scan"] = f.Scan
	ev.Tags["path"] = f.Path
	ev.Tags["reason"] = f.Scan + " finding: " + f.Path
	for k, v := range f.Tags {
		ev.Tags[k] = v
	}
	return ev
}
