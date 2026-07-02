// xhelixctl recorder — read-only CLI for the SP-4 exemplar recorder.
//
//	xhelixctl recorder coverage          aggregate coverage across all apps
//	xhelixctl recorder shapes <app>      list shapes + exemplar counts for one app
package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/recorder"

	_ "modernc.org/sqlite"
)

func newRecorderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recorder",
		Short: "Inspect the SP-4 exemplar recorder",
	}
	cmd.AddCommand(newRecorderCoverageCmd())
	cmd.AddCommand(newRecorderShapesCmd())
	cmd.AddCommand(newRecorderWindowCmd())
	return cmd
}

// newRecorderWindowCmd controls the learning window on a running daemon.
//
//	xhelixctl recorder window            show current state
//	xhelixctl recorder window --open     start learning (mark events learnable)
//	xhelixctl recorder window --close    stop learning
func newRecorderWindowCmd() *cobra.Command {
	var sock string
	var open, close bool
	cmd := &cobra.Command{
		Use:   "window",
		Short: "Open/close the behavioral learning window on the running daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			if open && close {
				return fmt.Errorf("--open and --close are mutually exclusive")
			}
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var req map[string]any
			if open || close {
				req = map[string]any{"open": open} // close → open:false
			}
			var resp struct {
				Open    bool   `json:"open"`
				Control string `json:"control"`
			}
			if err := c.Call("recorder.window", req, &resp); err != nil {
				return fmt.Errorf("recorder.window: %w", err)
			}
			state := "CLOSED"
			if resp.Open {
				state = "OPEN"
			}
			fmt.Fprintf(os.Stdout, "learning window: %s (control: %s)\n", state, resp.Control)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket")
	cmd.Flags().BoolVar(&open, "open", false, "open the learning window (start recording)")
	cmd.Flags().BoolVar(&close, "close", false, "close the learning window (stop recording)")
	return cmd
}

func newRecorderCoverageCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show aggregate coverage across all recorded apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecorderCoverage(dbPath, os.Stdout)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/xhelix/recorder.db", "path to recorder.db")
	return cmd
}

func newRecorderShapesCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "shapes <app>",
		Short: "List shapes and exemplar counts for one app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRecorderShapes(dbPath, args[0], os.Stdout)
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/xhelix/recorder.db", "path to recorder.db")
	return cmd
}

func runRecorderCoverage(dbPath string, w io.Writer) error {
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("recorder db not found at %s — has the recorder ever run?", dbPath)
	}
	st, err := openRecorderReadOnly(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	rows, err := st.AllShapes()
	if err != nil {
		return fmt.Errorf("allshapes: %w", err)
	}
	rep := recorder.Coverage(rows)
	_, err = fmt.Fprint(w, renderCoverage(rep))
	return err
}

func runRecorderShapes(dbPath, appID string, w io.Writer) error {
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("recorder db not found at %s — has the recorder ever run?", dbPath)
	}
	st, err := openRecorderReadOnly(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	rows, err := st.Shapes(appID)
	if err != nil {
		return fmt.Errorf("shapes: %w", err)
	}
	if len(rows) == 0 {
		fmt.Fprintf(w, "No shapes recorded for app %q.\n", appID)
		return nil
	}
	fmt.Fprintf(w, "Shapes for %s (%d total):\n", appID, len(rows))
	for _, r := range rows {
		exs, exErr := st.Exemplars(appID, r.ShapeHash)
		hashPrefix := r.ShapeHash[:min(8, len(r.ShapeHash))]
		if exErr != nil {
			fmt.Fprintf(w, "  %s  count=%-6d exemplars=(unavailable: %v) phase=%-12s last=%s\n",
				hashPrefix, r.Count, exErr, r.Phase,
				r.LastSeen.Format("2006-01-02T15:04:05Z"))
		} else {
			fmt.Fprintf(w, "  %s  count=%-6d exemplars=%-3d phase=%-12s last=%s\n",
				hashPrefix, r.Count, len(exs), r.Phase,
				r.LastSeen.Format("2006-01-02T15:04:05Z"))
		}
	}
	return nil
}

// renderCoverage formats a CoverageReport for terminal display. Pure — tested.
func renderCoverage(rep recorder.CoverageReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Recorder coverage: %d apps, %d shapes, %d total observations\n\n",
		rep.Apps, rep.Shapes, rep.TotalObservations)
	if rep.Apps == 0 {
		fmt.Fprintln(&sb, "  (no data — recorder may be disabled or empty)")
		return sb.String()
	}

	// Sort apps for deterministic output.
	apps := make([]string, 0, len(rep.ByApp))
	for a := range rep.ByApp {
		apps = append(apps, a)
	}
	sort.Strings(apps)

	for _, app := range apps {
		ac := rep.ByApp[app]
		fmt.Fprintf(&sb, "  %-30s shapes=%-4d observations=%-8d newest=%s\n",
			app, ac.Shapes, ac.Observations,
			ac.NewestShape.Format("2006-01-02T15:04:05Z"))
	}
	return sb.String()
}

// openRecorderReadOnly opens the recorder SQLite DB read-only.
// Mirrors the pattern in cmd/xhelixctl/history.go.
func openRecorderReadOnly(path string) (*recorder.Store, error) {
	st, err := recorder.NewStore(recorder.Options{
		Path:              path,
		ExemplarsPerShape: 20,
		RetentionDays:     30,
	})
	if err != nil {
		return nil, fmt.Errorf("open recorder db: %w", err)
	}
	return st, nil
}
