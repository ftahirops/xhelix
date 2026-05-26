package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/incidentgraph"
)

// newIncidentsCmd builds the `xhelixctl incidents` subtree:
//
//	xhelixctl incidents list   [--all] [--limit N] [--json]
//	xhelixctl incidents show   <id> [--json]
//	xhelixctl incidents close  <id> --reason <text>
//
// All commands read the on-disk incident store directly
// (/var/lib/xhelix/incidents.db). `close` mutates the audit table —
// the daemon is NOT notified live in v1; restart/sweep reconciles.
func newIncidentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "incidents",
		Short: "Inspect and manage assembled incidents (Phase D.1)",
	}
	cmd.PersistentFlags().String("db", "/var/lib/xhelix/incidents.db", "path to incident store")
	cmd.AddCommand(newIncidentsListCmd())
	cmd.AddCommand(newIncidentsShowCmd())
	cmd.AddCommand(newIncidentsCloseCmd())
	return cmd
}

func newIncidentsListCmd() *cobra.Command {
	var (
		showAll  bool
		limit    int
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List incidents (open by default; --all includes closed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath, _ := cmd.Flags().GetString("db")
			s, err := openStoreRO(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()
			var incs []incidentgraph.Incident
			if showAll {
				incs, err = s.LoadAll(limit)
			} else {
				incs, err = s.LoadOpen()
			}
			if err != nil {
				return err
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(incs)
			}
			return printIncidentTable(os.Stdout, incs)
		},
	}
	cmd.Flags().BoolVar(&showAll, "all", false, "include closed incidents")
	cmd.Flags().IntVar(&limit, "limit", 100, "max rows when --all is set")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON instead of a table")
	return cmd
}

func newIncidentsShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show full detail for one incident, including evidence ring",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dbPath, _ := cmd.Flags().GetString("db")
			s, err := openStoreRO(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()
			inc, ok, err := s.Get(args[0])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no incident with id %q", args[0])
			}
			if asJSON {
				return json.NewEncoder(os.Stdout).Encode(inc)
			}
			printIncidentDetail(os.Stdout, inc)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON instead of formatted output")
	return cmd
}

func newIncidentsCloseCmd() *cobra.Command {
	var reason string
	cmd := &cobra.Command{
		Use:   "close <id>",
		Short: "Mark an incident closed in the audit store",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return fmt.Errorf("--reason is required")
			}
			dbPath, _ := cmd.Flags().GetString("db")
			s, err := incidentgraph.OpenStore(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()
			ok, err := s.MarkClosed(args[0], reason, time.Now())
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("no open incident with id %q", args[0])
			}
			fmt.Fprintf(os.Stdout, "closed: %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "operator-supplied close reason (required)")
	return cmd
}

func openStoreRO(path string) (*incidentgraph.Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("incident store %q: %w", path, err)
	}
	return incidentgraph.OpenStore(path)
}

func printIncidentTable(w *os.File, incs []incidentgraph.Incident) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tINTENT\tCONF\tEVIDENCE\tAGE\tSUMMARY")
	now := time.Now()
	for _, inc := range incs {
		age := now.Sub(inc.UpdatedAt).Truncate(time.Second)
		summary := inc.Summary
		if len(summary) > 60 {
			summary = summary[:57] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.2f\t%d\t%s\t%s\n",
			inc.ID, inc.Severity, inc.Intent, inc.Confidence,
			len(inc.Evidence), age, summary)
	}
	return tw.Flush()
}

func printIncidentDetail(w *os.File, inc incidentgraph.Incident) {
	fmt.Fprintf(w, "incident:   %s\n", inc.ID)
	fmt.Fprintf(w, "severity:   %s\n", inc.Severity)
	fmt.Fprintf(w, "intent:     %s\n", inc.Intent)
	fmt.Fprintf(w, "confidence: %.2f\n", inc.Confidence)
	fmt.Fprintf(w, "started:    %s\n", inc.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "updated:    %s\n", inc.UpdatedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "summary:    %s\n", inc.Summary)
	if len(inc.SourceIDs) > 0 {
		fmt.Fprintf(w, "sources:    %v\n", inc.SourceIDs)
	}
	if len(inc.LineageIDs) > 0 {
		fmt.Fprintf(w, "lineages:   %v\n", inc.LineageIDs)
	}
	if len(inc.TTPTags) > 0 {
		fmt.Fprintf(w, "ttp:        %v\n", inc.TTPTags)
	}
	if len(inc.MitreIDs) > 0 {
		fmt.Fprintf(w, "mitre:      %v\n", inc.MitreIDs)
	}
	fmt.Fprintf(w, "\nevidence (%d entries):\n", len(inc.Evidence))
	for i, e := range inc.Evidence {
		fmt.Fprintf(w, "  [%2d] %s  %-18s %s\n",
			i, e.At.Format("15:04:05"), e.Kind, e.Summary)
	}
}
