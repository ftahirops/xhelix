package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/lineage"
	"github.com/xhelix/xhelix/pkg/source"
)

const defaultSourceDBPath = "/var/lib/xhelix/source.db"

// newSourceCmd is the operator surface for v2 SourceAnchors.
//
// The CLI talks to the SQLite store directly (not via localapi) so it
// works even when the daemon is stopped, and shows what was persisted
// vs in-memory hot state. T01 / Phase A1.
func newSourceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "source",
		Short: "Inspect v2 SourceAnchors (sshd / pam / sudo / cron / systemd ingress)",
		Long: `Every authenticated or scheduled entry point on this host
mints a SourceAnchor. Anchors persist to /var/lib/xhelix/source.db.

  list              — recent anchors, newest first
  show <id>         — full detail for one anchor
  children <id>     — anchors that pivoted from this one (e.g. sudo from SSH)
  count             — total anchors in store`,
	}
	cmd.AddCommand(newSourceListCmd())
	cmd.AddCommand(newSourceShowCmd())
	cmd.AddCommand(newSourceChildrenCmd())
	cmd.AddCommand(newSourceCountCmd())
	return cmd
}

func newSourceListCmd() *cobra.Command {
	var (
		limit  int
		kind   string
		dbPath string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recent SourceAnchors (newest first)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openSourceStore(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			anchors, err := st.List(ctx, limit)
			if err != nil {
				return fmt.Errorf("list: %w", err)
			}
			if kind != "" {
				want := source.Kind(0)
				switch kind {
				case "ssh":
					want = source.KindSSH
				case "pam":
					want = source.KindPAM
				case "sudo":
					want = source.KindSudo
				case "cron":
					want = source.KindCron
				case "systemd":
					want = source.KindSystemd
				default:
					return fmt.Errorf("unknown --kind %q (want ssh|pam|sudo|cron|systemd)", kind)
				}
				filtered := anchors[:0]
				for _, a := range anchors {
					if a.Kind == want {
						filtered = append(filtered, a)
					}
				}
				anchors = filtered
			}
			printAnchorTable(os.Stdout, anchors)
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "max anchors to return")
	cmd.Flags().StringVar(&kind, "kind", "", "filter by kind: ssh|pam|sudo|cron|systemd")
	cmd.Flags().StringVar(&dbPath, "db", defaultSourceDBPath, "source.db path")
	return cmd
}

func newSourceShowCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show full detail for one SourceAnchor",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseAnchorID(args[0])
			if err != nil {
				return err
			}
			st, err := openSourceStore(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			a, err := st.Get(ctx, id)
			if err != nil {
				return fmt.Errorf("show %d: %w", id, err)
			}
			printAnchorDetail(os.Stdout, a)

			// Walk parent chain upward (if any).
			if a.ParentAnchorID != 0 {
				fmt.Fprintln(os.Stdout, "")
				fmt.Fprintln(os.Stdout, "Parent chain:")
				cur := a.ParentAnchorID
				for cur != 0 {
					p, err := st.Get(ctx, cur)
					if err != nil {
						fmt.Fprintf(os.Stdout, "  <%d: %v>\n", cur, err)
						break
					}
					fmt.Fprintf(os.Stdout, "  %d  %s  %s  %s\n",
						p.ID, p.Kind, p.Actor, p.CreatedAt.Format(time.RFC3339))
					cur = p.ParentAnchorID
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", defaultSourceDBPath, "source.db path")
	return cmd
}

func newSourceChildrenCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "children <id>",
		Short: "List anchors that pivoted from this one (e.g. sudos from an SSH session)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := parseAnchorID(args[0])
			if err != nil {
				return err
			}
			st, err := openSourceStore(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			kids, err := st.Children(ctx, id)
			if err != nil {
				return fmt.Errorf("children %d: %w", id, err)
			}
			if len(kids) == 0 {
				fmt.Fprintf(os.Stdout, "(no children for anchor %d)\n", id)
				return nil
			}
			printAnchorTable(os.Stdout, kids)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", defaultSourceDBPath, "source.db path")
	return cmd
}

func newSourceCountCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "count",
		Short: "Print total number of SourceAnchors in the store",
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := openSourceStore(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			n, err := st.Count(ctx)
			if err != nil {
				return err
			}
			fmt.Printf("%d anchors\n", n)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", defaultSourceDBPath, "source.db path")
	return cmd
}

func openSourceStore(path string) (*source.Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("source store %s: %w (daemon may not have run yet)", path, err)
	}
	return source.Open(path)
}

func parseAnchorID(s string) (lineage.LineageID, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid anchor id %q: %w", s, err)
	}
	return lineage.LineageID(n), nil
}

func printAnchorTable(w *os.File, anchors []source.Anchor) {
	if len(anchors) == 0 {
		fmt.Fprintln(w, "(no anchors)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tACTOR\tSRC_IP\tUNIT\tPARENT\tCREATED")
	for _, a := range anchors {
		parent := "-"
		if a.ParentAnchorID != 0 {
			parent = fmt.Sprintf("%d", uint64(a.ParentAnchorID))
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			uint64(a.ID), a.Kind, dashIfEmpty(a.Actor), dashIfEmpty(a.SourceIP),
			dashIfEmpty(a.Unit), parent,
			a.CreatedAt.Format(time.RFC3339),
		)
	}
	tw.Flush()
}

func printAnchorDetail(w *os.File, a source.Anchor) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "ID:\t%d\n", uint64(a.ID))
	fmt.Fprintf(tw, "Kind:\t%s\n", a.Kind)
	fmt.Fprintf(tw, "Parent:\t%d\n", uint64(a.ParentAnchorID))
	fmt.Fprintf(tw, "Created:\t%s\n", a.CreatedAt.Format(time.RFC3339Nano))
	fmt.Fprintf(tw, "Host:\t%s\n", dashIfEmpty(a.Host))
	fmt.Fprintf(tw, "Actor:\t%s\n", dashIfEmpty(a.Actor))
	fmt.Fprintf(tw, "UID:\t%d\n", a.UID)
	fmt.Fprintf(tw, "LoginUID:\t%d\n", a.LoginUID)
	fmt.Fprintf(tw, "SourceIP:\t%s\n", dashIfEmpty(a.SourceIP))
	fmt.Fprintf(tw, "SourcePort:\t%d\n", a.SourcePort)
	fmt.Fprintf(tw, "SSHKeyHash:\t%s\n", dashIfEmpty(a.SSHKeyHash))
	fmt.Fprintf(tw, "Unit:\t%s\n", dashIfEmpty(a.Unit))
	fmt.Fprintf(tw, "Detail:\t%s\n", dashIfEmpty(a.Detail))
	tw.Flush()
}

