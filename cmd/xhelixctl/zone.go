package main

import (
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/trustzone"
)

// newZoneCmd surfaces the Week 5 trust-zone manager for operators.
// Implementation hits the YAML file directly (default
// /etc/xhelix/trustzones.yaml) — the daemon watcher reloads on a
// 30s tick, so changes apply within half a minute. This keeps the
// CLI usable when the daemon isn't running (initial host setup,
// recovery) without standing up a separate RPC surface.
func newZoneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zone",
		Short: "Trust zones — operator-assigned per-subject labels",
		Long: `Trust zones bind a subject identity (uid / cgroup unit /
cgroup class / process comm) to a trust label. The egress decision
engine consults the zone when no per-binary policy applies.

Labels:
  trusted     no extra restriction (default)
  restricted  allowed to reach known-safe dest classes; everything else verifies
  untrusted   only private/loopback; everything external denied
  tor_only    only Tor SOCKS loopback ports; everything else must route via Tor

Edits land in /etc/xhelix/trustzones.yaml and the running daemon
reloads within 30s.`,
	}
	cmd.AddCommand(newZoneListCmd())
	cmd.AddCommand(newZoneSetCmd())
	cmd.AddCommand(newZoneRemoveCmd())
	cmd.AddCommand(newZoneDefaultCmd())
	cmd.AddCommand(newZoneReloadCmd())
	return cmd
}

const defaultZonePath = "/etc/xhelix/trustzones.yaml"

func openZoneMgr(path string) (*trustzone.Manager, error) {
	m := trustzone.New(path, trustzone.LabelTrusted)
	if _, err := m.Reload(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

func newZoneListCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show default label + all assignments",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := openZoneMgr(path)
			if err != nil {
				return err
			}
			fmt.Printf("default_label: %s\n", m.Default())
			all := m.All()
			if len(all) == 0 {
				fmt.Println("(no assignments)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "IDX\tSELECTOR\tVALUE\tLABEL\tCOMMENT")
			for i, a := range all {
				sel, val := assignmentDescribe(a)
				fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\n", i, sel, val, a.Label, a.Comment)
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultZonePath, "trust-zone YAML file")
	return cmd
}

func assignmentDescribe(a trustzone.Assignment) (string, string) {
	if a.UID != nil {
		return "uid", strconv.FormatUint(uint64(*a.UID), 10)
	}
	if a.CGroupUnit != "" {
		return "cgroup_unit", a.CGroupUnit
	}
	if a.CGroupClass != "" {
		return "cgroup_class", a.CGroupClass
	}
	if a.Comm != "" {
		return "comm", a.Comm
	}
	return "(none)", ""
}

func newZoneSetCmd() *cobra.Command {
	var path string
	var uid int
	var unit, class, comm, label, comment string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Add a zone assignment (use exactly one selector flag)",
		Example: `  xhelixctl zone set --uid 1001 --label untrusted
  xhelixctl zone set --cgroup-unit user@1000.service --label restricted
  xhelixctl zone set --comm tor-browser --label tor_only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if label == "" {
				return fmt.Errorf("--label required")
			}
			selectors := 0
			a := trustzone.Assignment{Label: trustzone.Label(label), Comment: comment}
			if uid >= 0 {
				u := uint32(uid)
				a.UID = &u
				selectors++
			}
			if unit != "" {
				a.CGroupUnit = unit
				selectors++
			}
			if class != "" {
				a.CGroupClass = class
				selectors++
			}
			if comm != "" {
				a.Comm = comm
				selectors++
			}
			if selectors == 0 {
				return fmt.Errorf("one of --uid / --cgroup-unit / --cgroup-class / --comm required")
			}
			if selectors > 1 {
				return fmt.Errorf("only one selector flag at a time (got %d)", selectors)
			}
			m, err := openZoneMgr(path)
			if err != nil {
				return err
			}
			if err := m.Add(a); err != nil {
				return err
			}
			fmt.Printf("added: %s=%s label=%s\n", firstNonEmptyZone(a), assignmentValue(a), a.Label)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultZonePath, "trust-zone YAML file")
	cmd.Flags().IntVar(&uid, "uid", -1, "match by UID (-1 = unset)")
	cmd.Flags().StringVar(&unit, "cgroup-unit", "", "match by systemd unit name")
	cmd.Flags().StringVar(&class, "cgroup-class", "", "match by cgroup class (user/system/container)")
	cmd.Flags().StringVar(&comm, "comm", "", "match by process comm")
	cmd.Flags().StringVar(&label, "label", "", "zone label (trusted/restricted/untrusted/tor_only)")
	cmd.Flags().StringVar(&comment, "comment", "", "optional operator note")
	return cmd
}

func firstNonEmptyZone(a trustzone.Assignment) string {
	s, _ := assignmentDescribe(a)
	return s
}

func assignmentValue(a trustzone.Assignment) string {
	_, v := assignmentDescribe(a)
	return v
}

func newZoneRemoveCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "remove <index>",
		Short: "Remove an assignment by index (see `zone list`)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			idx, err := strconv.Atoi(args[0])
			if err != nil {
				return fmt.Errorf("invalid index %q: %w", args[0], err)
			}
			m, err := openZoneMgr(path)
			if err != nil {
				return err
			}
			if err := m.Remove(idx); err != nil {
				return err
			}
			fmt.Printf("removed assignment %d\n", idx)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultZonePath, "trust-zone YAML file")
	return cmd
}

func newZoneDefaultCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "default <label>",
		Short: "Set the default label (applied when no assignment matches)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := openZoneMgr(path)
			if err != nil {
				return err
			}
			if err := m.SetDefault(trustzone.Label(args[0])); err != nil {
				return err
			}
			fmt.Printf("default_label set to %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultZonePath, "trust-zone YAML file")
	return cmd
}

func newZoneReloadCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Force-reload the YAML (mostly a sanity check; daemon polls every 30s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := openZoneMgr(path)
			if err != nil {
				return err
			}
			n, err := m.Reload()
			if err != nil {
				return err
			}
			fmt.Printf("reloaded %d assignments from %s\n", n, path)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", defaultZonePath, "trust-zone YAML file")
	return cmd
}
