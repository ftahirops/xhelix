package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/appident"
	"gopkg.in/yaml.v3"
)

// newAppidentCmd is the operator surface for /etc/xhelix/apps.d declarations.
// The two subcommands cover the lifecycle:
//
//	discover - scan /proc and emit YAML decl candidates for what's running
//	list     - list currently-loaded decls
func newAppidentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "appident",
		Aliases: []string{"apps", "appid"},
		Short:   "Manage operator app-identification declarations (/etc/xhelix/apps.d/*.yaml)",
	}
	cmd.AddCommand(newAppidentDiscoverCmd())
	cmd.AddCommand(newAppidentListCmd())
	return cmd
}

// newAppidentDiscoverCmd walks /proc to find running processes that
// aren't recognized by current decls + heuristics, and emits candidate
// YAML decls for the operator to review + drop into /etc/xhelix/apps.d/.
//
// This is the practical alternative to fleet curation (T17/T20-T22):
// operators run this once after install, review the suggestions,
// commit them. Honest scope — host-local discovery, not multi-host
// fleet consensus.
func newAppidentDiscoverCmd() *cobra.Command {
	var (
		vendorDir string
		opDir     string
		minSeen   int
		outDir    string
		write     bool
	)
	cmd := &cobra.Command{
		Use:   "discover",
		Short: "Scan /proc and emit candidate app-decl YAMLs for unidentified processes",
		Long: `Walks /proc/<pid> for currently-running processes, runs each through
the loaded decl + heuristic stack, and emits a YAML candidate for any
process that wasn't matched. Operators review the candidates and commit
the ones that make sense.

Typical workflow:
  xhelixctl appident discover           # print to stdout
  xhelixctl appident discover --write   # write to /etc/xhelix/apps.d/discovered.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load existing decls so already-matched processes are skipped.
			vendor, _ := appident.LoadDecls(vendorDir)
			op, _ := appident.LoadDecls(opDir)
			decls := append(vendor, op...)
			ident := appident.New(decls)

			candidates, err := scanProc(ident, minSeen)
			if err != nil {
				return err
			}

			if len(candidates) == 0 {
				fmt.Fprintln(os.Stdout, "no unidentified processes found")
				return nil
			}

			out := emitYAMLCandidates(candidates)

			if !write {
				fmt.Fprint(os.Stdout, out)
				fmt.Fprintf(os.Stderr,
					"\n%d candidate(s). Re-run with --write to save to %s\n",
					len(candidates), filepath.Join(outDir, "discovered.yaml"))
				return nil
			}

			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			dst := filepath.Join(outDir, "discovered.yaml")
			if err := os.WriteFile(dst, []byte(out), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "wrote %d candidate(s) to %s\n", len(candidates), dst)
			fmt.Fprintln(os.Stdout, "review the file, then restart xhelix to apply")
			return nil
		},
	}
	cmd.Flags().StringVar(&vendorDir, "vendor", "/usr/share/xhelix/apps.d", "vendor decl dir")
	cmd.Flags().StringVar(&opDir, "operator", "/etc/xhelix/apps.d", "operator decl dir")
	cmd.Flags().IntVar(&minSeen, "min-seen", 1, "minimum process count to emit a candidate")
	cmd.Flags().StringVar(&outDir, "out", "/etc/xhelix/apps.d", "directory for discovered.yaml")
	cmd.Flags().BoolVar(&write, "write", false, "write to disk instead of stdout")
	return cmd
}

func newAppidentListCmd() *cobra.Command {
	var (
		vendorDir string
		opDir     string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List loaded app declarations (vendor + operator)",
		RunE: func(cmd *cobra.Command, args []string) error {
			v, vErrs := appident.LoadDecls(vendorDir)
			for _, e := range vErrs {
				fmt.Fprintf(os.Stderr, "vendor: %v\n", e)
			}
			o, oErrs := appident.LoadDecls(opDir)
			for _, e := range oErrs {
				fmt.Fprintf(os.Stderr, "operator: %v\n", e)
			}
			fmt.Fprintf(os.Stdout, "VENDOR (%s):\n", vendorDir)
			for _, d := range v {
				fmt.Fprintf(os.Stdout, "  %-20s kind=%s\n", d.App, d.Kind)
			}
			fmt.Fprintf(os.Stdout, "\nOPERATOR (%s):\n", opDir)
			for _, d := range o {
				fmt.Fprintf(os.Stdout, "  %-20s kind=%s\n", d.App, d.Kind)
			}
			fmt.Fprintf(os.Stdout, "\nTotal: vendor=%d operator=%d\n", len(v), len(o))
			return nil
		},
	}
	cmd.Flags().StringVar(&vendorDir, "vendor", "/usr/share/xhelix/apps.d", "vendor decl dir")
	cmd.Flags().StringVar(&opDir, "operator", "/etc/xhelix/apps.d", "operator decl dir")
	return cmd
}

// candidate is one unmatched basename observed in /proc.
type candidate struct {
	Comm     string
	ExePath  string
	ArgvHint string
	Cgroup   string
	Count    int
}

// scanProc walks /proc/<pid> and returns candidates the loaded decls
// did not match (or matched only via fallback heuristic).
func scanProc(ident *appident.Identifier, minSeen int) ([]candidate, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	byKey := map[string]*candidate{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// PID dirs only.
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		exe, _ := os.Readlink("/proc/" + pid + "/exe")
		if exe == "" {
			continue
		}
		comm := readProcFile("/proc/" + pid + "/comm")
		argv := readProcArgv("/proc/" + pid + "/cmdline")
		cgroup := readProcCgroup("/proc/" + pid + "/cgroup")

		sig := appident.Signals{
			ExePath:    exe,
			ArgvJoined: argv,
			CgroupPath: cgroup,
			Comm:       comm,
		}
		a := ident.Identify(sig)
		// Anything matched by a declaration (Source starts with
		// "decl:") is already covered. Heuristic matches are also
		// "covered" — operators get to focus only on truly unknown.
		if !a.Empty() && !strings.HasPrefix(a.Source, "heuristic:exe_basename") {
			continue
		}
		key := filepath.Base(exe) + "|" + comm
		c := byKey[key]
		if c == nil {
			c = &candidate{
				Comm:     comm,
				ExePath:  exe,
				ArgvHint: truncateLine(argv, 80),
				Cgroup:   cgroup,
			}
			byKey[key] = c
		}
		c.Count++
	}
	out := make([]candidate, 0, len(byKey))
	for _, c := range byKey {
		if c.Count >= minSeen {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Comm < out[j].Comm
	})
	return out, nil
}

// emitYAMLCandidates renders a multi-document YAML file the operator
// can edit + drop into /etc/xhelix/apps.d/.
func emitYAMLCandidates(cs []candidate) string {
	var b strings.Builder
	b.WriteString("# Discovered app candidates — review + commit.\n")
	b.WriteString("# Edit `app:` to a meaningful name. Tighten `match:` as needed.\n")
	for _, c := range cs {
		decl := appident.Declaration{
			App:  candidateAppName(c),
			Kind: appident.KindBackground,
			Match: appident.MatchRules{
				ExePath: []string{c.ExePath},
			},
		}
		buf, _ := yaml.Marshal(decl)
		fmt.Fprintf(&b, "---\n# comm=%s count=%d argv=%s\n%s",
			c.Comm, c.Count, c.ArgvHint, string(buf))
	}
	return b.String()
}

// candidateAppName produces a default app name for a candidate.
func candidateAppName(c candidate) string {
	base := filepath.Base(c.ExePath)
	if base == "" {
		base = c.Comm
	}
	// Strip version suffix.
	for _, fam := range []string{"python", "ruby", "node", "perl", "php"} {
		if strings.HasPrefix(base, fam) {
			return fam
		}
	}
	return base
}

func readProcFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimRight(string(b), "\n")
}

func readProcArgv(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " ")
}

func readProcCgroup(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// First line, last colon-segment is the path.
	first := strings.SplitN(string(b), "\n", 2)[0]
	if idx := strings.LastIndex(first, ":"); idx >= 0 {
		return first[idx+1:]
	}
	return first
}

// truncateLine clips s to n bytes plus ellipsis when over.
func truncateLine(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
