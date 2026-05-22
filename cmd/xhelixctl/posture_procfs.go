package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	procfsposture "github.com/xhelix/xhelix/pkg/posture/procfs"
)

func newProcfsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "procfs",
		Short: "Inspect and harden /proc against same-UID credential scraping",
		Long: `Generates the sysctl drop-in (Yama ptrace_scope=2, fs.suid_dumpable=0,
link-protection) and per-service systemd drop-ins (ProtectProc=invisible,
ProcSubset=pid, NoNewPrivileges=yes) for declared consumer services.

Generation is read-only. Apply writes to /etc and reloads sysctl/systemd
— the daemon never does this automatically.`,
	}
	cmd.AddCommand(newProcfsStatusCmd())
	cmd.AddCommand(newProcfsGenerateCmd())
	cmd.AddCommand(newProcfsApplyCmd())
	return cmd
}

func newProcfsStatusCmd() *cobra.Command {
	var units []string
	c := &cobra.Command{
		Use:   "status",
		Short: "Report current host procfs-hardening state",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := procfsposture.ReadStatus(units)
			fmt.Println("procfs hardening — live kernel + filesystem state")
			fmt.Println()
			fmt.Printf("  kernel.yama.ptrace_scope    = %d  (want 2)\n", st.PtraceScope)
			fmt.Printf("  fs.suid_dumpable            = %d  (want 0)\n", st.SuidDumpable)
			fmt.Printf("  fs.protected_hardlinks      = %d  (want 1)\n", st.HardlinksProt)
			fmt.Printf("  fs.protected_symlinks       = %d  (want 1)\n", st.SymlinksProt)
			fmt.Println()
			if st.SysctlInstalled {
				fmt.Printf("  sysctl drop-in: INSTALLED at %s\n", procfsposture.SysctlPath)
			} else {
				fmt.Printf("  sysctl drop-in: NOT INSTALLED (expected %s)\n", procfsposture.SysctlPath)
			}
			fmt.Println()
			if len(st.UnitsWithDropIn)+len(st.UnitsMissing) == 0 {
				fmt.Println("  systemd drop-ins: no target units found on this host")
			} else {
				fmt.Printf("  systemd drop-ins:  %d installed, %d missing\n",
					len(st.UnitsWithDropIn), len(st.UnitsMissing))
				for _, u := range st.UnitsWithDropIn {
					fmt.Printf("    + %s\n", u)
				}
				for _, u := range st.UnitsMissing {
					fmt.Printf("    - %s  (target unit present, drop-in missing)\n", u)
				}
			}
			fmt.Println()
			fmt.Println("Summary:", st.Summary())
			return nil
		},
	}
	c.Flags().StringSliceVar(&units, "unit", nil,
		"systemd unit names to check (default: built-in target list)")
	return c
}

func newProcfsGenerateCmd() *cobra.Command {
	var (
		outDir string
		units  []string
	)
	c := &cobra.Command{
		Use:   "generate",
		Short: "Generate sysctl + systemd drop-ins (does not write to /etc)",
		Long: `Writes generated drop-ins to a staging directory (default
/tmp/xhelix-procfs-stage) or stdout when --out=-. Use 'apply' to
install them under /etc and reload services.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if units == nil {
				units = procfsposture.DefaultTargets()
			}
			files := buildFileMap(units)
			if outDir == "-" {
				for path, body := range files {
					fmt.Printf("# === %s ===\n%s\n", path, body)
				}
				return nil
			}
			if outDir == "" {
				outDir = "/tmp/xhelix-procfs-stage"
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			for path, body := range files {
				dst := filepath.Join(outDir, strings.ReplaceAll(path, "/", "_"))
				if err := os.WriteFile(dst, []byte(body), 0o644); err != nil {
					return err
				}
				fmt.Printf("wrote %s\n  (final destination: %s)\n", dst, path)
			}
			fmt.Println()
			fmt.Println("Inspect, then run 'xhelixctl posture procfs apply --confirm' to install.")
			return nil
		},
	}
	c.Flags().StringVar(&outDir, "out", "",
		"staging directory (default /tmp/xhelix-procfs-stage). Use - for stdout.")
	c.Flags().StringSliceVar(&units, "unit", nil,
		"systemd unit names (default: built-in target list)")
	return c
}

func newProcfsApplyCmd() *cobra.Command {
	var (
		confirm     bool
		skipReload  bool
		units       []string
		yesToAll    bool
	)
	c := &cobra.Command{
		Use:   "apply",
		Short: "Install generated drop-ins under /etc and reload (operator-gated)",
		Long: `Writes the sysctl drop-in and per-service systemd drop-ins to /etc.
This affects all xhelix-managed consumer services. Reversible by
removing the drop-in files and reloading.

REQUIRES --confirm. Prompts again before each file unless --yes.

Reloads:
  - 'sysctl --system' after writing the sysctl drop-in
  - 'systemctl daemon-reload' after writing systemd drop-ins
  - Affected units are NOT restarted automatically; restart them
    yourself when ready ('systemctl restart <unit>').`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirm {
				return fmt.Errorf("--confirm required (this writes to /etc)")
			}
			if os.Geteuid() != 0 {
				return fmt.Errorf("apply requires root (writes to /etc/sysctl.d and /etc/systemd/system)")
			}
			if units == nil {
				units = procfsposture.DefaultTargets()
			}
			files := buildFileMap(units)
			// Stable order so prompts and logs are deterministic.
			var paths []string
			for p := range files {
				paths = append(paths, p)
			}
			sortStrings(paths)

			reader := bufio.NewReader(os.Stdin)
			for _, p := range paths {
				body := files[p]
				if !yesToAll {
					fmt.Printf("About to write %s (%d bytes). [y/N/a=yes-to-all] ", p, len(body))
					line, _ := reader.ReadString('\n')
					ans := strings.ToLower(strings.TrimSpace(line))
					switch ans {
					case "a", "yes-to-all":
						yesToAll = true
					case "y", "yes":
						// proceed
					default:
						fmt.Printf("  skipped %s\n", p)
						continue
					}
				}
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					return fmt.Errorf("mkdir %s: %w", filepath.Dir(p), err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					return fmt.Errorf("write %s: %w", p, err)
				}
				fmt.Printf("  wrote %s\n", p)
			}
			if skipReload {
				fmt.Println()
				fmt.Println("Skipping sysctl + systemd reload (--skip-reload).")
				return nil
			}
			fmt.Println()
			fmt.Println("Running 'sysctl --system'...")
			if out, err := exec.Command("sysctl", "--system").CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "  sysctl --system failed: %v\n%s\n", err, out)
			}
			fmt.Println("Running 'systemctl daemon-reload'...")
			if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
				fmt.Fprintf(os.Stderr, "  daemon-reload failed: %v\n%s\n", err, out)
			}
			fmt.Println()
			fmt.Println("Done. Restart affected services to pick up the drop-ins:")
			for _, u := range units {
				fmt.Printf("  systemctl restart %s\n", u)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&confirm, "confirm", false, "required: confirms /etc writes")
	c.Flags().BoolVar(&yesToAll, "yes", false, "skip per-file confirmation prompts")
	c.Flags().BoolVar(&skipReload, "skip-reload", false, "skip sysctl + systemctl daemon-reload after write")
	c.Flags().StringSliceVar(&units, "unit", nil,
		"systemd unit names (default: built-in target list)")
	return c
}

// buildFileMap returns destination-path → body for every file the
// procfs hardener would install.
func buildFileMap(units []string) map[string]string {
	out := map[string]string{
		procfsposture.SysctlPath: procfsposture.SysctlContent(),
	}
	for _, u := range units {
		out[procfsposture.DropInPath(u)] = procfsposture.DropInContent(u)
	}
	return out
}

func sortStrings(s []string) {
	// Small dependency-free sort; the slice is tiny (≤20 entries).
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
