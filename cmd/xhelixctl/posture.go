package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/autobaseline"
	"github.com/xhelix/xhelix/pkg/posture/host"
	"github.com/xhelix/xhelix/pkg/posture/modsig"
	"github.com/xhelix/xhelix/pkg/vendorcatalog"
	"github.com/xhelix/xhelix/sensors/lsmaudit"

	_ "modernc.org/sqlite"
)

const autobaselineDBPath = "/var/lib/xhelix/autobaseline.db"

func newPostureCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "posture",
		Short: "Inspect host security posture",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "lsm",
		Short: "Report active LSMs (AppArmor / SELinux / BPF LSM)",
		RunE: func(cmd *cobra.Command, args []string) error {
			st := lsmaudit.Detect()
			fmt.Println("Active LSMs:")
			for _, n := range st.Active {
				fmt.Printf("  - %s\n", n)
			}
			if st.HasAppArmor {
				fmt.Printf("AppArmor mode: %s\n", st.AppArmorMode)
			} else {
				fmt.Println("AppArmor: not present")
			}
			if st.HasSELinux {
				fmt.Printf("SELinux mode: %s\n", st.SELinuxMode)
			} else {
				fmt.Println("SELinux: not present")
			}
			if st.HasBPFLSM {
				fmt.Println("BPF LSM: enabled")
			} else {
				fmt.Println("BPF LSM: NOT ENABLED (xhelix LSM hooks will be degraded)")
			}
			fmt.Printf("\nSummary: %s\n", st.Summary())
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "host",
		Short: "Report host hardening posture (Phase G.5)",
		Long: `Inspects host-level security knobs and reports a posture score 0-100.

Read-only: never modifies host state. Each check returns
PASS / WARN / FAIL / UNKNOWN with operator-actionable remediation
for non-PASS rows.

Checks: ASLR, kptr_restrict, dmesg_restrict, yama.ptrace_scope,
unprivileged_bpf_disabled, unprivileged_userns_clone, fs.protected_*,
sysrq, lockdown, module.sig_enforce, secureboot, BPF-LSM active,
landlock available, /tmp tmpfs hardening.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print(host.Inspect().FormatText())
			return nil
		},
	})
	cmd.AddCommand(newVendorsCmd())
	cmd.AddCommand(newBaselineCmd())
	cmd.AddCommand(newProcfsCmd())
	cmd.AddCommand(newModsigCmd())
	return cmd
}

// newModsigCmd surfaces kernel-module-load defenses + non-root
// CAP_SYS_MODULE holders. Read-only — does not modify host state.
func newModsigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "modsig",
		Short: "Inspect kernel module-load defenses (BYOVD-equivalent posture)",
		Long: `Reports host-level defenses against malicious kernel module loads:

  - /sys/module/module/parameters/sig_enforce  (module signature enforcement)
  - /sys/kernel/security/lockdown               (kernel lockdown mode)
  - mokutil --sb-state                          (secure boot)
  - non-root processes holding CAP_SYS_MODULE   (privilege exposure)

xhelix DETECTS kernel module loads via eBPF (kprobe on init_module /
finit_module) but does not PREVENT them. Prevention lives in the
kernel — turning on the three flags above raises the BYOVD-class
attack cost substantially.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			st := modsig.Read()
			fmt.Print(modsig.FormatStatus(st))
			return nil
		},
	}
}

// newVendorsCmd surfaces what vendorcatalog.AutoDetect found on the
// host. Read-only — uses the live filesystem, not the daemon.
func newVendorsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "vendors",
		Short: "Show auto-detected hosting/control-panel stacks",
		RunE: func(cmd *cobra.Command, args []string) error {
			cat, _ := vendorcatalog.LoadDir("/usr/share/xhelix/vendors")
			dets := cat.AutoDetect()
			if len(dets) == 0 {
				fmt.Println("No known vendors detected on this host.")
				fmt.Println("xhelix runs with the baked-in runtime allowlist only.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "VENDOR\tMATCH\tBINARIES")
			for _, d := range dets {
				fmt.Fprintf(tw, "%s\t%s\t%d\n", d.Vendor, d.Reason, len(d.Binaries))
			}
			return tw.Flush()
		},
	}
}

func newBaselineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Inspect and control the autobaseline (observe/detect)",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "status",
		Short: "Print current mode, observation remaining, profile size",
		RunE: func(cmd *cobra.Command, args []string) error {
			return baselineStatus()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Dump the sealed (image, action, detail) profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			return baselineShow()
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "seal",
		Short: "Force-seal the observation window now (advance to detect mode)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return baselineSeal()
		},
	})
	return cmd
}

// baselineStatus opens the same DB the daemon writes to and reads
// the state table directly. Read-only, doesn't require the daemon
// to be stopped.
func baselineStatus() error {
	if _, err := os.Stat(autobaselineDBPath); os.IsNotExist(err) {
		fmt.Println("Autobaseline: not yet initialised (daemon hasn't started).")
		return nil
	}
	db, err := sql.Open("sqlite", autobaselineDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	var startedAt, sealedAt time.Time
	rows, err := db.Query(`SELECT key, value FROM state`)
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return err
		}
		t, perr := time.Parse(time.RFC3339Nano, v)
		if perr != nil {
			continue
		}
		switch k {
		case "start_at":
			startedAt = t
		case "sealed_at":
			sealedAt = t
		}
	}
	rows.Close()

	var binaries, behaviors int
	_ = db.QueryRow(`SELECT COUNT(DISTINCT image) FROM profile`).Scan(&binaries)
	_ = db.QueryRow(`SELECT COUNT(*) FROM profile`).Scan(&behaviors)

	mode := autobaseline.ModeObserve
	if !sealedAt.IsZero() {
		mode = autobaseline.ModeDetect
	}
	fmt.Printf("Mode:               %s\n", mode)
	fmt.Printf("Started:            %s\n", startedAt.Format(time.RFC3339))
	if !sealedAt.IsZero() {
		fmt.Printf("Sealed at:          %s\n", sealedAt.Format(time.RFC3339))
	} else {
		// Daemon default window is 24h; we don't have it here, so
		// just show elapsed.
		fmt.Printf("Elapsed:            %s\n", time.Since(startedAt).Round(time.Second))
	}
	fmt.Printf("Binaries observed:  %d\n", binaries)
	fmt.Printf("Behaviors recorded: %d\n", behaviors)
	return nil
}

func baselineShow() error {
	if _, err := os.Stat(autobaselineDBPath); os.IsNotExist(err) {
		return fmt.Errorf("no profile at %s", autobaselineDBPath)
	}
	db, err := sql.Open("sqlite", autobaselineDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT image, action, detail, hits FROM profile ORDER BY image, action, detail`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type row struct {
		Image, Action, Detail string
		Hits                  uint64
	}
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.Image, &r.Action, &r.Detail, &r.Hits); err != nil {
			return err
		}
		all = append(all, r)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Image != all[j].Image {
			return all[i].Image < all[j].Image
		}
		if all[i].Action != all[j].Action {
			return all[i].Action < all[j].Action
		}
		return all[i].Detail < all[j].Detail
	})

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "IMAGE\tACTION\tDETAIL\tHITS")
	for _, r := range all {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\n", r.Image, r.Action, r.Detail, r.Hits)
	}
	return tw.Flush()
}

func baselineSeal() error {
	// Open with no auto-seal logic — just write sealed_at directly.
	// This avoids needing to coordinate with a running daemon: the
	// daemon's next Tick() will reload state and find it sealed.
	if _, err := os.Stat(autobaselineDBPath); os.IsNotExist(err) {
		return fmt.Errorf("no profile at %s — daemon hasn't started", autobaselineDBPath)
	}
	db, err := sql.Open("sqlite", autobaselineDBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	var existing string
	_ = db.QueryRow(`SELECT value FROM state WHERE key='sealed_at'`).Scan(&existing)
	if existing != "" {
		fmt.Printf("Already sealed at %s — no action.\n", existing)
		return nil
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO state(key,value) VALUES('sealed_at',?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, now); err != nil {
		return err
	}
	fmt.Printf("Sealed at %s.\n", now)
	fmt.Println("NOTE: the running daemon picks this up on its next 30s tick.")
	fmt.Println("      Until then, IsKnown() queries return false (observe mode).")
	return nil
}
