package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// newSecrettaintCmd is the operator surface for the secret-taint store.
// Phase B.2 ships informational subcommands; direct lineage inspection
// arrives in Phase B.3 (LocalAPI wiring).
func newSecrettaintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "secrettaint",
		Aliases: []string{"taint"},
		Short:   "Inspect the secret-taint store",
		Long: `Secret-taint tracks per-lineage secret-touch state. When a process
touches sensitive material (.env, /proc/*/environ, cloud creds, kube
tokens, IMDS, etc.), its lineage transitions:

  clean → secret_touched → outbound_restricted → containment_required

Subsequent novel outbound or persistence actions face stricter rules.`,
	}
	cmd.AddCommand(newSecrettaintShowCmd())
	cmd.AddCommand(newSecrettaintClassesCmd())
	return cmd
}

func newSecrettaintShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show current secret-taint state (placeholder until LocalAPI wired)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stdout, "Secret-taint live state is exposed through the daemon journal:")
			fmt.Fprintln(os.Stdout, "")
			fmt.Fprintln(os.Stdout, "  sudo journalctl -u xhelix --no-pager | grep secrettaint")
			fmt.Fprintln(os.Stdout, "")
			fmt.Fprintln(os.Stdout, "Direct lineage inspection arrives in Phase B.3 (LocalAPI wiring).")
			return nil
		},
	}
}

func newSecrettaintClassesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "classes",
		Short: "List secret class taxonomy and what triggers each",
		RunE: func(cmd *cobra.Command, args []string) error {
			rows := []struct{ class, trigger string }{
				{"env", "shell environment variable read"},
				{"proc_environ", "/proc/<pid>/environ scrape (procscrape sensor)"},
				{"cloud_creds", "AWS/GCP/Azure cred file read OR credbroker cloud release"},
				{"kube_token", "K8s service-account token OR credbroker kube release"},
				{"git_token", ".git-credentials or .netrc"},
				{"api_key", ".docker/config.json or .npmrc OR credbroker api_key"},
				{"browser_session", "browser cred-store access OR credbroker session"},
				{"secret_file", "/etc/shadow, sudoers, SSH host keys, /root/.ssh/id_*"},
				{"metadata", "IMDS endpoint (169.254.169.254 etc.)"},
				{"session_store", "/var/lib/xhelix/credbroker/* or /run/credentials/*"},
				{"workload_identity", "cloud-init sensitive-data-dir"},
				{"token", "generic credbroker release"},
			}
			fmt.Fprintf(os.Stdout, "%-22s %s\n", "CLASS", "TRIGGER")
			for _, r := range rows {
				fmt.Fprintf(os.Stdout, "%-22s %s\n", r.class, r.trigger)
			}
			fmt.Fprintln(os.Stdout)
			fmt.Fprintln(os.Stdout, "Taint state transitions:")
			fmt.Fprintln(os.Stdout, "  clean → secret_touched           (any touch)")
			fmt.Fprintln(os.Stdout, "  ... → outbound_restricted        (novel outbound — Phase C)")
			fmt.Fprintln(os.Stdout, "  ... → containment_required       (multi-gate — Phase D)")
			return nil
		},
	}
}
