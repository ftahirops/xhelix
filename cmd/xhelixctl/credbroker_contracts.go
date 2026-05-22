package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/credbroker"
	"github.com/xhelix/xhelix/pkg/localapi"
)

// newCredbrokerContractCmd adds the `xhelixctl credbroker contract`
// subtree for managing Layer-2 (per-app, path-anchored) contracts.
//
// Layer-2 contracts let developers declare which sealed credentials
// their app may open, anchored by binary path + (optional) SHA pin +
// parent shape + rate cap. Once any contract claims a sealed path,
// only matching callers can authenticate — Layer-1 fallback is
// bypassed for that file. See pkg/credbroker/app_contract.go.
func newCredbrokerContractCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contract",
		Short: "Manage Layer-2 per-app credential contracts",
		Long: `Layer-2 contracts live at /etc/xhelix/contracts.d/*.yaml.
Each file declares one app's allowed sealed-credential access:

  binary:        /opt/myapp/bin/server
  sha256_pin:    "abc..."             # optional; without pin = TOFU
  parent_shape:  [systemd:myapp.service, interactive_shell]
  allowed_credentials:
    - /etc/myapp/db.sealed
    - /etc/myapp/aws.sealed
  purpose:       db_query
  max_opens_per_min: 30                # 0 = no cap

Once any contract claims a sealed path, ONLY callers matching that
contract can authenticate. Layer-1 (image-regex defaults) is bypassed
for that file. This is the universal-rock-solid guarantee.`,
	}
	cmd.AddCommand(newContractListCmd())
	cmd.AddCommand(newContractValidateCmd())
	cmd.AddCommand(newContractScaffoldCmd())
	return cmd
}

// list — query the daemon for loaded Layer-2 contracts.
func newContractListCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List Layer-2 contracts loaded by the running daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var resp struct {
				Contracts []struct {
					Name               string   `json:"name"`
					Binary             string   `json:"binary"`
					SHA256Pin          string   `json:"sha256_pin"`
					ParentShape        []string `json:"parent_shape"`
					AllowedCredentials []string `json:"allowed_credentials"`
					Purpose            string   `json:"purpose"`
					MaxOpensPerMin     int      `json:"max_opens_per_min"`
				} `json:"contracts"`
			}
			if err := c.Call("credbroker.contracts", struct{}{}, &resp); err != nil {
				return fmt.Errorf("credbroker.contracts: %w", err)
			}
			if len(resp.Contracts) == 0 {
				fmt.Println("No Layer-2 contracts loaded.")
				fmt.Println("Drop YAML at /etc/xhelix/contracts.d/<name>.yaml and restart xhelix.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tBINARY\tPINNED\tPARENT\tCREDS\tRATE")
			for _, c := range resp.Contracts {
				pinned := "no"
				if c.SHA256Pin != "" {
					pinned = c.SHA256Pin[:8] + "..."
				}
				rate := "∞"
				if c.MaxOpensPerMin > 0 {
					rate = fmt.Sprintf("%d/min", c.MaxOpensPerMin)
				}
				ps := strings.Join(c.ParentShape, ",")
				if ps == "" {
					ps = "any"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n",
					c.Name, c.Binary, pinned, ps, len(c.AllowedCredentials), rate)
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

// validate — locally parse a contract file before deployment.
func newContractValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <contract.yaml>",
		Short: "Lint a Layer-2 contract YAML without deploying it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := filepath.Dir(args[0])
			base := filepath.Base(args[0])
			if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
				return fmt.Errorf("contract file must end in .yaml or .yml")
			}
			set, errs := credbroker.LoadAppContractsDir(dir)
			// Find errors that reference this file specifically.
			for _, e := range errs {
				if strings.Contains(e.Error(), base) {
					return fmt.Errorf("validation failed: %w", e)
				}
			}
			for _, c := range set.Contracts() {
				if c.Name == strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml") {
					fmt.Printf("✓ contract %q is valid\n", c.Name)
					fmt.Printf("  binary:             %s\n", c.Binary)
					if c.SHA256Pin != "" {
						fmt.Printf("  sha256_pin:         %s\n", c.SHA256Pin)
					} else {
						fmt.Printf("  sha256_pin:         (TOFU — unpinned; consider pinning)\n")
					}
					if len(c.ParentShape) > 0 {
						fmt.Printf("  parent_shape:       %s\n", strings.Join(c.ParentShape, ", "))
					} else {
						fmt.Printf("  parent_shape:       (any — consider constraining)\n")
					}
					fmt.Printf("  allowed_credentials:\n")
					for _, p := range c.AllowedCredentials {
						fmt.Printf("    - %s\n", p)
					}
					if c.MaxOpensPerMin > 0 {
						fmt.Printf("  max_opens_per_min:  %d\n", c.MaxOpensPerMin)
					} else {
						fmt.Printf("  max_opens_per_min:  unlimited (consider a cap)\n")
					}
					return nil
				}
			}
			return fmt.Errorf("no contract loaded from %s", args[0])
		},
	}
	return cmd
}

// scaffold — emit a starter contract YAML to stdout for a binary.
func newContractScaffoldCmd() *cobra.Command {
	var purpose string
	var pin bool
	cmd := &cobra.Command{
		Use:   "scaffold <binary> [sealed-path]...",
		Short: "Print a Layer-2 contract template for a binary + sealed paths",
		Long: `Generates a starter contract YAML to stdout. Capture into
/etc/xhelix/contracts.d/<name>.yaml after review.

  xhelixctl credbroker contract scaffold /opt/myapp/bin/server \
      /etc/myapp/db.sealed /etc/myapp/aws.sealed --pin > /tmp/myapp.yaml

The --pin flag computes the current SHA-256 of the binary and embeds
it. Use only when you are certain the binary is in its intended
production state.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binary := args[0]
			creds := args[1:]
			fmt.Printf("# Layer-2 credbroker contract — generated by xhelixctl\n")
			fmt.Printf("# Review, then save as /etc/xhelix/contracts.d/<name>.yaml\n\n")
			fmt.Printf("binary: %s\n", binary)
			if pin {
				h, err := sha256OfFile(binary)
				if err != nil {
					fmt.Fprintf(os.Stderr, "warn: cannot compute SHA pin: %v (omitted)\n", err)
				} else {
					fmt.Printf("sha256_pin: %q\n", h)
				}
			}
			fmt.Printf("# parent_shape:\n")
			fmt.Printf("#   - systemd:<unit>.service   # if running as a service\n")
			fmt.Printf("#   - interactive_shell        # if developers run by hand\n")
			fmt.Printf("allowed_credentials:\n")
			if len(creds) == 0 {
				fmt.Printf("  - /path/to/your.sealed     # fill in\n")
			} else {
				for _, c := range creds {
					fmt.Printf("  - %s\n", c)
				}
			}
			if purpose != "" {
				fmt.Printf("purpose: %s\n", purpose)
			}
			fmt.Printf("# max_opens_per_min: 30        # uncomment to rate-cap\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&purpose, "purpose", "", "human-readable purpose")
	cmd.Flags().BoolVar(&pin, "pin", false, "include sha256_pin computed from current binary")
	return cmd
}
