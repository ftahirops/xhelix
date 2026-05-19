package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/passport"
)

const defaultSock = "/run/xhelix/xhelix.sock"

func newPassportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "passport",
		Short: "Manage DLCF Data Passports (signed short-TTL data-movement permits)",
	}
	cmd.AddCommand(newPassportIssueCmd())
	cmd.AddCommand(newPassportListCmd())
	cmd.AddCommand(newPassportRevokeCmd())
	return cmd
}

func newPassportIssueCmd() *cobra.Command {
	var (
		actor       string
		route       string
		classes     []string
		maxRows     uint64
		maxBytes    uint64
		cidrs       []string
		ips         []string
		hostSfx     []string
		reason      string
		approvedBy  string
		ttlSeconds  int
		sock        string
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "issue",
		Short: "Issue a Data Passport authorising bulk data movement",
		Long: `Mints a short-TTL signed token that permits the named actor to move
data of the named classes to the named destinations.

Example:
  xhelixctl passport issue \
    --actor=admin_91 --route=/admin/export/orders \
    --class=pii --class=customer_order \
    --max-rows=5000 \
    --cidr=10.0.30.0/24 \
    --reason="monthly finance export" \
    --approved-by=operator_12 \
    --ttl=600`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if approvedBy == "" {
				return errors.New("--approved-by is required (two-person workflow)")
			}
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()

			params := passport.IssueParams{
				Actor:            actor,
				Route:            route,
				DataClasses:      classes,
				MaxRows:          maxRows,
				MaxBytes:         maxBytes,
				DestCIDRs:        cidrs,
				DestIPs:          ips,
				DestHostSuffixes: hostSfx,
				Reason:           reason,
				ApprovedBy:       approvedBy,
				TTL:              time.Duration(ttlSeconds) * time.Second,
			}
			var signed passport.Signed
			if err := c.Call("passport.issue", params, &signed); err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(signed)
			}
			fmt.Printf("Passport issued.\n")
			fmt.Printf("  id          %s\n", signed.Passport.ID)
			fmt.Printf("  actor       %s\n", signed.Passport.Actor)
			fmt.Printf("  classes     %s\n", strings.Join(signed.Passport.DataClasses, ", "))
			fmt.Printf("  expires_at  %s\n", signed.Passport.ExpiresAt.Format(time.RFC3339))
			fmt.Printf("  approved_by %s\n", signed.Passport.ApprovedBy)
			fmt.Printf("  key_id      %s\n", signed.KeyID)
			return nil
		},
	}
	cmd.Flags().StringVar(&actor, "actor", "", "actor identifier (e.g. admin_91)")
	cmd.Flags().StringVar(&route, "route", "", "originating route, optional")
	cmd.Flags().StringSliceVar(&classes, "class", nil, "data class (repeat for multiple)")
	cmd.Flags().Uint64Var(&maxRows, "max-rows", 0, "row cap, 0 = unlimited")
	cmd.Flags().Uint64Var(&maxBytes, "max-bytes", 0, "byte cap, 0 = unlimited")
	cmd.Flags().StringSliceVar(&cidrs, "cidr", nil, "allowed destination CIDR (repeat)")
	cmd.Flags().StringSliceVar(&ips, "ip", nil, "allowed destination IP (repeat)")
	cmd.Flags().StringSliceVar(&hostSfx, "host-suffix", nil, "allowed destination host suffix (repeat)")
	cmd.Flags().StringVar(&reason, "reason", "", "business justification (required)")
	cmd.Flags().StringVar(&approvedBy, "approved-by", "", "second-pair-of-eyes id (required)")
	cmd.Flags().IntVar(&ttlSeconds, "ttl", 600, "lifetime in seconds (capped at 900)")
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "daemon LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the full signed passport as JSON")
	_ = cmd.MarkFlagRequired("actor")
	_ = cmd.MarkFlagRequired("class")
	_ = cmd.MarkFlagRequired("reason")
	_ = cmd.MarkFlagRequired("approved-by")
	return cmd
}

func newPassportListCmd() *cobra.Command {
	var (
		sock    string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List currently active passports",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp map[string]any
			if err := c.Call("passport.list", map[string]any{}, &resp); err != nil {
				return err
			}
			if jsonOut {
				return json.NewEncoder(os.Stdout).Encode(resp)
			}
			ps, _ := resp["passports"].([]any)
			fmt.Printf("active passports: %d\n", len(ps))
			for _, raw := range ps {
				if m, ok := raw.(map[string]any); ok {
					fmt.Printf("  %s  actor=%v  classes=%v  expires=%v\n",
						m["id"], m["actor"], m["data_classes"], m["expires_at"])
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "daemon LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

func newPassportRevokeCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an active passport by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return err
			}
			defer c.Close()
			var resp map[string]any
			if err := c.Call("passport.revoke", map[string]any{"id": args[0]}, &resp); err != nil {
				return err
			}
			fmt.Printf("revoked: %v\n", resp["revoked"])
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "daemon LocalAPI socket")
	return cmd
}
