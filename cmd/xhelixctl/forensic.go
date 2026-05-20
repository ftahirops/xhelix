package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/forensic"
	"github.com/xhelix/xhelix/pkg/forensicapi"
	"github.com/xhelix/xhelix/pkg/localapi"
)

func newForensicCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "forensic",
		Short: "Query the IOC store harvested from Ring-2 deception layers",
		Long:  `Query indicators harvested from honey-sh sessions, sinkhole beacons, DNS-poison events, decoy-FS reads, and crash-loop events.`,
	}
	cmd.AddCommand(newForensicIOCsCmd())
	cmd.AddCommand(newForensicShowCmd())
	cmd.AddCommand(newForensicTagCmd())
	cmd.AddCommand(newForensicCountCmd())
	return cmd
}

func newForensicIOCsCmd() *cobra.Command {
	var (
		sock        string
		jsonOut     bool
		kindFlag    string
		confidence  string
		origin      string
		sinceStr    string
		limit       int
	)
	cmd := &cobra.Command{
		Use:   "iocs",
		Short: "List harvested IOCs (filterable by kind / origin / confidence / since)",
		Example: `  xhelixctl forensic iocs
  xhelixctl forensic iocs --kind=domain,url --confidence=high
  xhelixctl forensic iocs --origin=sinkhole --since=2026-05-20T00:00:00Z
  xhelixctl forensic iocs --kind=ja3 --limit=10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()

			q := forensicapi.QueryParam{
				Confidence: confidence,
				Origin:     origin,
				Limit:      limit,
			}
			if kindFlag != "" {
				q.Kinds = strings.Split(kindFlag, ",")
			}
			if sinceStr != "" {
				if t, err := time.Parse(time.RFC3339, sinceStr); err != nil {
					return fmt.Errorf("--since must be RFC3339: %w", err)
				} else {
					q.Since = t.Format(time.RFC3339)
				}
			}

			var iocs []*forensic.IOC
			if err := c.Call("forensic.iocs", q, &iocs); err != nil {
				return err
			}
			if jsonOut {
				return jsonPrint(iocs)
			}
			if len(iocs) == 0 {
				fmt.Println("(no IOCs match)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "KIND\tVALUE\tCONFIDENCE\tCOUNT\tORIGINS\tLAST_SEEN")
			for _, i := range iocs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
					i.Kind, truncate(i.Value, 60), i.Confidence,
					i.Count, strings.Join(i.Origins, ","),
					i.LastSeen.Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON instead of a table")
	cmd.Flags().StringVar(&kindFlag, "kind", "", "comma-separated IOC kinds (domain,url,ipv4,...)")
	cmd.Flags().StringVar(&confidence, "confidence", "", "minimum confidence (deterministic|high|medium|low)")
	cmd.Flags().StringVar(&origin, "origin", "", "filter by capture origin (sinkhole|honeysh|dnspoison|...)")
	cmd.Flags().StringVar(&sinceStr, "since", "", "RFC3339 timestamp — only IOCs seen at-or-after this time")
	cmd.Flags().IntVar(&limit, "limit", 0, "max IOCs to return (default 200 server-side)")
	return cmd
}

func newForensicShowCmd() *cobra.Command {
	var (
		sock    string
		jsonOut bool
	)
	cmd := &cobra.Command{
		Use:   "show <kind> <value>",
		Short: "Show full detail for one IOC",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var ioc forensic.IOC
			if err := c.Call("forensic.ioc",
				forensicapi.KindValueParam{Kind: args[0], Value: args[1]}, &ioc); err != nil {
				return err
			}
			if jsonOut {
				return jsonPrint(ioc)
			}
			fmt.Printf("Kind:        %s\n", ioc.Kind)
			fmt.Printf("Value:       %s\n", ioc.Value)
			fmt.Printf("Confidence:  %s\n", ioc.Confidence)
			fmt.Printf("Count:       %d\n", ioc.Count)
			fmt.Printf("First seen:  %s\n", ioc.FirstSeen.Format(time.RFC3339))
			fmt.Printf("Last seen:   %s\n", ioc.LastSeen.Format(time.RFC3339))
			fmt.Printf("Origins:     %s\n", strings.Join(ioc.Origins, ", "))
			if len(ioc.Tags) > 0 {
				fmt.Printf("Tags:        %s\n", strings.Join(ioc.Tags, ", "))
			}
			if len(ioc.Sources) > 0 {
				fmt.Printf("Sources:     %s\n", strings.Join(ioc.Sources, ", "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print JSON")
	return cmd
}

func newForensicTagCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "tag <kind> <value> <tag>",
		Short: "Attach an operator label to an IOC (e.g. cobalt-strike, mimikatz)",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var resp map[string]bool
			if err := c.Call("forensic.ioc_tag",
				forensicapi.TagParam{Kind: args[0], Value: args[1], Tag: args[2]}, &resp); err != nil {
				return err
			}
			if !resp["ok"] {
				return fmt.Errorf("tag did not stick")
			}
			fmt.Println("tagged.")
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

func newForensicCountCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "count",
		Short: "Print the total IOC count",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var res forensicapi.CountResult
			if err := c.Call("forensic.ioc_count", struct{}{}, &res); err != nil {
				return err
			}
			fmt.Println(res.Total)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
