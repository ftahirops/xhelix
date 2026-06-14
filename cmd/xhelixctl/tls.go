package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

// newTLSCmd surfaces the Phase TLS-L2 plaintext ledger. The ledger
// lives in the daemon's web server, so the CLI speaks HTTP to it
// (default http://127.0.0.1:8080). Every list/get is audited on the
// daemon side to /var/log/xhelix/tls-plaintext-access.log.
//
// THIS IS A SENSITIVE FEATURE. Captured records may include URL
// query strings, request bodies, response bodies — even with the
// built-in header + JSON-field redaction. Treat the output of
// `xhelixctl tls list/get` as if it were a credential dump.
func newTLSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tls",
		Short: "TLS plaintext ledger (opt-in, audited)",
		Long: `Operator-facing surface for the L2 TLS plaintext capture.

The ledger is DISABLED by default. Operators must:
  1. Set tls_plaintext.enabled: true in /etc/xhelix/xhelix.yaml
  2. Add per-binary opt-ins to tls_plaintext.allowed_binaries
  3. Restart the daemon

Every 'list' and 'get' call is recorded on the daemon side to
/var/log/xhelix/tls-plaintext-access.log with timestamp, remote IP,
record ID, and binary. Authorization / Cookie / Set-Cookie /
X-Auth-* / X-Api-Key / X-Csrf-Token / X-Session-Id headers are
ALWAYS redacted. JSON fields named password/token/api_key/secret/
credentials/access_token/refresh_token/session_id are redacted by
regex.`,
	}
	cmd.AddCommand(newTLSAllowCmd())
	cmd.AddCommand(newTLSUnallowCmd())
	cmd.AddCommand(newTLSAllowListCmd())
	cmd.AddCommand(newTLSListCmd())
	cmd.AddCommand(newTLSGetCmd())
	cmd.AddCommand(newTLSStatsCmd())
	return cmd
}

const defaultTLSBase = "http://127.0.0.1:8080"

func tlsHTTP(method, base, path string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func newTLSAllowCmd() *cobra.Command {
	var base string
	cmd := &cobra.Command{
		Use:   "allow <binary>",
		Short: "Opt-in a binary for plaintext capture",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := tlsHTTP("POST", base, "/api/tls/plaintext/allow", map[string]string{
				"binary": args[0], "action": "add",
			})
			if err != nil {
				return err
			}
			fmt.Printf("opt-in added: %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", defaultTLSBase, "daemon dashboard URL")
	return cmd
}

func newTLSUnallowCmd() *cobra.Command {
	var base string
	cmd := &cobra.Command{
		Use:   "unallow <binary>",
		Short: "Remove a binary's opt-in",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := tlsHTTP("POST", base, "/api/tls/plaintext/allow", map[string]string{
				"binary": args[0], "action": "remove",
			})
			if err != nil {
				return err
			}
			fmt.Printf("opt-in removed: %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", defaultTLSBase, "daemon dashboard URL")
	return cmd
}

func newTLSAllowListCmd() *cobra.Command {
	var base string
	cmd := &cobra.Command{
		Use:   "allowlist",
		Short: "Show currently opted-in binaries",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := tlsHTTP("GET", base, "/api/tls/plaintext/allowlist", nil)
			if err != nil {
				return err
			}
			var out []string
			if err := json.Unmarshal(data, &out); err != nil {
				return err
			}
			if len(out) == 0 {
				fmt.Println("(no binaries opted in)")
				return nil
			}
			for _, b := range out {
				fmt.Println(b)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", defaultTLSBase, "daemon dashboard URL")
	return cmd
}

type tlsRecord struct {
	ID         string            `json:"id"`
	Time       time.Time         `json:"time"`
	Binary     string            `json:"binary"`
	PID        uint32            `json:"pid"`
	Direction  string            `json:"direction"`
	PeerSNI    string            `json:"peer_sni"`
	PeerIP     string            `json:"peer_ip"`
	PeerPort   uint16            `json:"peer_port"`
	HTTPMethod string            `json:"http_method"`
	HTTPPath   string            `json:"http_path"`
	HTTPStatus int               `json:"http_status"`
	Headers    map[string]string `json:"headers"`
	BodyBytes  int               `json:"body_bytes"`
	BodyText   string            `json:"body_text"`
	Truncated  bool              `json:"truncated"`
}

func newTLSListCmd() *cobra.Command {
	var base, binary string
	var n int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Show recent plaintext records",
		RunE: func(cmd *cobra.Command, args []string) error {
			q := url.Values{}
			q.Set("n", fmt.Sprintf("%d", n))
			if binary != "" {
				q.Set("binary", binary)
			}
			data, err := tlsHTTP("GET", base, "/api/tls/plaintext/list?"+q.Encode(), nil)
			if err != nil {
				return err
			}
			var recs []tlsRecord
			if err := json.Unmarshal(data, &recs); err != nil {
				return err
			}
			if len(recs) == 0 {
				fmt.Println("(no records)")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tTIME\tDIR\tBINARY\tSNI\tMETHOD/PATH\tSTATUS\tBODY")
			for _, r := range recs {
				mp := r.HTTPMethod
				if r.HTTPPath != "" {
					mp += " " + truncStrTLS(r.HTTPPath, 32)
				}
				preview := r.BodyText
				if len(preview) > 60 {
					preview = preview[:60] + "…"
				}
				preview = strings.ReplaceAll(preview, "\n", " ")
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
					r.ID, r.Time.Format("15:04:05"), r.Direction,
					truncStrTLS(r.Binary, 20),
					truncStrTLS(r.PeerSNI, 20),
					mp, r.HTTPStatus, preview)
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", defaultTLSBase, "daemon dashboard URL")
	cmd.Flags().StringVar(&binary, "binary", "", "filter by binary substring")
	cmd.Flags().IntVar(&n, "n", 50, "max records (1..500)")
	return cmd
}

func newTLSGetCmd() *cobra.Command {
	var base string
	cmd := &cobra.Command{
		Use:   "get <id>",
		Short: "Show one plaintext record in full",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := tlsHTTP("GET", base, "/api/tls/plaintext/get?id="+url.QueryEscape(args[0]), nil)
			if err != nil {
				return err
			}
			// pretty-print
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, data, "", "  "); err != nil {
				_, _ = os.Stdout.Write(data)
				return nil
			}
			_, _ = os.Stdout.Write(pretty.Bytes())
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", defaultTLSBase, "daemon dashboard URL")
	return cmd
}

func newTLSStatsCmd() *cobra.Command {
	var base string
	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Ledger counters (observed / stored / dropped)",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := tlsHTTP("GET", base, "/api/tls/plaintext/stats", nil)
			if err != nil {
				return err
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, data, "", "  "); err != nil {
				_, _ = os.Stdout.Write(data)
				return nil
			}
			_, _ = os.Stdout.Write(pretty.Bytes())
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVar(&base, "base", defaultTLSBase, "daemon dashboard URL")
	return cmd
}

func truncStrTLS(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
