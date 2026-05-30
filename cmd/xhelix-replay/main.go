// xhelix-replay — measure alert volume against an existing alerts.jsonl
// log under a (rules + runtime-registry + alert-mode) policy.
//
//	xhelix-replay --in alerts.jsonl --rules ruleset/core \
//	   --runtime ruleset/runtime_categories.yaml --mode visibility \
//	   --tp testdata/prod-trace/true_positive_rules.txt --format text
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xhelix/xhelix/pkg/rulecat"
	"github.com/xhelix/xhelix/pkg/rules"
)

func main() {
	in := flag.String("in", "", "path to alerts.jsonl (required)")
	rulesDir := flag.String("rules", "ruleset/core", "YAML rules directory")
	runtimeFile := flag.String("runtime", "ruleset/runtime_categories.yaml", "runtime category registry")
	mode := flag.String("mode", "visibility", "alert mode: visibility | detection")
	tpFile := flag.String("tp", "", "optional newline-separated TP rule ids")
	format := flag.String("format", "text", "output: text | json")
	verdict := flag.Bool("verdict", false, "route incident/weak_signal through the per-lineage score engine (lower bound: replay lineage is per-PID)")
	flag.Parse()
	if *in == "" {
		fmt.Fprintln(os.Stderr, "xhelix-replay: --in is required")
		os.Exit(2)
	}

	resolver := rulecat.NewResolver()
	if rs, err := rules.LoadDir(*rulesDir); err != nil {
		fmt.Fprintf(os.Stderr, "load rules %s: %v\n", *rulesDir, err)
	} else {
		resolver.AddRules(rs)
	}
	if err := resolver.AddRuntimeFile(*runtimeFile); err != nil {
		fmt.Fprintf(os.Stderr, "load runtime registry: %v\n", err)
		os.Exit(1)
	}

	var tp map[string]bool
	if *tpFile != "" {
		b, err := os.ReadFile(*tpFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read tp file: %v\n", err)
			os.Exit(1)
		}
		tp = map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				tp[l] = true
			}
		}
	}

	res, err := ReplayFile(*in, ReplayOpts{AlertMode: *mode, Resolver: resolver, TruePositiveIDs: tp, Verdict: *verdict})
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		os.Exit(1)
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("Replay summary (mode=%s, verdict=%v, classified_rules=%d)\n", *mode, *verdict, resolver.Len())
		fmt.Printf("  total lines:  %d\n", res.TotalLines)
		fmt.Printf("  parsed:       %d\n", res.Parsed)
		fmt.Printf("  emitted:      %d\n", res.Emitted)
		fmt.Printf("  suppressed:   %d\n", res.Suppressed)
		if *verdict {
			fmt.Printf("  verdicts_emitted: %d  (incident/weak_signal routed through per-lineage score engine)\n", res.VerdictsEmitted)
			fmt.Println("  NOTE: replay lineage = identity (per-PID). No proctree ancestry is")
			fmt.Println("        reconstructed from the trace, so this is a CONSERVATIVE LOWER BOUND;")
			fmt.Println("        the live daemon correlates across parent+child PIDs and collapses MORE.")
			fmt.Println("  top collapsed_by_rule (raw incident/weak fires that did NOT cross threshold):")
			for _, kv := range topN(res.CollapsedByRule, 15) {
				fmt.Printf("    %-40s %d\n", kv.k, kv.v)
			}
		}
		fmt.Printf("  by category suppressed: fact=%d weak_signal=%d\n",
			res.SuppressedByCategory["fact"], res.SuppressedByCategory["weak_signal"])
		// Top emitted rules.
		fmt.Println("  top emitted rules:")
		for _, kv := range topN(res.EmittedByRule, 15) {
			fmt.Printf("    %-40s %d\n", kv.k, kv.v)
		}
		if len(res.Unclassified) > 0 {
			fmt.Printf("  unclassified rule ids (%d distinct) — default weak_signal:\n", len(res.Unclassified))
			for _, kv := range topN(res.Unclassified, 15) {
				fmt.Printf("    %-40s %d\n", kv.k, kv.v)
			}
		}
		if len(res.TPRegressions) > 0 {
			fmt.Println("\n  *** TRUE-POSITIVE REGRESSIONS ***")
			for _, m := range res.TPRegressions {
				fmt.Printf("    %s\n", m)
			}
		}
	}
	if len(res.TPRegressions) > 0 {
		os.Exit(3) // signal regression for CI
	}
}

type kvPair struct {
	k string
	v int
}

func topN(m map[string]int, n int) []kvPair {
	out := make([]kvPair, 0, len(m))
	for k, v := range m {
		out = append(out, kvPair{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].v != out[j].v {
			return out[i].v > out[j].v
		}
		return out[i].k < out[j].k
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
