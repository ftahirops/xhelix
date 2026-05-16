package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/model"
	"github.com/xhelix/xhelix/pkg/rules"
)

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Manage detection rules",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "lint [path]",
		Short: "Validate rule YAML files",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := "ruleset/core"
			if len(args) > 0 {
				path = args[0]
			}
			return lintRules(path)
		},
	})
	return cmd
}

func lintRules(path string) error {
	parsed, err := rules.LoadDir(path)
	if err != nil {
		return fmt.Errorf("load: %w", err)
	}
	if len(parsed) == 0 {
		fmt.Printf("no rules found under %s\n", path)
		return nil
	}

	// Compile every rule to verify CEL is well-formed.
	eng, err := rules.NewEngine(func(model.Alert) {})
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}
	if err := eng.Load(parsed); err != nil {
		return fmt.Errorf("compile: %w", err)
	}

	fmt.Printf("%d rules valid\n", len(parsed))
	return nil
}
