package main

import (
	"context"
	"fmt"
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/plan"

	"github.com/spf13/cobra"
)

func newPlanCmd() *cobra.Command {
	var (
		outputDir   string
		interactive bool
		noTUI       bool
	)
	cmd := &cobra.Command{
		Use:   `plan ["<intent>"]`,
		Short: "Generate an architecture plan from a natural-language intent",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if len(cfg.LLM.Providers) == 0 {
				return fmt.Errorf("no LLM provider configured; run 'cbx llm login <provider>' first")
			}

			dir := outputDir
			if dir == "" {
				dir = "."
			}

			var intent string
			if len(args) > 0 {
				intent = args[0]
			}

			if noTUI {
				if intent == "" {
					return fmt.Errorf("intent required in non-interactive mode")
				}
				return runOneShot(cfg, intent, dir)
			}

			if interactive || intent == "" {
				return runInteractive(cfg, intent, dir)
			}

			return runOneShot(cfg, intent, dir)
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for plan files")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Force interactive mode")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive one-shot mode")
	return cmd
}

func runOneShot(cfg *config.Config, intent, dir string) error {
	client := &plan.MockClient{}
	provider := cfg.LLM.Default
	if provider == "" {
		provider = "claude"
	}
	p, err := client.GeneratePlan(context.Background(), intent, provider)
	if err != nil {
		return err
	}

	adrPath := fmt.Sprintf("%s/plan.adr.md", dir)
	d2Path := fmt.Sprintf("%s/plan.d2", dir)

	if err := os.WriteFile(adrPath, []byte(p.ADRContent), 0o644); err != nil {
		return fmt.Errorf("writing ADR: %w", err)
	}
	if err := os.WriteFile(d2Path, []byte(p.D2Content), 0o644); err != nil {
		return fmt.Errorf("writing diagram: %w", err)
	}

	if !quietFlag {
		fmt.Printf("✓ Wrote %s (%d bytes)\n", adrPath, len(p.ADRContent))
		fmt.Printf("✓ Wrote %s (%d bytes)\n", d2Path, len(p.D2Content))
	}
	return nil
}

func runInteractive(cfg *config.Config, intent, dir string) error {
	session := plan.NewSession(dir)
	client := &plan.MockClient{}
	return plan.REPL(session, client, cfg, os.Stdin, os.Stdout, intent)
}
