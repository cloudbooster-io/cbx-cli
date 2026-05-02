package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/plan"

	"github.com/spf13/cobra"
)

func newPlanCmd() *cobra.Command {
	var (
		outputDir       string
		noTUI           bool
		diagramFormat   string
		llmProvider     string
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

			if noTUI || jsonFlag {
				if intent == "" {
					return fmt.Errorf("intent required in non-interactive mode")
				}
				return runOneShot(cfg, intent, dir, diagramFormat)
			}

			return runInteractive(cfg, intent, dir, diagramFormat, noTUI, llmProvider)
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for plan files")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive one-shot mode")
	cmd.Flags().StringVar(&diagramFormat, "diagram", "mermaid", "Diagram output format (mermaid or d2)")
	cmd.Flags().StringVar(&llmProvider, "llm", "", "Override the default LLM provider for this run")
	return cmd
}

func runOneShot(cfg *config.Config, intent, dir, diagramFormat string) error {
	client := &plan.MockClient{}
	provider := cfg.LLM.Default
	if provider == "" {
		provider = "claude"
	}
	p, err := client.GeneratePlan(context.Background(), intent, provider)
	if err != nil {
		return err
	}

	md := output.RenderPlanMD(p.Intent, p.Version, p.ADRContent, p.MermaidContent)

	if jsonFlag {
		envelope := map[string]any{
			"data": map[string]string{
				"markdown": md,
			},
		}
		b, err := json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("marshalling JSON: %w", err)
		}
		fmt.Println(string(b))
		return nil
	}

	mdPath := fmt.Sprintf("%s/plan.md", dir)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return fmt.Errorf("writing plan markdown: %w", err)
	}

	if !quietFlag {
		fmt.Printf("✓ Wrote %s (%d bytes)\n", mdPath, len(md))
	}

	if diagramFormat == "d2" {
		d2Path := fmt.Sprintf("%s/plan.d2", dir)
		if err := os.WriteFile(d2Path, []byte(p.D2Content), 0o644); err != nil {
			return fmt.Errorf("writing D2 diagram: %w", err)
		}
		if !quietFlag {
			fmt.Printf("✓ Wrote %s (%d bytes)\n", d2Path, len(p.D2Content))
		}
	}

	return nil
}

func runInteractive(cfg *config.Config, intent, dir, diagramFormat string, noTUI bool, llmProvider string) error {
	session := plan.NewSession(dir)
	session.DiagramFormat = diagramFormat
	session.ActiveProvider = llmProvider
	return plan.REPL(session, cfg, os.Stdin, os.Stdout, intent, noTUI)
}
