package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/plan"

	"github.com/spf13/cobra"
)

func newPlanCmd() *cobra.Command {
	var (
		outputDir     string
		noTUI         bool
		diagramFormat string
		llmProvider   string
		htmlPreview   bool
		noOpen        bool
		previewPort   int
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
				return runOneShot(cfg, intent, dir, diagramFormat, htmlPreview, noOpen, previewPort)
			}

			return runInteractive(cfg, intent, dir, diagramFormat, noTUI, llmProvider)
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for plan files")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive one-shot mode")
	cmd.Flags().StringVar(&diagramFormat, "diagram", "mermaid", "Diagram output format (mermaid or d2)")
	cmd.Flags().StringVar(&llmProvider, "llm", "", "Override the default LLM provider for this run")
	cmd.Flags().BoolVar(&htmlPreview, "html", false, "Start a local HTML preview server after writing plan files (one-shot mode)")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "Do not auto-open the HTML preview in a browser (requires --html)")
	cmd.Flags().IntVar(&previewPort, "port", 0, "Local HTML preview server port (0 = random; requires --html)")
	return cmd
}

func runOneShot(cfg *config.Config, intent, dir, diagramFormat string, htmlPreview, noOpen bool, previewPort int) error {
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

	// Optional HTML preview server (CB-422). Opt-in via --html. Skip in --json
	// or when running with d2 diagrams (the template renders mermaid only).
	if htmlPreview && !jsonFlag && diagramFormat != "d2" {
		htmlBytes, err := generatePlanHTML(p.Intent, p.ADRContent, template.HTML(p.MermaidContent))
		if err != nil {
			if !quietFlag {
				fmt.Fprintf(os.Stderr, "warning: failed to generate HTML preview: %v\n", err)
			}
			return nil
		}
		if err := startPreviewServer(dir, htmlBytes, previewPort, noOpen); err != nil && !quietFlag {
			fmt.Fprintf(os.Stderr, "warning: HTML preview server: %v\n", err)
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
