package cmd

import (
	"context"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	coreplan "gitlab.com/cloudbooster.io/platform/cbx-cli/core/plan"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/llm"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/plan"
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
		variants      int
	)
	cmd := &cobra.Command{
		Use:   `plan ["<intent>"]`,
		Short: "Generate an architecture plan from a natural-language intent",
		Long: `Generate an architecture plan from a natural-language intent.

With no intent on the command line, cbx plan opens an interactive REPL
(Bubble Tea TUI) that lets you refine the plan turn by turn. Pass an
intent positionally to run one-shot and exit when the artifacts are on
disk.

Output artifacts (written into --output-dir, default cwd):
  plan.md   — the generated architecture plan (ADR-style)
  plan.d2   — the architecture diagram (or plan.mermaid with --diagram mermaid)

Use --llm <provider> to override the default LLM provider for a single
run; the default is whatever you configured via 'cbx llm api login' or
'cbx llm cli list'. Use --variants N to generate N alternative plans
side by side.`,
		Example: `  # Interactive REPL (TUI) — refine the plan turn by turn
  cbx plan

  # One-shot: emit plan.md (+ diagram) from an intent in the cwd
  cbx plan "S3 + Lambda image processor"

  # One-shot + local HTML preview server, don't auto-open the browser
  cbx plan "intent" --html --no-open`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if len(cfg.LLM.Providers) == 0 {
				return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
					What: "no LLM provider configured",
					Why:  "cbx plan needs a model to generate the plan",
					Fix:  "run `cbx llm api login claude` (API key) or `cbx llm cli list` (use Claude Code / Codex CLI)",
					Code: "E_NO_LLM",
				}))
			}

			dir := outputDir
			if dir == "" {
				dir = "."
			}

			var intent string
			if len(args) > 0 {
				intent = args[0]
			}

			// Resolve credentials once, here at the composition root, and
			// inject them downstream. Library code (the runner/pipeline) never
			// reads the OS keyring itself, so unit tests don't trigger a
			// Keychain authorization prompt. The CloudBooster bearer token is
			// resolved eagerly; the LLM credential is resolved lazily per
			// provider so a mid-session /llm switch picks up the right one.
			token := auth.AccessToken()
			llmToken := func(provider string) string {
				tok, _ := llm.GetToken(provider)
				return tok
			}

			isHeadless := noTUI || output.JSON() || (intent != "" && !isatty.IsTerminal(os.Stdout.Fd()))
			if isHeadless {
				if intent == "" {
					return fmt.Errorf("intent required in non-interactive mode")
				}
				return runOneShot(cfg, intent, dir, diagramFormat, htmlPreview, noOpen, previewPort, llmProvider, variants, token, llmToken)
			}

			return runInteractive(cfg, intent, dir, diagramFormat, noTUI, llmProvider, token, llmToken)
		},
	}
	cmd.Flags().StringVarP(&outputDir, "output-dir", "d", "", "Output directory for plan files (default: cwd)")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive one-shot mode")
	cmd.Flags().StringVar(&diagramFormat, "diagram", "mermaid", "Diagram output format (mermaid or d2)")
	cmd.Flags().StringVar(&llmProvider, "llm", "", "Override the default LLM provider for this run")
	cmd.Flags().BoolVar(&htmlPreview, "html", false, "Start a local HTML preview server after writing plan files (one-shot mode)")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "Do not auto-open the HTML preview in a browser (requires --html)")
	cmd.Flags().IntVar(&previewPort, "port", 0, "Local HTML preview server port (0 = random; requires --html)")
	cmd.Flags().IntVar(&variants, "variants", 1, "Number of plan variants to generate")
	return cmd
}

type headlessProgress struct {
	silent bool
}

func (p *headlessProgress) PhaseStart(phase, total int, label string) {
	if p.silent {
		return
	}
	output.PrintPhase(os.Stderr, phase, total, label)
}

func (p *headlessProgress) SetStatus(left, right string) {}

func (p *headlessProgress) Token(token string) {}

func (p *headlessProgress) Candidate(name, description string) {}

func (p *headlessProgress) Commit() {}

func runOneShot(cfg *config.Config, intent, dir, diagramFormat string, htmlPreview, noOpen bool, previewPort int, llmProvider string, variants int, token string, llmToken func(provider string) string) error {
	if variants < 1 {
		return fmt.Errorf("variants must be at least 1")
	}
	if variants > 2 {
		return fmt.Errorf("free tier capped at 2 variants")
	}

	runner := coreplan.NewRunner(cfg, llmProvider, token, llmToken)
	ctx := context.Background()

	var plans []*coreplan.Plan
	for i := 0; i < variants; i++ {
		plan, err := runner.Run(ctx, intent, &headlessProgress{silent: output.JSON()})
		if err != nil {
			return err
		}
		plans = append(plans, plan)
	}

	if output.JSON() {
		if variants == 1 {
			md := output.RenderPlanMD(plans[0].Intent, plans[0].Version, plans[0].ADRContent, plans[0].MermaidContent)
			return output.PrintJSON(map[string]string{"markdown": md}, nil)
		}
		var variantsData []map[string]string
		for _, p := range plans {
			md := output.RenderPlanMD(p.Intent, p.Version, p.ADRContent, p.MermaidContent)
			variantsData = append(variantsData, map[string]string{"markdown": md})
		}
		return output.PrintJSON(map[string]any{"variants": variantsData}, nil)
	}

	// Write files for each variant.
	var files []string
	var totalBytes int
	for i, p := range plans {
		md := output.RenderPlanMD(p.Intent, p.Version, p.ADRContent, p.MermaidContent)
		mdPath := planFilePath(dir, "plan.md", i)
		if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
			return fmt.Errorf("writing plan markdown: %w", err)
		}
		files = append(files, mdPath)
		totalBytes += len(md)

		if diagramFormat == "d2" {
			d2Path := planFilePath(dir, "plan.d2", i)
			if err := os.WriteFile(d2Path, []byte(p.D2Content), 0o644); err != nil {
				return fmt.Errorf("writing D2 diagram: %w", err)
			}
			files = append(files, d2Path)
			totalBytes += len(p.D2Content)
		}
	}

	if !quietFlag {
		output.PrintPlanSummary(os.Stdout, files, totalBytes, len(plans[0].Components))
	}

	// Optional HTML preview server (CB-422). Opt-in via --html. Skip in --json
	// or when running with d2 diagrams (the template renders mermaid only).
	if htmlPreview && !output.JSON() && diagramFormat != "d2" && len(plans) > 0 {
		htmlBytes, err := generatePlanHTML(plans[0].Intent, plans[0].ADRContent, template.HTML(plans[0].MermaidContent))
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

func planFilePath(dir, base string, idx int) string {
	if idx == 0 {
		return filepath.Join(dir, base)
	}
	ext := filepath.Ext(base)
	name := base[:len(base)-len(ext)]
	return filepath.Join(dir, fmt.Sprintf("%s-v%d%s", name, idx+1, ext))
}

func runInteractive(cfg *config.Config, intent, dir, diagramFormat string, noTUI bool, llmProvider, token string, llmToken func(provider string) string) error {
	session := plan.NewSession(dir)
	session.DiagramFormat = diagramFormat
	session.ActiveProvider = llmProvider
	return plan.REPL(session, cfg, os.Stdin, os.Stdout, intent, noTUI, token, llmToken)
}
