package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
	tui "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/chat"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	var (
		pulumiStateFile    string
		terraformStateFile string
		sourceDir          string
		iacType            string
		outputFormat       string
		reportFile         string
		noTUI              bool
		interactive        bool
		timeout            time.Duration
		timeoutPerScanner  time.Duration
		yes                bool
		scanners           string
		llmProvider        string
		llmMaxFiles        int
		llmMaxBytesPerFile int
	)

	validIaCTypes := map[string]bool{
		"":                            true,
		audit.IaCTypeAuto:             true,
		audit.IaCTypeTerraform:        true,
		audit.IaCTypeCloudFormation:   true,
		audit.IaCTypeK8s:              true,
		audit.IaCTypeHelm:             true,
	}

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit infrastructure state for security and compliance issues",
		Long: `Audit infrastructure state for security and compliance issues.

Supported scanners and version ranges:
  tfsec   >= 1.28.0, < 2.0.0
  checkov >= 2.4.0, < 4.0.0
  prowler >= 3.0.0, < 5.0.0
  trivy   >= 0.48.0, < 1.0.0

By default mock scanners are used (zero network, no external binaries).
Use --scanners to enable real scanner binaries.

Source-mode only: --llm <provider> ships the source files to a configured
LLM (run 'cbx llm login <provider>' first) and emits structured findings.
This breaks the "fully offline" default; the analyzer runs only when the
flag is set. Mutually exclusive with --scanners.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputs := 0
			if pulumiStateFile != "" {
				inputs++
			}
			if terraformStateFile != "" {
				inputs++
			}
			if sourceDir != "" {
				inputs++
			}
			switch inputs {
			case 0:
				return fmt.Errorf("exactly one of --pulumi-state, --terraform-state, or --source is required")
			case 1:
				// ok
			default:
				return fmt.Errorf("--pulumi-state, --terraform-state, and --source are mutually exclusive")
			}

			if !validIaCTypes[iacType] {
				return fmt.Errorf("invalid --iac-type %q (choose: auto, terraform, cloudformation, k8s, helm)", iacType)
			}

			// Resolve --source to an absolute path before threading it
			// downstream. Without this, `cbx audit --source .` derives a
			// nonsense basename ("." → renderer drops it; default report
			// becomes `_audit_report.md`; mock findings render as
			// `source/main.tf`). Same idea for state files for symmetry.
			if sourceDir != "" {
				abs, absErr := filepath.Abs(sourceDir)
				if absErr != nil {
					return fmt.Errorf("resolving --source path: %w", absErr)
				}
				sourceDir = abs
			}

			stateFile := pulumiStateFile
			if stateFile == "" {
				stateFile = terraformStateFile
			}

			// inputLabel is the user-facing path used as the audit's "header" in
			// renderers and as the basis for the default report filename.
			inputLabel := stateFile
			if sourceDir != "" {
				inputLabel = sourceDir
			}

			validOutputs := map[string]bool{
				"":              true,
				"json":          true,
				"markdown":      true,
				"sarif":         true,
				"github-action": true,
			}
			if !validOutputs[outputFormat] {
				return fmt.Errorf("invalid output format %q (choose: json, markdown, sarif, github-action)", outputFormat)
			}

			// --json global flag behaves like --output json
			if jsonFlag && outputFormat == "" {
				outputFormat = "json"
			}

			var scannerNames []string
			mockScanners := true
			if scanners != "" {
				mockScanners = false
				for _, s := range strings.Split(scanners, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						scannerNames = append(scannerNames, s)
					}
				}
			}

			if llmProvider != "" {
				if scanners != "" {
					return fmt.Errorf("--llm and --scanners are mutually exclusive")
				}
				if sourceDir == "" {
					return fmt.Errorf("--llm requires --source (state-mode audits use rule-based scanners)")
				}
				// Suppress the static mock when --llm is selected — the
				// analyzer fully replaces the scanner list.
				mockScanners = false
			}

			opts := audit.Options{
				StateFile:         stateFile,
				SourceDir:         sourceDir,
				IaCType:           iacType,
				OutputFormat:      outputFormat,
				ReportFile:        reportFile,
				Interactive:       interactive,
				NoTUI:             noTUI,
				Quiet:             quietFlag,
				Yes:               yes,
				MockScanners:      mockScanners,
				Scanners:          scannerNames,
				LLMProvider:        llmProvider,
				LLMMaxFiles:        llmMaxFiles,
				LLMMaxBytesPerFile: llmMaxBytesPerFile,
				Timeout:           timeout,
				TimeoutPerScanner: timeoutPerScanner,
			}

			if interactive {
				if chat.IsTUIAvailable(os.Stdin, noTUI) && isatty.IsTerminal(os.Stdout.Fd()) && outputFormat == "" && !jsonFlag {
					return runInteractiveAudit(opts)
				}
				fmt.Fprintln(os.Stderr, "Interactive mode requires a terminal. Falling back to standard output.")
			}

			result, err := audit.Run(opts)
			if err != nil {
				if result == nil {
					return err
				}
				fmt.Fprintln(os.Stderr, err)
			}

			// Output rendering
			switch outputFormat {
			case "json":
				if err := output.PrintJSON(result.Findings, nil); err != nil {
					return err
				}
			case "sarif":
				out, err := audit.RenderSARIF(result.Findings)
				if err != nil {
					return err
				}
				fmt.Println(out)
			case "github-action":
				out := audit.RenderGitHubAction(result.Findings)
				fmt.Println(out)
			case "markdown":
				out := audit.RenderMarkdown(result.Findings)
				fmt.Println(out)
			default:
				out := audit.RenderPlain(result.Findings, inputLabel)
				fmt.Print(out)
			}

			if !quietFlag {
				fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" Wrote markdown report: "+result.ReportPath))
			}

			severityErr := audit.ExitWithSeverity(result.Findings)
			if severityErr != nil {
				return severityErr
			}
			if err != nil {
				return &audit.ExitCodeError{Code: 1}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&pulumiStateFile, "pulumi-state", "", "Path to Pulumi state file")
	cmd.Flags().StringVar(&terraformStateFile, "terraform-state", "", "Path to Terraform state file")
	cmd.Flags().StringVar(&sourceDir, "source", "", "Path to an IaC source directory to audit (mutually exclusive with --pulumi-state / --terraform-state)")
	cmd.Flags().StringVar(&iacType, "iac-type", audit.IaCTypeAuto, "IaC flavor for source-mode auto-detection (auto|terraform|cloudformation|k8s|helm)")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format (json, markdown, sarif, github-action)")
	cmd.Flags().StringVar(&reportFile, "report-file", "", "Path for markdown report output")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive mode (no-op for v1)")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Enable interactive follow-up mode")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Minute, "Overall audit timeout")
	cmd.Flags().DurationVar(&timeoutPerScanner, "timeout-per-scanner", 5*time.Minute, "Timeout per scanner/provider")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip interactive confirmations")
	cmd.Flags().StringVar(&scanners, "scanners", "", "Comma-separated list of scanners to run (tfsec,checkov,prowler,trivy)")
	cmd.Flags().StringVar(&llmProvider, "llm", "", "Source-mode only: send source files to the named LLM provider (claude|codex|ollama) and emit structured findings. Requires 'cbx llm login <provider>' first. Implies network egress.")
	cmd.Flags().IntVar(&llmMaxFiles, "llm-max-files", 0, "Cap on the number of source files shipped to the LLM analyzer (0 = default 50; only meaningful with --llm)")
	cmd.Flags().IntVar(&llmMaxBytesPerFile, "llm-max-bytes-per-file", 0, "Per-file byte cap for the LLM analyzer; longer files are truncated (0 = default 64 KB; only meaningful with --llm)")

	return cmd
}

func runInteractiveAudit(opts audit.Options) error {
	// Bypass the stdin size-guard prompt since we own the terminal.
	opts.Yes = true

	findings, err := audit.Collect(opts)
	if err != nil && findings == nil {
		return err
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}

	model := tui.NewModel(findings)
	model.SetSize(80, 24) // default; will be updated by WindowSizeMsg

	p := tea.NewProgram(model, tea.WithInput(os.Stdin), tea.WithOutput(os.Stdout), tea.WithAltScreen())

	_, tuiErr := p.Run()
	if tuiErr != nil {
		return fmt.Errorf("running TUI: %w", tuiErr)
	}

	// Write report on exit
	reportPath := opts.ReportFile
	if reportPath == "" {
		reportPath = audit.DefaultReportPath(opts)
	}
	if writeErr := os.WriteFile(reportPath, []byte(audit.RenderMarkdown(findings)), 0o644); writeErr != nil {
		return fmt.Errorf("writing report: %w", writeErr)
	}

	if !opts.Quiet {
		fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" Wrote markdown report: "+reportPath))
	}

	severityErr := audit.ExitWithSeverity(findings)
	if severityErr != nil {
		return severityErr
	}
	if err != nil {
		return &audit.ExitCodeError{Code: 1}
	}
	return nil
}
