package main

import (
	"fmt"
	"os"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

func newAuditCmd() *cobra.Command {
	var (
		pulumiStateFile    string
		terraformStateFile string
		outputFormat       string
		reportFile         string
		noTUI              bool
		interactive        bool
		timeout            time.Duration
		timeoutPerScanner  time.Duration
		yes                bool
	)

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit infrastructure state for security and compliance issues",
		RunE: func(cmd *cobra.Command, args []string) error {
			if pulumiStateFile == "" && terraformStateFile == "" {
				return fmt.Errorf("--pulumi-state or --terraform-state is required")
			}

			if interactive {
				fmt.Fprintln(os.Stderr, "Interactive audit mode is a follow-up phase. See https://docs.cloudbooster.io/audit for details.")
				return nil
			}

			stateFile := pulumiStateFile
			if stateFile == "" {
				stateFile = terraformStateFile
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

			opts := audit.Options{
				StateFile:         stateFile,
				OutputFormat:      outputFormat,
				ReportFile:        reportFile,
				Interactive:       interactive,
				NoTUI:             noTUI,
				Quiet:             quietFlag,
				Yes:               yes,
				MockScanners:      true,
				Timeout:           timeout,
				TimeoutPerScanner: timeoutPerScanner,
			}

			result, err := audit.Run(opts)
			if err != nil {
				return err
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
				out := audit.RenderPlain(result.Findings, stateFile)
				fmt.Print(out)
			}

			if !quietFlag {
				fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" Wrote markdown report: "+result.ReportPath))
			}

			return audit.ExitWithSeverity(result.Findings)
		},
	}

	cmd.Flags().StringVar(&pulumiStateFile, "pulumi-state", "", "Path to Pulumi state file")
	cmd.Flags().StringVar(&terraformStateFile, "terraform-state", "", "Path to Terraform state file")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format (json, markdown, sarif, github-action)")
	cmd.Flags().StringVar(&reportFile, "report-file", "", "Path for markdown report output")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive mode (no-op for v1)")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Enable interactive follow-up mode")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Minute, "Overall audit timeout")
	cmd.Flags().DurationVar(&timeoutPerScanner, "timeout-per-scanner", 5*time.Minute, "Timeout per scanner/provider")
	cmd.Flags().BoolVar(&yes, "yes", false, "Skip interactive confirmations")

	return cmd
}
