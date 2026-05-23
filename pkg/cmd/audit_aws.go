package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	awsdisc "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/discover/aws"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// newAuditAWSCmd builds the `cbx audit aws [profile]` subcommand. It's a
// child of `audit`, registered in newAuditCmd. Lives in its own file to
// keep the parent audit.go from sprawling — the live-AWS surface is large
// enough to deserve its own home.
func newAuditAWSCmd() *cobra.Command {
	var (
		configFile     string
		regions        string
		awsConcurrency int
		diagnose       bool
	)

	cmd := &cobra.Command{
		Use:   "aws [profile]",
		Short: "Audit a live AWS account using the default SDK credential chain or an explicit profile/credentials file",
		Long: `Audit a live AWS account directly via the AWS SDK.

Resolution precedence for the profile (highest wins):
  1. --config <path>   — explicit credentials file
  2. positional [profile] — named profile in ~/.aws/credentials
  3. AWS_PROFILE env var
  4. "default" profile

Region resolution: if --regions is omitted, the profile's configured
region is used. If the profile has no region and you're on a TTY, an
interactive picker shows enabled regions. In non-interactive mode
(--json, --quiet, --yes, or no TTY) you must pass --regions.

Use --regions all to fan out across every enabled region in the account.

Discovery uses the CloudControl API across a curated set of CFN types
(see internal/audit/discover/aws/types_to_query.go). Per-resource
permission errors are aggregated and surfaced cleanly; pass --diagnose
to print every denied API call plus a recommended IAM policy patch.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := os.Getenv("AWS_PROFILE")
			if len(args) == 1 {
				profile = args[0]
			}

			var regionList []string
			for _, r := range strings.Split(regions, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					regionList = append(regionList, r)
				}
			}

			if awsConcurrency < 1 {
				awsConcurrency = 4
			}

			outputFormat := coalesceJSON()
			interactive := isatty.IsTerminal(os.Stdin.Fd()) &&
				isatty.IsTerminal(os.Stdout.Fd()) &&
				outputFormat == "" &&
				!quietFlag

			discoverParams := awsdisc.DiscoverParams{
				Profile:         profile,
				CredentialsFile: configFile,
				Regions:         regionList,
				Concurrency:     awsConcurrency,
				Diagnose:        diagnose,
			}
			if interactive {
				discoverParams.PromptForRegions = func(ctx context.Context, enabled []string) ([]string, error) {
					return awsdisc.PromptForRegions(ctx, enabled, os.Stdin, os.Stdout)
				}
			}

			ctx := context.Background()
			discResult, err := awsdisc.Discover(ctx, discoverParams)
			if err != nil {
				return err
			}

			// Header. Goes to stderr so machine-readable output on stdout
			// stays unpolluted.
			if !quietFlag && outputFormat == "" {
				fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" AWS preflight ok"))
				fmt.Fprintln(os.Stderr, "  audited account:  "+discResult.Identity.AccountID)
				fmt.Fprintln(os.Stderr, "  identity:         "+discResult.Identity.ARN)
				fmt.Fprintln(os.Stderr, "  audited regions:  "+strings.Join(discResult.Regions, ", "))
				fmt.Fprintln(os.Stderr, fmt.Sprintf("  resources found:  %d", len(discResult.Resources)))
				if len(discResult.PermissionErr) > 0 {
					fmt.Fprintln(os.Stderr, fmt.Sprintf("  permission errors: %d (re-run with --diagnose for details)", len(discResult.PermissionErr)))
				}
				if len(discResult.OtherErrs) > 0 {
					fmt.Fprintln(os.Stderr, fmt.Sprintf("  other warnings:    %d", len(discResult.OtherErrs)))
				}
			}

			// Run the scanner pipeline against the discovered resources.
			opts := audit.Options{
				AWS:           true,
				AWSAccountID:  discResult.Identity.AccountID,
				MockScanners:  true, // native CB rules; no external CLIs (plan §7.10)
				Quiet:         quietFlag,
				OutputFormat:  outputFormat,
			}
			findings, scanErr := audit.CollectFromResources(opts, discResult.Resources)
			if scanErr != nil && findings == nil {
				return scanErr
			}

			// JSON envelope path
			if outputFormat == "json" {
				payload := map[string]any{
					"identity":          discResult.Identity,
					"regions":           discResult.Regions,
					"resources_count":   len(discResult.Resources),
					"findings":          findings,
					"permission_errors": permErrsToJSON(discResult.PermissionErr),
				}
				return output.PrintJSON(payload, nil)
			}

			// Plain rendering
			label := fmt.Sprintf("aws://%s", discResult.Identity.AccountID)
			fmt.Print(audit.RenderPlain(findings, label))

			// Diagnose summary (per-call permission errors + IAM patch)
			if diagnose && len(discResult.PermissionErr) > 0 {
				renderDiagnose(os.Stderr, discResult.PermissionErr, discResult.Identity.ARN)
			}

			// Write the markdown report.
			reportPath := audit.DefaultReportPath(opts)
			if writeErr := os.WriteFile(reportPath, []byte(audit.RenderMarkdown(findings)), 0o644); writeErr != nil {
				return fmt.Errorf("writing report: %w", writeErr)
			}
			if !quietFlag {
				fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" Wrote markdown report: "+reportPath))
			}

			if severityErr := audit.ExitWithSeverity(findings); severityErr != nil {
				return severityErr
			}
			if scanErr != nil {
				return &audit.ExitCodeError{Code: 1}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configFile, "config", "", "Path to an AWS credentials file (overrides profile resolution)")
	cmd.Flags().StringVar(&regions, "regions", "", "Comma-separated AWS regions (default: profile default region; 'all' for every enabled region)")
	cmd.Flags().IntVar(&awsConcurrency, "aws-concurrency", 4, "Max concurrent AWS API calls per service")
	cmd.Flags().BoolVar(&diagnose, "diagnose", false, "Emit per-call IAM permission errors and a recommended IAM policy patch")

	return cmd
}

// coalesceJSON returns "json" when the global --json flag is on, else "".
// Mirrors what newAuditCmd does to keep the two subcommands consistent.
func coalesceJSON() string {
	if jsonFlag {
		return "json"
	}
	return ""
}

// permErrsToJSON converts *PermissionError slice into the JSON-friendly
// shape — keeps the JSON output envelope free of pointer/private fields.
func permErrsToJSON(in []*awsdisc.PermissionError) []map[string]string {
	out := make([]map[string]string, 0, len(in))
	for _, e := range in {
		out = append(out, map[string]string{
			"service": e.Service,
			"action":  e.Action,
			"region":  e.Region,
			"error":   fmt.Sprintf("%v", e.Cause),
		})
	}
	return out
}

// renderDiagnose prints the --diagnose summary: per-call permission
// errors and an actionable IAM policy patch that, if attached to the
// caller, unblocks the failing API actions.
func renderDiagnose(w *os.File, errs []*awsdisc.PermissionError, callerARN string) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Permission errors during discovery:")
	uniqActions := map[string]struct{}{}
	for _, e := range errs {
		region := e.Region
		if region == "" {
			region = "global"
		}
		fmt.Fprintf(w, "  ✗ %-40s → AccessDenied (in %s)\n", e.Action, region)
		uniqActions[e.Action] = struct{}{}
	}
	if len(uniqActions) == 0 {
		return
	}

	actions := make([]string, 0, len(uniqActions))
	for a := range uniqActions {
		actions = append(actions, a)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Recommended IAM policy patch to fix the above:")
	fmt.Fprintln(w, "  {")
	fmt.Fprintln(w, "    \"Effect\": \"Allow\",")
	fmt.Fprintln(w, "    \"Action\": [")
	for i, a := range actions {
		comma := ","
		if i == len(actions)-1 {
			comma = ""
		}
		fmt.Fprintf(w, "      %q%s\n", a, comma)
	}
	fmt.Fprintln(w, "    ],")
	fmt.Fprintln(w, "    \"Resource\": \"*\"")
	fmt.Fprintln(w, "  }")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Caller: %s\n", callerARN)
}
