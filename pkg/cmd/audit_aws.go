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

NOTE: this PR ships the subcommand scaffolding + IAM preflight + region
resolution. CloudControl discovery + per-service describers + the
component grouping pass land in the next PR — for now the run reports
the resolved identity/regions and exits cleanly with 0 resources.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := os.Getenv("AWS_PROFILE")
			if len(args) == 1 {
				profile = args[0]
			}

			// Region flag → cleaned []string
			var regionList []string
			for _, r := range strings.Split(regions, ",") {
				r = strings.TrimSpace(r)
				if r != "" {
					regionList = append(regionList, r)
				}
			}

			// Concurrency default
			if awsConcurrency < 1 {
				awsConcurrency = 4
			}

			opts := audit.Options{
				AWS:            true,
				AWSProfile:     profile,
				AWSConfigFile:  configFile,
				Regions:        regionList,
				AWSConcurrency: awsConcurrency,
				Diagnose:       diagnose,
				Quiet:          quietFlag,
				OutputFormat:   coalesceJSON(),
			}

			// Decide whether to wire the interactive region picker. Available
			// only when stdin AND stdout are real TTYs and we're not in a
			// machine-readable mode.
			interactive := isatty.IsTerminal(os.Stdin.Fd()) &&
				isatty.IsTerminal(os.Stdout.Fd()) &&
				opts.OutputFormat == "" &&
				!opts.Quiet

			discoverParams := awsdisc.DiscoverParams{
				Profile:         opts.AWSProfile,
				CredentialsFile: opts.AWSConfigFile,
				Regions:         opts.Regions,
				Concurrency:     opts.AWSConcurrency,
				Diagnose:        opts.Diagnose,
			}
			if interactive {
				discoverParams.PromptForRegions = func(ctx context.Context, enabled []string) ([]string, error) {
					return awsdisc.PromptForRegions(ctx, enabled, os.Stdin, os.Stdout)
				}
			}

			ctx := context.Background()
			result, err := awsdisc.Discover(ctx, discoverParams)
			if err != nil {
				return err
			}

			// Header — surfaces what the run targeted. Same lines whether or
			// not the discovery layer has been implemented yet.
			if !opts.Quiet && opts.OutputFormat == "" {
				fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" AWS preflight ok"))
				fmt.Fprintln(os.Stderr, "  audited account:  "+result.Identity.AccountID)
				fmt.Fprintln(os.Stderr, "  identity:         "+result.Identity.ARN)
				fmt.Fprintln(os.Stderr, "  audited regions:  "+strings.Join(result.Regions, ", "))
				fmt.Fprintln(os.Stderr, "  resources found:  "+fmt.Sprint(len(result.Resources))+"  (discovery layer not yet implemented — next PR)")
			}

			// JSON output for machine consumers — same envelope as other
			// audit subcommands.
			if opts.OutputFormat == "json" {
				payload := map[string]any{
					"identity":   result.Identity,
					"regions":    result.Regions,
					"resources":  result.Resources,
					"discovery":  "not_yet_implemented",
				}
				return output.PrintJSON(payload, nil)
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
