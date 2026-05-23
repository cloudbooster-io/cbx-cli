package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	awsdisc "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/discover/aws"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/group"
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
		llmMaxCost     float64
	)

	cmd := &cobra.Command{
		Use:     "aws [profile]",
		Aliases: []string{"a"},
		Short:   "Audit a live AWS account",
		Long: `Audit a live AWS account directly via the AWS SDK.

Credentials come from the default SDK credential chain or an explicit
profile / credentials file. Resolution precedence for the profile
(highest wins):

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
to print every denied API call plus a recommended IAM policy patch.

Findings are always grounded in CloudBooster's curated AWS knowledge
via cbx-mcp tool calls invoked through the Claude Code CLI. This is
not optional: the audit ships discovered resources (plus
cb_describer_* enrichment from the per-service describers) to the
model as context, then matches each finding to a specific CB
knowledge entry. Claude Code must be on PATH and cbx-mcp must be
available on disk. Use --llm-max-cost to cap the per-run cost.`,
		Example: `  # Audit the default AWS profile in its configured region
  cbx audit aws

  # Audit a named profile across specific regions
  cbx audit aws prod --regions us-east-1,us-west-2

  # Fan out across every enabled region with IAM diagnostics
  cbx audit aws --regions all --diagnose`,
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

			// Live progress UI. Suppressed (no-op) on non-TTY / --quiet
			// / --json so machine-readable callers stay quiet. The UI
			// methods are safe to call regardless; wiring stays simple.
			ui := output.NewAWSDiscoveryUI()
			if interactive {
				ui.SetPhase("authenticating")
				ui.Start()
				defer ui.Done()
				discoverParams.OnProgress = func(ev awsdisc.ProgressEvent) {
					switch ev.Phase {
					case awsdisc.ProgressPhasePreflight:
						if ev.Identity != nil {
							ui.SetIdentity(ev.Identity.ARN)
						}
						ui.SetPhase("resolving regions")
					case awsdisc.ProgressPhaseRegions:
						ui.SetRegions(ev.Regions)
						ui.SetPhase("discovering resources")
					case awsdisc.ProgressPhaseScoutStart:
						ui.SetPhase("scouting regions for activity")
						ui.ScoutStart(ev.Total)
					case awsdisc.ProgressPhaseScoutRegionDone:
						ui.ScoutRegionDone(ev.Region, ev.Found, ev.Done, ev.Total)
					case awsdisc.ProgressPhaseScoutDone:
						ui.ScoutDone(ev.Regions)
						ui.SetRegions(ev.Regions)
						ui.SetPhase("discovering resources")
					case awsdisc.ProgressPhaseDiscoverStart:
						ui.SetTotalJobs(ev.Total)
					case awsdisc.ProgressPhaseJobStart:
						ui.JobStart(ev.Region, ev.Type)
					case awsdisc.ProgressPhaseEnrichProgress:
						ui.EnrichProgress(ev.Region, ev.Type, ev.Done, ev.Found)
					case awsdisc.ProgressPhaseJobDone:
						ui.JobDone(ev.Region, ev.Type, ev.Found, ev.Done, ev.Total)
					case awsdisc.ProgressPhaseDiscoverDone:
						ui.SetPhase("done")
					}
				}
			}

			ctx := context.Background()
			discResult, err := awsdisc.Discover(ctx, discoverParams)
			ui.Done()
			if err != nil {
				return err
			}

			// CB-grounded LLM analysis is always-on for `cbx audit aws`:
			// the value of the audit IS the grounding in CB's curated
			// knowledge, so the native-rules / mock-scanners path is no
			// longer reachable from the CLI. Library callers in cb-cli
			// can still construct different Options if they need to.
			opts := audit.Options{
				AWS:          true,
				AWSAccountID: discResult.Identity.AccountID,
				MockScanners: false,
				LLMProvider:  audit.ClaudeCodeProvider,
				CBKnowledge:  true,
				LLMMaxCost:   llmMaxCost,
				Quiet:        quietFlag,
				OutputFormat: outputFormat,
			}

			// RunFromResources collapses the previous bespoke flow
			// (CollectFromResources + group.Group + WriteFile) into one
			// entry point that cb-cli can call to get the same envelope
			// shape. The AWSAuditContext drives RenderAWSMarkdown so the
			// on-disk report carries the §7.7 + §7.12 audit header and
			// per-component finding sections. The AWS-specific stderr
			// decorations (preflight header, diagnose summary) remain
			// here in the subcommand since they're CLI-only.
			awsCtx := &audit.AWSAuditContext{
				AccountID:  discResult.Identity.AccountID,
				Identity:   discResult.Identity.ARN,
				Regions:    discResult.Regions,
				EventCount: discResult.EventCount,
			}
			result, runErr := audit.RunFromResources(opts, discResult.Resources, awsCtx)
			if runErr != nil && result == nil {
				return runErr
			}

			// Header. Goes to stderr so machine-readable output on stdout
			// stays unpolluted. The CloudTrail line is the v1 nod to
			// security-conscious users (plan §7.7) — they always ask
			// "how noisy is this in CloudTrail?" before running.
			if !quietFlag && outputFormat == "" {
				fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" AWS preflight ok"))
				fmt.Fprintln(os.Stderr, "  audited account:  "+discResult.Identity.AccountID)
				fmt.Fprintln(os.Stderr, "  identity:         "+discResult.Identity.ARN)
				fmt.Fprintln(os.Stderr, "  audited regions:  "+strings.Join(discResult.Regions, ", "))
				fmt.Fprintln(os.Stderr, fmt.Sprintf("  resources found:  %d", len(discResult.Resources)))
				fmt.Fprintln(os.Stderr, fmt.Sprintf("  note:             this run generated ~%d CloudTrail Read events", discResult.EventCount))
				renderComponentsSummary(os.Stderr, result.Components)
				if len(discResult.PermissionErr) > 0 {
					fmt.Fprintln(os.Stderr, fmt.Sprintf("  permission errors: %d (re-run with --diagnose for details)", len(discResult.PermissionErr)))
				}
				if len(discResult.OtherErrs) > 0 {
					fmt.Fprintln(os.Stderr, fmt.Sprintf("  other warnings:    %d", len(discResult.OtherErrs)))
				}
			}

			if outputFormat == "json" {
				payload := map[string]any{
					"identity":                  discResult.Identity,
					"regions":                   discResult.Regions,
					"resources_count":           len(discResult.Resources),
					"cloudtrail_events_estimate": discResult.EventCount,
					"findings":                  result.Findings,
					"components":        result.Components,
					"permission_errors": permErrsToJSON(discResult.PermissionErr),
				}
				return output.PrintJSON(payload, nil)
			}

			// Plain rendering
			label := fmt.Sprintf("aws://%s", discResult.Identity.AccountID)
			fmt.Print(audit.RenderPlain(result.Findings, label))

			// Diagnose summary (per-call permission errors + IAM patch)
			if diagnose && len(discResult.PermissionErr) > 0 {
				renderDiagnose(os.Stderr, discResult.PermissionErr, discResult.Identity.ARN)
			}

			if !quietFlag {
				fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" Wrote markdown report: "+result.ReportPath))
			}

			if severityErr := audit.ExitWithSeverity(result.Findings); severityErr != nil {
				return severityErr
			}
			if runErr != nil {
				return &audit.ExitCodeError{Code: 1}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&configFile, "config", "", "Path to an AWS credentials file (overrides profile resolution)")
	cmd.Flags().StringVar(&regions, "regions", "", "Comma-separated AWS regions (default: profile default region; 'all' for every enabled region)")
	cmd.Flags().StringVar(&regions, "region", "", "Alias for --regions (singular form)")
	cmd.Flags().IntVar(&awsConcurrency, "aws-concurrency", 4, "Max concurrent AWS API calls per service")
	cmd.Flags().BoolVar(&diagnose, "diagnose", false, "Emit per-call IAM permission errors and a recommended IAM policy patch")
	cmd.Flags().Float64Var(&llmMaxCost, "llm-max-cost", 0, "USD ceiling for a single grounded audit; the run is not aborted but a warning finding is emitted when claude's reported total_cost_usd exceeds the cap (0 = default $2.00)")

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

// renderComponentsSummary prints a one-line-per-kind summary of the
// component groupings. Quiet by design — full per-component listings go
// in the markdown report. Suppressed entirely when there are no
// components (the audit found nothing or had no resources to group).
func renderComponentsSummary(w *os.File, components []group.Component) {
	if len(components) == 0 {
		return
	}
	byKind := map[string]int{}
	for _, c := range components {
		byKind[c.Kind]++
	}
	for _, kind := range []string{"tag", "cb-primitive"} {
		if n := byKind[kind]; n > 0 {
			fmt.Fprintln(w, fmt.Sprintf("  components (%-12s): %d", kind, n))
		}
	}
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
