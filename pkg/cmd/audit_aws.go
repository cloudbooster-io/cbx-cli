package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
	awsdisc "github.com/cloudbooster-io/cbx-cli/internal/audit/discover/aws"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/group"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
	audittui "github.com/cloudbooster-io/cbx-cli/internal/tui/audit"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// newAuditAWSCmd builds the `cbx audit aws [profile]` subcommand. It's a
// child of `audit`, registered in newAuditCmd. Lives in its own file to
// keep the parent audit.go from sprawling — the live-AWS surface is large
// enough to deserve its own home.
func newAuditAWSCmd() *cobra.Command {
	var (
		credentialsFile string
		regions         []string
		regionsCSV      string
		awsConcurrency  int
		diagnose        bool
		llmMaxCost      float64
		dryRun          bool
		noTUI           bool
	)

	cmd := &cobra.Command{
		Use:     "aws [profile|console-url]",
		Aliases: []string{"a"},
		Short:   "Audit a live AWS account",
		Long: `Audit a live AWS account directly via the AWS SDK.

Credentials come from the default SDK credential chain or an explicit
profile / credentials file. Resolution precedence for the profile
(highest wins):

  1. --credentials-file <path> — explicit credentials file
  2. positional [profile] — named profile in ~/.aws/credentials
  3. AWS_PROFILE env var
  4. "default" profile

The positional argument may also be an AWS console URL (e.g.
https://us-east-1.console.aws.amazon.com/...); the region is parsed
from the hostname and used as a default. Explicit --region values
still win.

Region resolution: if --region is omitted, the profile's configured
region is used. If the profile has no region and you're on a TTY, an
interactive picker shows enabled regions. In non-interactive mode
(--output json, --quiet, or no TTY) you must pass --region.

Use --region all to fan out across every enabled region in the account.

Discovery uses the CloudControl API across a curated set of CFN types
(see internal/audit/discover/aws/types_to_query.go). Per-resource
permission errors are aggregated and surfaced cleanly; pass --diagnose
to print every denied API call plus a recommended IAM policy patch.

Findings are always grounded in CloudBooster's curated AWS knowledge.
This is not optional: the audit fetches the relevant CB knowledge (AWS
primitives, best practices, and composition guidance) directly over
CloudBooster's knowledge API, then inlines it into the prompt alongside
the discovered resources (plus cb_describer_* enrichment from the
per-service describers) and runs Claude Code (` + "`claude -p`" + `) to match
each finding to that grounding. Claude Code must be on PATH. Use
--llm-max-cost to cap the per-run cost (USD; default 2.00).`,
		Example: `  # Audit the default AWS profile in its configured region
  cbx audit aws

  # Audit a named profile across specific regions (repeatable)
  cbx audit aws prod --region us-east-1 --region us-west-2

  # Audit using an AWS console URL (region parsed from hostname)
  cbx audit aws https://us-east-1.console.aws.amazon.com/console/home

  # Fan out across every enabled region with IAM diagnostics
  cbx audit aws --region all --diagnose

  # Print the audit plan and exit without firing CloudControl/LLM
  cbx audit aws --dry-run`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := os.Getenv("AWS_PROFILE")
			var urlRegion string
			if len(args) == 1 {
				if r, _, ok := parseConsoleURL(args[0]); ok {
					urlRegion = r
					// Profile resolution falls through; the console URL
					// carries no profile, only region.
				} else {
					profile = args[0]
				}
			}

			// Merge --region (repeatable) and --regions (CSV alias). The
			// repeatable form is canonical; the CSV form is kept hidden
			// for back-compat with scripts written against the prior
			// release. Dedupe to keep --region us-east-1 --regions
			// us-east-1 from double-counting.
			regionList := mergeRegions(regions, regionsCSV)
			if len(regionList) == 0 && urlRegion != "" {
				regionList = []string{urlRegion}
			}
			// Persistent fallback: `cbx config set aws.default_region us-east-1`
			// wins over the SDK profile picker and the interactive prompt,
			// but still loses to any explicit --region / console-URL.
			if len(regionList) == 0 {
				if cfg, err := config.Load(); err == nil && cfg.AWS.DefaultRegion != "" {
					regionList = []string{cfg.AWS.DefaultRegion}
				}
			}

			if awsConcurrency < 1 {
				awsConcurrency = 4
			}

			outputFormat := ""
			if output.JSON() {
				outputFormat = "json"
			}
			interactive := isatty.IsTerminal(os.Stdin.Fd()) &&
				isatty.IsTerminal(os.Stdout.Fd()) &&
				outputFormat == "" &&
				!quietFlag

			discoverParams := awsdisc.DiscoverParams{
				Profile:         profile,
				CredentialsFile: credentialsFile,
				Regions:         regionList,
				Concurrency:     awsConcurrency,
				Diagnose:        diagnose,
				ScoutOnly:       dryRun,
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

			// --dry-run short-circuit: print the audit plan and exit
			// before any CloudControl Discover or LLM invocation. Scout
			// has already run (and is the heaviest preflight step) so
			// the user gets the same region/account picture they'd see
			// in a real run.
			if dryRun {
				return renderDryRun(outputFormat, discResult, discoverParams)
			}

			// Discovery header card — what we just learned about the
			// account, rendered before grounding so the user sees their
			// audit context immediately rather than after a silent
			// LLM pause.
			if !quietFlag && outputFormat == "" {
				fmt.Fprint(os.Stderr, renderDiscoveryCard(discResult))
				fmt.Fprintln(os.Stderr)
			}

			// Move non-fatal discovery warnings into the advisories
			// buffer so they surface in the end-of-run card instead of
			// inline noise above the findings.
			if len(discResult.PermissionErr) > 0 {
				output.Advise(output.Advisory{
					Code:  "aws-permission-errors",
					Title: fmt.Sprintf("%d AWS permission errors during discovery", len(discResult.PermissionErr)),
					Hint:  "cbx audit aws --diagnose",
				})
			}
			if len(discResult.OtherErrs) > 0 {
				output.Advise(output.Advisory{
					Code:  "aws-discovery-warnings",
					Title: fmt.Sprintf("%d non-fatal warnings during discovery", len(discResult.OtherErrs)),
				})
			}

			// CB-grounded LLM analysis is always-on for `cbx audit aws`:
			// the value of the audit IS the grounding in CB's curated
			// knowledge, so the native-rules / mock-scanners path is no
			// longer reachable from the CLI. Library callers in downstream consumers
			// can still construct different Options if they need to.
			opts := audit.Options{
				AWS:               true,
				AWSAccountID:      discResult.Identity.AccountID,
				AWSAccountPosture: discResult.AccountPosture,
				MockScanners:      false,
				LLMProvider:       audit.ClaudeCodeProvider,
				CBKnowledge:       true,
				LLMMaxCost:        llmMaxCost,
				Quiet:             quietFlag,
				OutputFormat:      outputFormat,
			}

			// RunFromResources collapses the previous bespoke flow
			// (CollectFromResources + group.Group + WriteFile) into one
			// entry point that downstream consumers can call to get the same envelope
			// shape. The AWSAuditContext drives RenderAWSMarkdown so the
			// on-disk report carries the §7.7 + §7.12 audit header and
			// per-component finding sections. The AWS-specific stderr
			// decorations (preflight header, diagnose summary) remain
			// here in the subcommand since they're CLI-only.
			awsCtx := &audit.AWSAuditContext{
				AccountID:      discResult.Identity.AccountID,
				Identity:       discResult.Identity.ARN,
				CallerARN:      discResult.Identity.ARN,
				Regions:        discResult.Regions,
				EventCount:     discResult.EventCount,
				AccountPosture: discResult.AccountPosture,
			}

			// Grounding-phase spinner. RunFromResources spawns claude -p
			// under the hood; without this the user sees the discovery
			// header, then dead silence, then findings — and reasonably
			// assumes the audit has hung. Suppressed on --quiet / --json
			// so machine consumers aren't polluted with ANSI cursor games.
			var groundingSpinner *output.Spinner
			if !quietFlag && outputFormat == "" {
				groundingSpinner = output.NewSpinner("grounding findings against CloudBooster knowledge")
				groundingSpinner.Start()
			}
			result, runErr := audit.RunFromResources(opts, discResult.Resources, awsCtx)
			if groundingSpinner != nil {
				groundingSpinner.Stop()
			}
			if runErr != nil && result == nil {
				return runErr
			}

			// One-line component summary right after grounding so the
			// user knows the LLM ran and what it grouped resources into.
			if !quietFlag && outputFormat == "" && result != nil {
				fmt.Fprintln(os.Stderr, renderGroundingSummary(result.Components))
			}

			if output.JSON() {
				payload := map[string]any{
					"identity":                   discResult.Identity,
					"regions":                    discResult.Regions,
					"resources_count":            len(discResult.Resources),
					"cloudtrail_events_estimate": discResult.EventCount,
					"findings":                   result.Findings,
					"components":                 result.Components,
					"permission_errors":          permErrsToJSON(discResult.PermissionErr),
				}
				if err := output.PrintJSON(payload, nil); err != nil {
					return err
				}
				// JSON mode must still signal severity/partial-failure via the
				// exit code, exactly like the human path below — otherwise
				// `cbx audit aws --json` always exits 0 even on critical findings.
				if severityErr := audit.ExitWithSeverity(result.Findings); severityErr != nil {
					return severityErr
				}
				if runErr != nil {
					return &audit.ExitCodeError{Code: 1}
				}
				return nil
			}

			// Plain rendering. The label is the "stateFile" identifier
			// RenderPlain uses to derive the report path — keep the
			// "aws://<accountID>" form so reportFileFor() produces
			// "<accountID>_audit_report.md", matching what the runner
			// wrote. (Passing result.ReportPath here would double the
			// suffix and produce a broken OSC-8 link.)
			label := fmt.Sprintf("aws://%s", discResult.Identity.AccountID)
			fmt.Print(audit.RenderPlain(result.Findings, label))

			// Diagnose summary (per-call permission errors + IAM patch)
			if diagnose && len(discResult.PermissionErr) > 0 {
				renderDiagnose(os.Stderr, discResult.PermissionErr, discResult.Identity.ARN)
			}

			// Interactive TUI takeover. The static report already
			// printed above, so the TUI runs on the alt-screen — on
			// exit, the user is back in their shell with the static
			// output preserved in scrollback. Suppressed on --no-tui,
			// --json, --quiet, and non-TTY paths so machine consumers
			// stay quiet and CI never spawns a Bubble Tea program.
			if interactive && !noTUI && len(result.Findings) > 0 {
				ctxLine := fmt.Sprintf("AWS · %s · %s", discResult.Identity.AccountID, strings.Join(discResult.Regions, ", "))
				if name := bestAccountLabel(discResult.Identity, os.Getenv("AWS_PROFILE")); name != "" {
					ctxLine = fmt.Sprintf("AWS · %s (%s) · %s", discResult.Identity.AccountID, name, strings.Join(discResult.Regions, ", "))
				}
				model := audittui.NewModel(result.Findings).
					WithContext(ctxLine).
					WithReportPath(result.ReportPath).
					WithHTMLReportPath(result.HTMLReportPath)
				p := tea.NewProgram(model, tea.WithAltScreen())
				if _, err := p.Run(); err != nil {
					// TUI failure shouldn't fail the audit — the static
					// findings already printed. Surface as advisory.
					output.Advise(output.Advisory{
						Code:  "audit-tui-failed",
						Title: "interactive viewer failed: " + err.Error(),
						Hint:  "pass --no-tui to suppress",
					})
				}
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

	cmd.Flags().StringVar(&credentialsFile, "credentials-file", "", "Path to an AWS shared credentials file (overrides profile resolution)")
	// Hidden deprecated alias for --credentials-file. MarkDeprecated
	// emits a one-time stderr warning automatically.
	cmd.Flags().StringVar(&credentialsFile, "config", "", "Deprecated alias for --credentials-file")
	_ = cmd.Flags().MarkDeprecated("config", "use --credentials-file")
	_ = cmd.Flags().MarkHidden("config")

	cmd.Flags().StringSliceVar(&regions, "region", nil, "AWS region (repeatable, e.g. --region us-east-1 --region us-west-2; 'all' fans out across every enabled region)")
	// Back-compat: --regions <csv> stays callable for users who scripted
	// it, but is hidden from --help to keep the new surface clean.
	cmd.Flags().StringVar(&regionsCSV, "regions", "", "Comma-separated AWS regions (deprecated, use --region)")
	_ = cmd.Flags().MarkHidden("regions")

	cmd.Flags().IntVar(&awsConcurrency, "aws-concurrency", 4, "Max concurrent AWS API calls per service")
	cmd.Flags().BoolVar(&diagnose, "diagnose", false, "Emit per-call IAM permission errors and a recommended IAM policy patch")
	cmd.Flags().Float64Var(&llmMaxCost, "llm-max-cost", 2.0, "USD ceiling for a single grounded audit; a warning finding is emitted when claude's reported total_cost_usd exceeds the cap. 0 disables the cap")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the audit plan (regions, CFN types, est events, dependency checks) and exit without firing CloudControl or LLM calls")
	cmd.Flags().BoolVar(&noTUI, "no-tui", false, "Skip the interactive findings TUI — print the static report and exit. Implied by --json, --quiet, and non-TTY.")

	return cmd
}

// mergeRegions combines the repeatable --region flag values with the
// hidden CSV --regions value, trimming and de-duplicating. Order from
// --region is preserved; CSV entries are appended after.
func mergeRegions(repeatable []string, csv string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(r string) {
		r = strings.TrimSpace(r)
		if r == "" {
			return
		}
		if _, ok := seen[r]; ok {
			return
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	// StringSliceVar splits on commas internally, so --region us-east-1,us-west-2
	// also works; iterate as-is.
	for _, r := range repeatable {
		// Defensive split in case the user passes a CSV inside one
		// --region — keeps behavior identical to the prior --regions.
		for _, sub := range strings.Split(r, ",") {
			add(sub)
		}
	}
	for _, r := range strings.Split(csv, ",") {
		add(r)
	}
	return out
}

// parseConsoleURL returns (region, accountID, true) when arg is an HTTPS
// URL pointing at the AWS console. Region is extracted from the host
// subdomain (e.g. us-east-1.console.aws.amazon.com → us-east-1). Account
// ID is not currently parsed from console URLs (the format is
// inconsistent — sometimes in the path, sometimes the query, sometimes
// absent) so the second return is reserved for future use.
func parseConsoleURL(arg string) (region, accountID string, ok bool) {
	if !strings.HasPrefix(arg, "https://") && !strings.HasPrefix(arg, "http://") {
		return "", "", false
	}
	u, err := url.Parse(arg)
	if err != nil {
		return "", "", false
	}
	host := u.Hostname()
	// Accept both regional (us-east-1.console.aws.amazon.com) and the
	// global landing (console.aws.amazon.com). Anything else is treated
	// as a non-console URL → fall through to profile-name handling.
	if !(host == "console.aws.amazon.com" || strings.HasSuffix(host, ".console.aws.amazon.com")) {
		return "", "", false
	}
	// The hostname is one of:
	//   <region>.console.aws.amazon.com
	//   console.aws.amazon.com
	//   <account>-<alias>.<region>.console.aws.amazon.com (SSO start URL)
	parts := strings.Split(host, ".")
	// Find the index of "console" — the segment immediately before it
	// (if any) is the region.
	for i, p := range parts {
		if p == "console" && i > 0 {
			candidate := parts[i-1]
			// Region segments are lowercase letters/digits/dashes; reject
			// obvious non-regions (e.g. SSO portal names).
			if isLikelyAWSRegion(candidate) {
				region = candidate
			}
			break
		}
	}
	return region, "", true
}

// isLikelyAWSRegion is a cheap shape check (xx-yyyy-N). Avoids pulling
// the full SDK region list just to validate a hostname segment.
func isLikelyAWSRegion(s string) bool {
	if len(s) < 9 || len(s) > 20 {
		return false
	}
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return false
	}
	last := parts[len(parts)-1]
	if len(last) == 0 {
		return false
	}
	for _, r := range last {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// renderDryRun prints (to stdout-as-JSON or stderr-as-text) the audit
// plan and returns nil. Called when --dry-run is set; the discover step
// has already run with ScoutOnly=true so we have the resolved regions
// and an accurate event-count estimate, but no CloudControl traffic
// fired and no LLM was invoked.
func renderDryRun(outputFormat string, dr *awsdisc.DiscoverResult, _ awsdisc.DiscoverParams) error {
	_, claudeErr := exec.LookPath("claude")
	claudeOK := claudeErr == nil
	cfnCount := awsdisc.DiscoverableTypeCount()

	if outputFormat == "json" {
		payload := map[string]any{
			"dry_run":                    true,
			"identity":                   dr.Identity,
			"regions":                    dr.Regions,
			"cfn_type_count":             cfnCount,
			"cloudtrail_events_estimate": dr.EventCount,
			"claude_cli_available":       claudeOK,
		}
		return output.PrintJSON(payload, nil)
	}

	fmt.Fprintln(os.Stderr, output.Success.Render(output.Symbol("check")+" Dry run — audit plan"))
	acct := dr.Identity.AccountID
	if name := bestAccountLabel(dr.Identity, os.Getenv("AWS_PROFILE")); name != "" {
		acct += " (" + name + ")"
	}
	fmt.Fprintln(os.Stderr, "  account:           "+acct)
	fmt.Fprintln(os.Stderr, "  identity:          "+dr.Identity.ARN)
	fmt.Fprintln(os.Stderr, "  regions:           "+strings.Join(dr.Regions, ", "))
	fmt.Fprintf(os.Stderr, "  CFN types queried: %d\n", cfnCount)
	fmt.Fprintf(os.Stderr, "  est CloudTrail Read events: ~%d\n", dr.EventCount)
	fmt.Fprintf(os.Stderr, "  claude CLI on PATH: %v\n", claudeOK)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "(no CloudControl Discover or LLM calls were made)")
	return nil
}

// renderDiscoveryCard builds the framed AWS discovery summary printed to
// stderr after preflight + discovery and before LLM grounding. Replaces
// the prior six `fmt.Fprintln` lines so the header reads as a single
// visual unit with an "AWS" chip up top.
func renderDiscoveryCard(dr *awsdisc.DiscoverResult) string {
	title := "audit · " + dr.Identity.AccountID
	if name := bestAccountLabel(dr.Identity, os.Getenv("AWS_PROFILE")); name != "" {
		title += " · " + name
	}
	card := output.Card{
		Label: output.Chip("AWS", lipgloss.Color("231"), lipgloss.Color("236")),
		Title: title,
	}
	card.AddRow("identity", shortenIdentity(dr.Identity.ARN))
	card.AddRow("regions", strings.Join(dr.Regions, ", "))
	card.AddRow("resources", fmt.Sprintf("%d", len(dr.Resources)))
	card.AddRow("CloudTrail", output.Dim.Render(
		fmt.Sprintf("~%d Read events generated by this run", dr.EventCount)))
	card.Footer = "grounded in CloudBooster knowledge"
	return card.Render()
}

// bestAccountLabel returns the friendliest account name we can derive.
// Precedence: IAM account alias (set via iam:CreateAccountAlias) > a
// sanitized fragment of the AWS profile name (the part between the
// first ':' and the first '/' — e.g. "CB:platform-testing-customer4/
// AdministratorAccess" → "platform-testing-customer4"). Empty when
// nothing useful is available. The profile fragment is purely a
// client-side label, not authoritative for the account, but it's the
// only place a human-readable name exists when the alias is unset.
func bestAccountLabel(id awsdisc.Identity, profile string) string {
	if id.AccountAlias != "" {
		return id.AccountAlias
	}
	return profileFriendlyName(profile)
}

// profileFriendlyName extracts the human fragment from an AWS profile
// name that follows the "<org>:<account-name>/<role>" convention
// (common for SSO-managed profiles). Returns "" for unrecognised
// shapes — we don't want to print a confusing partial string when the
// profile doesn't follow the convention.
func profileFriendlyName(profile string) string {
	if profile == "" {
		return ""
	}
	colon := strings.Index(profile, ":")
	if colon < 0 {
		return ""
	}
	rest := profile[colon+1:]
	if slash := strings.Index(rest, "/"); slash >= 0 {
		return rest[:slash]
	}
	return rest
}

// renderGroundingSummary returns a single dim status line summarising
// the LLM grouping pass: total component count plus per-kind breakdown.
// Empty result is rendered as a "no components" hint so the user knows
// grouping actually ran.
func renderGroundingSummary(components []group.Component) string {
	if len(components) == 0 {
		return output.Dim.Render("  " + output.Symbol("arrow") + " grounded · no components extracted")
	}
	byKind := map[string]int{}
	for _, c := range components {
		byKind[c.Kind]++
	}
	parts := []string{}
	for _, kind := range []string{"tag", "cb-primitive"} {
		if n := byKind[kind]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, kind))
		}
	}
	detail := strings.Join(parts, " · ")
	if detail == "" {
		detail = fmt.Sprintf("%d components", len(components))
	}
	return output.Dim.Render(
		fmt.Sprintf("  %s grounded · %d components (%s)",
			output.Symbol("arrow"), len(components), detail))
}

// shortenIdentity trims long SSO/role ARNs so the discovery header card
// stays readable. We keep the role name + assumed-user suffix and middle-
// elide the rest. ARNs that fit untouched pass through unchanged.
func shortenIdentity(arn string) string {
	if len(arn) <= 80 {
		return arn
	}
	parts := strings.Split(arn, "/")
	if len(parts) < 2 {
		return arn
	}
	tail := strings.Join(parts[len(parts)-2:], "/")
	return ".../" + tail
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
		fmt.Fprintf(w, "  %s %-40s → AccessDenied (in %s)\n", output.Symbol("cross"), e.Action, region)
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
