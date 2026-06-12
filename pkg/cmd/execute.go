package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
	"github.com/cloudbooster-io/cbx-cli/internal/telemetry"
	"github.com/cloudbooster-io/cbx-cli/internal/update"
	"github.com/spf13/cobra"
)

// beautifyCobraError rewrites the bare cobra error strings (unknown
// command, unknown flag) into a structured ErrorDetail so the user
// sees the same red-gutter error block as everywhere else. Unknown
// commands gain a list of suggested closest matches when cobra
// computed any. Errors that don't match either pattern fall through
// unchanged.
func beautifyCobraError(root *cobra.Command, err error) error {
	if err == nil {
		return err
	}
	msg := err.Error()

	// "unknown command \"X\" for \"cbx ...\""
	if strings.HasPrefix(msg, "unknown command ") {
		name := extractQuoted(msg)
		suggestions := root.SuggestionsFor(name)
		fix := "run `cbx --help` to see available commands"
		if len(suggestions) > 0 {
			fix = "did you mean: " + strings.Join(suggestions, ", ") + "? (or run `cbx --help`)"
		}
		return output.NewError(output.ErrorDetail{
			What: fmt.Sprintf("%s is not a cbx command", quote(name)),
			Why:  "no command, alias, or subcommand matches that name",
			Fix:  fix,
			Code: "E_UNKNOWN_COMMAND",
		})
	}
	// "unknown flag: --bogus" / "unknown shorthand flag: 'x' in -x"
	if strings.HasPrefix(msg, "unknown flag:") || strings.HasPrefix(msg, "unknown shorthand flag:") {
		return output.NewError(output.ErrorDetail{
			What: msg,
			Why:  "cbx didn't recognise that flag for the command you ran",
			Fix:  "run the command with --help to see its flags (e.g. `cbx audit aws --help`)",
			Code: "E_UNKNOWN_FLAG",
		})
	}
	return err
}

// extractQuoted pulls the first double-quoted segment out of s, used to
// extract the offending command name from cobra's error messages.
func extractQuoted(s string) string {
	i := strings.Index(s, "\"")
	if i < 0 {
		return s
	}
	j := strings.Index(s[i+1:], "\"")
	if j < 0 {
		return s[i+1:]
	}
	return s[i+1 : i+1+j]
}

func quote(s string) string { return "\"" + s + "\"" }

// renderUpdateBanner builds the end-of-run "update available" card. Goes
// to stderr, suppressed under quiet/JSON/CI by shouldShowUpdateBanner.
// The chip + dim arrow + accent on the new version reads at a glance,
// and the footer suggests the exact command to run.
func renderUpdateBanner(current, latest string) string {
	from := output.Dim.Render(current)
	arrow := output.Dim.Render(" " + output.Symbol("arrow") + " ")
	to := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42")).Render(latest)
	if !output.Enabled() {
		to = latest
	}
	card := output.Card{
		Label: output.Chip("UPDATE", lipgloss.Color("231"), lipgloss.Color("22")),
		Title: "new cbx release available",
		Rows: []output.CardRow{
			{Key: "version", Value: from + arrow + to},
		},
		Footer: output.Dim.Render(output.Symbol("arrow")+" run ") +
			"cbx upgrade" +
			output.Dim.Render(" to install"),
	}
	return card.Render()
}

// Execute builds the root command, runs the background update check, executes
// the CLI, and displays the update banner if applicable.
func Execute() error {
	// Suppress the legacy-config nudge for commands where it would be noise
	// (version/help/completion/--json/--quiet/-o json). Done before any
	// config.Dir() call by swapping the configurable nudge sink. The
	// sentinel-once guard still protects everything else.
	if !shouldNudgeLegacyConfig() {
		config.LegacyConfigNudge = func(legacy, modern string) {}
	}

	root := NewRootCmd()

	// Start background update check so it runs in parallel with the command.
	// Skip entirely when the banner would be suppressed anyway (saves a
	// network round-trip + battery on every short-lived invocation).
	updateResult := make(chan *update.Result, 1)
	go func() {
		if update.IsDisabled() || !shouldRunUpdateCheck() {
			close(updateResult)
			return
		}
		checker := update.NewChecker(Version)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if result, err := checker.Check(ctx); err == nil {
			updateResult <- result
		}
		close(updateResult)
	}()

	err := root.Execute()
	err = beautifyCobraError(root, err)

	// Flush any advisories the run accumulated but didn't render inline.
	// Audit's RenderPlain drains its own; this catches notices buffered
	// by other commands (cbx config / cbx llm) so they still
	// surface to the user instead of vanishing at process exit.
	if !quietFlag && !output.JSON() {
		if adv := output.FlushAdvisories(); adv != "" {
			fmt.Fprint(os.Stderr, "\n"+adv)
		}
	}

	// Report the error to Sentry (no-op when telemetry is disabled).
	// Exit-code carriers (--llm cost warning, severity-based exits)
	// are not real failures — skip those to keep the dashboard clean.
	if err != nil {
		var exitErr *audit.ExitCodeError
		if !errors.As(err, &exitErr) {
			telemetry.CaptureError(err)
		}
	}
	// Flush before returning so the OS exit doesn't drop in-flight
	// events. 2s is the same ceiling sentry-go uses in its examples.
	telemetry.Flush(2 * time.Second)

	// Show update banner at command end if applicable.
	select {
	case result := <-updateResult:
		if result != nil && result.HasUpdate && shouldShowUpdateBanner() {
			fmt.Fprint(os.Stderr, "\n"+renderUpdateBanner(Version, result.LatestVersion))
		}
	default:
		// Check hasn't completed yet; don't wait.
	}

	return err
}

// ExitCode translates an error returned by Execute into an OS exit code.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *audit.ExitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	// Under --output json the error must land in the Envelope on stdout —
	// machine consumers never see the styled card. Structured errors carry
	// their what/why/fix/code through; plain errors become a bare message.
	if output.JSON() {
		var detailErr *output.DetailError
		if errors.As(err, &detailErr) {
			d := detailErr.Detail
			_ = output.PrintJSON(nil, &output.ErrDetail{
				Code:    d.Code,
				Message: d.What,
				Why:     d.Why,
				Fix:     d.Fix,
			})
		} else {
			_ = output.PrintJSON(nil, output.JSONError(err))
		}
		return 1
	}
	fmt.Fprintln(os.Stderr, err)
	return 1
}

// shouldRunUpdateCheck is a best-effort heuristic over os.Args (cobra hasn't
// parsed yet at the time Execute fires the background goroutine). When the
// banner would never display, the network call is wasted — skip it. False
// positives are fine (we just do an extra round-trip the user won't see);
// false negatives are also fine (we miss a banner once).
func shouldRunUpdateCheck() bool {
	args := os.Args
	if len(args) < 2 {
		return true
	}
	// Walk past program name; first non-flag arg is the subcommand.
	for _, a := range args[1:] {
		switch a {
		case "--json", "-q", "--quiet":
			return false
		}
		if a == "-o" || a == "--output" {
			// Conservative: assume the next token is "json"-shaped and
			// skip. We don't bother indexing because output-as-json
			// suppresses the banner unconditionally downstream.
			return false
		}
		if strings.HasPrefix(a, "--output=") || strings.HasPrefix(a, "-o=") {
			return false
		}
	}
	// Find first positional (subcommand).
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		switch a {
		case "version", "upgrade", "completion", "help":
			return false
		}
		break
	}
	return true
}

// shouldNudgeLegacyConfig decides whether the one-time legacy-config-dir
// nudge is appropriate for the current invocation. Mirrors the heuristic
// used by shouldRunUpdateCheck: skip for version/help/completion, and for
// machine-output / quiet modes where the message would just be noise on
// stderr that the user did not opt into.
func shouldNudgeLegacyConfig() bool {
	args := os.Args
	if len(args) < 2 {
		return true
	}
	for _, a := range args[1:] {
		switch a {
		case "--json", "-q", "--quiet", "--version", "-v", "-h", "--help":
			return false
		}
		if a == "-o" || a == "--output" {
			return false
		}
		if strings.HasPrefix(a, "--output=") || strings.HasPrefix(a, "-o=") {
			return false
		}
	}
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		switch a {
		case "version", "help", "completion":
			return false
		}
		break
	}
	return true
}

func shouldShowUpdateBanner() bool {
	if os.Getenv("CI") == "true" || config.Env("NO_UPDATE_CHECK") == "1" {
		return false
	}
	if quietFlag || output.JSON() {
		return false
	}
	if executedCommand == "upgrade" || executedCommand == "version" {
		return false
	}
	return true
}
