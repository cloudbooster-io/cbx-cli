package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/telemetry"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/update"
)

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

	// Report the error to Sentry (no-op when telemetry is disabled).
	// Exit-code carriers (--llm cost warning, severity-based exits)
	// are not real failures — skip those to keep the dashboard clean.
	if err != nil {
		if _, isExitCode := err.(*audit.ExitCodeError); !isExitCode {
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
			fmt.Fprintf(os.Stderr, "\nA new version of cbx is available: %s → %s\nRun `cbx upgrade` to update.\n", Version, result.LatestVersion)
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
	if ec, ok := err.(*audit.ExitCodeError); ok {
		return ec.Code
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
