package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/telemetry"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/update"
)

// Execute builds the root command, runs the background update check, executes
// the CLI, and displays the update banner if applicable.
func Execute() error {
	root := NewRootCmd()

	// Start background update check so it runs in parallel with the command.
	updateResult := make(chan *update.Result, 1)
	go func() {
		if update.IsDisabled() {
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

func shouldShowUpdateBanner() bool {
	if os.Getenv("CI") == "true" || os.Getenv("CB_NO_UPDATE_CHECK") == "1" {
		return false
	}
	if quietFlag || jsonFlag {
		return false
	}
	if executedCommand == "upgrade" || executedCommand == "version" {
		return false
	}
	return true
}
