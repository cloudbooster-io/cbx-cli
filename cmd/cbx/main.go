package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/update"
)

func main() {
	root := newRootCmd()

	// Start background update check so it runs in parallel with the command.
	updateResult := make(chan *update.Result, 1)
	go func() {
		if update.IsDisabled() {
			close(updateResult)
			return
		}
		checker := update.NewChecker(version)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if result, err := checker.Check(ctx); err == nil {
			updateResult <- result
		}
		close(updateResult)
	}()

	if err := root.Execute(); err != nil {
		if ec, ok := err.(*audit.ExitCodeError); ok {
			os.Exit(ec.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Show update banner at command end if applicable.
	select {
	case result := <-updateResult:
		if result != nil && result.HasUpdate && shouldShowUpdateBanner() {
			fmt.Fprintf(os.Stderr, "\nA new version of cbx is available: %s → %s\nRun `cbx upgrade` to update.\n", version, result.LatestVersion)
		}
	default:
		// Check hasn't completed yet; don't wait.
	}
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
