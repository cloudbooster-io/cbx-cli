package main

import (
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/telemetry"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/pkg/cmd"
)

func main() {
	// Capture in-flight panics for telemetry, then re-panic so the
	// runtime's default crash behaviour (stack trace + exit 2) wins.
	defer telemetry.Recover()
	os.Exit(cmd.ExitCode(cmd.Execute()))
}
