package main

import (
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/telemetry"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/pkg/cmd"
)

func main() {
	// Bake the ldflags-injected version into the auth User-Agent so the
	// CloudBooster Devices panel renders ``cbx-cli/<ver> (<os>/<arch>)``
	// instead of the default ``Go-http-client/1.1``.
	auth.SetVersion(cmd.Version)

	// Capture in-flight panics for telemetry, then re-panic so the
	// runtime's default crash behaviour (stack trace + exit 2) wins.
	defer telemetry.Recover()
	os.Exit(cmd.ExitCode(cmd.Execute()))
}
