package main

import (
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/pkg/cmd"
)

func main() {
	os.Exit(cmd.ExitCode(cmd.Execute()))
}
