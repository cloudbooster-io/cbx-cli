package main

import (
	"fmt"
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if ec, ok := err.(*audit.ExitCodeError); ok {
			os.Exit(ec.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
