package main

import (
	"fmt"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of cbx",
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonFlag {
				return output.PrintJSON(map[string]string{
					"version": version,
					"commit":  commit,
					"date":    date,
				}, nil)
			}
			fmt.Printf("cbx version %s (commit: %s, built: %s)\n", version, commit, date)
			return nil
		},
	}
}
