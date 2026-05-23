package cmd

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
			if output.JSON() {
				return output.PrintJSON(map[string]string{
					"version": Version,
					"commit":  Commit,
					"date":    Date,
				}, nil)
			}
			fmt.Printf("cbx version %s (commit: %s, built: %s)\n", Version, Commit, Date)
			return nil
		},
	}
}
