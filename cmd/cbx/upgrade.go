package main

import (
	"errors"

	"github.com/spf13/cobra"
)

func newUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade cbx to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}
