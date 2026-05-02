package main

import (
	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = "unknown"
	date      = "unknown"
	jsonFlag  bool
	quietFlag bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cbx",
		Short: "CloudBooster CLI — plan, audit, and manage cloud infrastructure",
		Long: `cbx is the CloudBooster CLI for planning cloud infrastructure,
auditing existing deployments, and interacting with the CloudBooster platform.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output in JSON format")
	root.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "Suppress non-error output")

	root.AddCommand(
		newVersionCmd(),
		newDoctorCmd(),
		newLoginCmd(),
		newLogoutCmd(),
		newStatusCmd(),
		newLLMCmd(),
		newPlanCmd(),
		newAuditCmd(),
	)

	return root
}
