package main

import (
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

var (
	version   = "dev"
	commit    = "unknown"
	date      = "unknown"
	jsonFlag  bool
	quietFlag bool
	noTUI     bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cbx",
		Short: "CloudBooster CLI — plan, audit, and manage cloud infrastructure",
		Long: `cbx is the CloudBooster CLI for planning cloud infrastructure,
auditing existing deployments, and interacting with the CloudBooster platform.`,
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.SetHelpTemplate(output.HelpTemplate())
	root.SetUsageTemplate(output.UsageTemplate())

	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output in JSON format")
	root.PersistentFlags().BoolVar(&quietFlag, "quiet", false, "Suppress non-error output")
	root.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive mode without TUI")

	root.AddCommand(
		newVersionCmd(),
		newDoctorCmd(),
		newLoginCmd(),
		newLogoutCmd(),
		newStatusCmd(),
		newLLMCmd(),
		newKnowledgeCmd(),
		newPlanCmd(),
		newAuditCmd(),
		newUpgradeCmd(),
	)

	return root
}
