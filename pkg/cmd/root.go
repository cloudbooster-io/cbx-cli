package cmd

import (
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

var (
	Version     = "dev"
	Commit      = "unknown"
	Date        = "unknown"
	jsonFlag    bool
	quietFlag   bool
	noTUI       bool
	noColorFlag bool
)

// executedCommand tracks which subcommand was run (used by background update check).
var executedCommand string

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cbx",
		Short: "CloudBooster CLI — plan, audit, and manage cloud infrastructure",
		Long: `cbx is the CloudBooster CLI for planning cloud infrastructure,
auditing existing deployments, and interacting with the CloudBooster platform.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			output.Configure(noColorFlag, quietFlag)
			executedCommand = cmd.Name()
			return nil
		},
	}

	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output in JSON format")
	root.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "Suppress non-error output")
	root.PersistentFlags().BoolVar(&noTUI, "no-tui", false, "Use non-interactive mode without TUI")
	root.PersistentFlags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")

	output.InstallHelpTemplate(root)

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
		newEnvCmd(),
	)

	return root
}
