package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

func newEnvCmd() *cobra.Command {
	env := &cobra.Command{
		Use:     "env",
		Aliases: []string{"envs"},
		Short:   "Manage and inspect environments",
		Long:    `List environments, view status, cost, drift, and logs.`,
		// Hidden until the API surface ships; the RunE stubs return
		// "not implemented" and pollute --help for first-time users.
		Hidden: true,
	}
	env.AddCommand(
		newEnvListCmd(),
		newEnvStatusCmd(),
	)
	return env
}

func newEnvListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List environments for the current project",
		Hidden:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}

func newEnvStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "status <env-id>",
		Short:  "Show high-level status for an environment",
		Hidden: true,
		Args:   RequireExactlyOneArg("env-id", "cbx env status <env-id>"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}
