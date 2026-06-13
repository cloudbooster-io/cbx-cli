package cmd

import (
	"github.com/spf13/cobra"
)

// newAuthCmd builds the `cbx auth` parent group that mirrors the
// top-level login/logout/status verbs. The top-level forms remain
// the stable API; the parent exists so users who type `cbx auth …`
// (the convention in many other CLIs) find what they expect.
//
// Both forms delegate to the same runLogin/runLogout/runStatus
// helpers in login.go, so behaviour stays single-sourced.
func newAuthCmd() *cobra.Command {
	auth := &cobra.Command{
		Use:   "auth",
		Short: "Manage CloudBooster authentication",
		Long: `Manage CloudBooster authentication.

These subcommands mirror the top-level cbx login / logout / status
verbs and share the same implementation.`,
	}
	auth.AddCommand(
		newAuthLoginCmd(),
		newAuthLogoutCmd(),
		newAuthStatusCmd(),
	)
	return auth
}

func newAuthLoginCmd() *cobra.Command {
	var deviceCode bool
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to CloudBooster",
		Example: `  # Log in via browser (default)
  cbx auth login

  # Headless / SSH — device-code flow
  cbx auth login --device-code

  # Manual paste-back (no browser launch)
  cbx auth login --no-browser`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd, deviceCode, noBrowser)
		},
	}
	cmd.Flags().BoolVar(&deviceCode, "device-code", false, "Use device-code flow for headless/SSH sessions")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the auth URL and wait for manual paste-back")
	return cmd
}

func newAuthLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out of CloudBooster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogout(cmd)
		},
	}
}

func newAuthStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		Example: `  # Show who you're logged in as
  cbx auth status

  # Machine-readable status
  cbx auth status --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd)
		},
	}
}
