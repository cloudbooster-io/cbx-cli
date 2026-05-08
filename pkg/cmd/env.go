package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/core/api/v1"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

func newEnvCmd() *cobra.Command {
	env := &cobra.Command{
		Use:   "env",
		Short: "Manage and inspect environments",
		Long:  `List environments, view status, cost, drift, and logs.`,
	}
	env.AddCommand(
		newEnvListCmd(),
		newEnvStatusCmd(),
	)
	return env
}

func newEnvListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List environments for the current project",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}

func newEnvStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <env-id>",
		Short: "Show high-level status for an environment",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("not implemented")
		},
	}
}

// envClient is a helper that builds an API client for env subcommands.
func envClient() (*v1.APIClient, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	client, err := v1.NewAPIClient(cfg, func(o *v1.ClientOptions) {
		o.Quiet = quietFlag
	})
	if err != nil {
		return nil, fmt.Errorf("creating API client: %w", err)
	}
	return client, nil
}

// envAuthCheck verifies the user is authenticated and prints a friendly
// message when they are not.
func envAuthCheck() error {
	kr, err := auth.NewKeyring()
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	if _, err := auth.LoadToken(kr); err != nil {
		return fmt.Errorf("not authenticated: run `cbx login` first")
	}
	return nil
}

// envHandleAPIError translates common API errors into user-friendly messages.
func envHandleAPIError(err error, statusCode int) error {
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	switch statusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("authentication expired: run `cbx login` to re-authenticate")
	case http.StatusForbidden:
		return fmt.Errorf("access denied: a paid CloudBooster account is required for this command")
	case http.StatusNotFound:
		return fmt.Errorf("environment not found")
	case http.StatusTooManyRequests:
		return fmt.Errorf("rate limit exceeded: please wait before retrying")
	}
	if statusCode >= 500 {
		return fmt.Errorf("server error (%d): please retry later", statusCode)
	}
	if statusCode >= 400 {
		return fmt.Errorf("request error (%d)", statusCode)
	}
	return nil
}

// envPrintJSONOrText outputs data as JSON when --json is set, otherwise
// delegates to the provided text printer.
func envPrintJSONOrText(data any, textFn func()) error {
	if jsonFlag {
		return output.PrintJSON(data, nil)
	}
	if !quietFlag {
		textFn()
	}
	return nil
}
