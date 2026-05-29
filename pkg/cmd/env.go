package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/cloudbooster-io/cbx-cli/core/api/v1"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/core/auth"
	"github.com/cloudbooster-io/cbx-cli/internal/output"

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

// envClient is a helper that builds an API client for env subcommands.
func envClient() (*v1.APIClient, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}
	token := auth.AccessToken()
	client, err := v1.NewAPIClient(cfg, func(o *v1.ClientOptions) {
		o.Quiet = quietFlag
		o.Token = token
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
		return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
			What: "not authenticated",
			Why:  "no CloudBooster token found in the OS keychain",
			Fix:  "run `cbx login` to sign in",
			Code: "E_AUTH_REQUIRED",
		}))
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
		return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
			What: "authentication expired",
			Why:  "the server returned HTTP 401 Unauthorized",
			Fix:  "run `cbx login` to re-authenticate",
			Code: "E_AUTH_EXPIRED",
		}))
	case http.StatusForbidden:
		return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
			What: "access denied",
			Why:  "a paid CloudBooster account is required for this command",
			Fix:  "upgrade your plan at https://cloudbooster.io/pricing or contact your workspace admin",
			Code: "E_PLAN_REQUIRED",
		}))
	case http.StatusNotFound:
		return fmt.Errorf("environment not found")
	case http.StatusTooManyRequests:
		return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
			What: "rate limit exceeded",
			Why:  "the server returned HTTP 429 Too Many Requests",
			Fix:  "wait a moment before retrying; if this persists, reduce request frequency",
			Code: "E_RATE_LIMITED",
		}))
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
	if output.JSON() {
		return output.PrintJSON(data, nil)
	}
	if !quietFlag {
		textFn()
	}
	return nil
}
