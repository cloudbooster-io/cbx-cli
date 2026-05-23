package cmd

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/core/api/v1"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

// runLogin / runLogout / runStatus are the shared bodies used by both
// the top-level `cbx login|logout|status` and the auth-parented
// `cbx auth login|logout|status`. Keeping them at package scope means
// the auth-parent commands are pure wiring; behaviour stays single-sourced.
func runLogin(cmd *cobra.Command, deviceCode, noBrowser bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	kr, err := auth.NewKeyring()
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}

	ocfg := &auth.Config{APIURL: cfg.APIURL}
	var result *auth.ExchangeResult
	if deviceCode {
		result, err = auth.RunDeviceFlow(cmd.Context(), ocfg)
	} else {
		var spinner *output.Spinner
		if !noBrowser && !jsonFlag && !quietFlag {
			spinner = output.NewSpinner("Waiting for browser callback…")
			spinner.Start()
		}
		result, err = auth.RunPKCEFlow(cmd.Context(), ocfg, auth.PKCEOptions{
			NoBrowser: noBrowser,
			Stdin:     cmd.InOrStdin(),
		})
		if spinner != nil {
			spinner.Stop()
		}
	}
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	if err := auth.SaveToken(kr, result.Token); err != nil {
		return fmt.Errorf("storing token: %w", err)
	}

	cfg.Auth.Email = result.Email
	if !result.Token.Expiry.IsZero() {
		cfg.Auth.ExpiresAt = result.Token.Expiry.Format(time.RFC3339)
	}
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	if jsonFlag {
		return output.PrintJSON(map[string]string{
			"email": result.Email,
		}, nil)
	}

	if !quietFlag {
		if result.Email != "" {
			fmt.Printf("%s Logged in as %s\n", output.Success.Render(output.Symbol("check")), result.Email)
		} else {
			fmt.Printf("%s Logged in to CloudBooster\n", output.Success.Render(output.Symbol("check")))
		}
	}
	return nil
}

func runLogout(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	kr, err := auth.NewKeyring()
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	if err := auth.DeleteToken(kr); err != nil {
		return fmt.Errorf("clearing token: %w", err)
	}

	cfg.Auth = config.AuthConfig{}
	if err := config.Save(cfg); err != nil {
		return err
	}

	if jsonFlag {
		return output.PrintJSON(map[string]string{"status": "logged_out"}, nil)
	}

	if !quietFlag {
		fmt.Printf("%s Logged out of CloudBooster\n", output.Success.Render(output.Symbol("check")))
	}
	return nil
}

func runStatus(cmd *cobra.Command) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	kr, err := auth.NewKeyring()
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}

	token, err := auth.LoadToken(kr)
	if err != nil {
		if jsonFlag {
			return output.PrintJSON(map[string]string{"status": "not_logged_in"}, nil)
		}
		fmt.Println("Not logged in.")
		return nil
	}

	httpClient, err := auth.AuthenticatedClient(cmd.Context(), cfg.APIURL, kr)
	if err != nil {
		if jsonFlag {
			return output.PrintJSON(map[string]string{"status": "not_logged_in"}, nil)
		}
		fmt.Println("Not logged in.")
		return nil
	}

	client, err := v1.NewClientWithResponses(cfg.APIURL, v1.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	resp, err := client.GetMeWithResponse(cmd.Context())
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "401") || strings.Contains(errStr, "Unauthorized") || strings.Contains(errStr, "cannot fetch token") {
			if jsonFlag {
				_ = output.PrintJSON(nil, output.JSONErrorf("authentication expired: run `cbx login`"))
				return fmt.Errorf("authentication expired")
			}
			return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
				What: "your session has expired",
				Why:  "the authentication token is no longer valid",
				Fix:  "run `cbx login` to re-authenticate",
				Code: "E_AUTH_EXPIRED",
			}))
		}
		return fmt.Errorf("checking status: %w", err)
	}

	if resp.StatusCode() == http.StatusUnauthorized {
		if jsonFlag {
			_ = output.PrintJSON(nil, output.JSONErrorf("authentication expired: run `cbx login`"))
			return fmt.Errorf("authentication expired")
		}
		return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
			What: "your session has expired",
			Why:  "the server returned HTTP 401 Unauthorized",
			Fix:  "run `cbx login` to re-authenticate",
			Code: "E_AUTH_EXPIRED",
		}))
	}

	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d", resp.StatusCode())
	}

	// Reload token from keyring in case AuthenticatedClient silently refreshed it.
	token, err = auth.LoadToken(kr)
	if err != nil {
		token = nil
	}

	email := ""
	if resp.JSON200 != nil && resp.JSON200.Email != nil {
		email = *resp.JSON200.Email
	}
	if email == "" {
		email = cfg.Auth.Email
	}

	fingerprint := "—"
	if token != nil && len(token.AccessToken) > 16 {
		fingerprint = token.AccessToken[:8] + "…" + token.AccessToken[len(token.AccessToken)-8:]
	} else if token != nil && token.AccessToken != "" {
		fingerprint = token.AccessToken
	}

	expiry := "—"
	if token != nil && !token.Expiry.IsZero() {
		expiry = token.Expiry.Format(time.RFC3339)
	}

	org := cfg.DefaultOrg
	if org == "" {
		org = "—"
	}

	if jsonFlag {
		return output.PrintJSON(map[string]string{
			"account":     email,
			"org":         org,
			"project":     "—",
			"fingerprint": fingerprint,
			"expiry":      expiry,
		}, nil)
	}

	tbl := output.NewTable([]string{"Field", "Value"})
	tbl.AddRow("Account", email)
	tbl.AddRow("Org", org)
	tbl.AddRow("Project", "—")
	tbl.AddRow("API key fingerprint", fingerprint)
	tbl.AddRow("Expiry", expiry)
	fmt.Print(tbl.Render())
	return nil
}

func newLoginCmd() *cobra.Command {
	var deviceCode bool
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to CloudBooster",
		Example: `  # Log in via browser (default)
  cbx login

  # Headless / SSH — device-code flow
  cbx login --device-code

  # Manual paste-back (no browser launch)
  cbx login --no-browser`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogin(cmd, deviceCode, noBrowser)
		},
	}
	cmd.Flags().BoolVar(&deviceCode, "device-code", false, "Use device-code flow for headless/SSH sessions")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "Print the auth URL and wait for manual paste-back")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out of CloudBooster",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogout(cmd)
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"whoami"},
		Short:   "Show authentication status",
		Example: `  # Show who you're logged in as
  cbx status

  # Machine-readable status
  cbx status --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd)
		},
	}
}
