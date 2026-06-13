package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/charmbracelet/lipgloss"
	v1 "github.com/cloudbooster-io/cbx-cli/core/api/v1"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/core/auth"
	"github.com/cloudbooster-io/cbx-cli/internal/output"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
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
		if !noBrowser && !output.JSON() && !quietFlag {
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

	if output.JSON() {
		return output.PrintJSON(map[string]string{
			"email": result.Email,
		}, nil)
	}

	if !quietFlag {
		if result.Email != "" {
			output.Successf("Logged in as %s", result.Email)
		} else {
			output.Successf("Logged in to CloudBooster")
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

	if output.JSON() {
		return output.PrintJSON(map[string]string{"status": "logged_out"}, nil)
	}

	if !quietFlag {
		output.Successf("Logged out of CloudBooster")
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

	// Check for token presence via Keychain metadata first. On macOS this
	// does not trigger the Keychain access prompt that a full Retrieve
	// would, so logged-out users see "not logged in" without a dialog.
	if present, _ := auth.HasToken(kr); !present {
		if output.JSON() {
			return output.PrintJSON(map[string]string{"status": "not_logged_in"}, nil)
		}
		fmt.Print(renderNotLoggedInCard())
		return nil
	}

	httpClient, err := auth.AuthenticatedClient(cmd.Context(), cfg.APIURL, kr)
	if err != nil {
		if output.JSON() {
			return output.PrintJSON(map[string]string{"status": "not_logged_in"}, nil)
		}
		fmt.Print(renderNotLoggedInCard())
		return nil
	}

	client, err := v1.NewClientWithResponses(cfg.APIURL, v1.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("creating API client: %w", err)
	}

	resp, err := client.GetMeWithResponse(cmd.Context())
	if err != nil {
		// Transport-level failure: no HTTP response reached us. The case
		// that means "auth expired" here is a failed token refresh, which
		// the oauth2 transport surfaces as a typed *oauth2.RetrieveError
		// (wrapped in *url.Error by net/http) — not as a 401 response.
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) {
			return output.NewError(output.ErrorDetail{
				What: "your session has expired",
				Why:  "the authentication token is no longer valid",
				Fix:  "run `cbx login` to re-authenticate",
				Code: "E_AUTH_EXPIRED",
			})
		}
		return fmt.Errorf("checking status: %w", err)
	}

	if resp.StatusCode() == http.StatusUnauthorized {
		return output.NewError(output.ErrorDetail{
			What: "your session has expired",
			Why:  "the server returned HTTP 401 Unauthorized",
			Fix:  "run `cbx login` to re-authenticate",
			Code: "E_AUTH_EXPIRED",
		})
	}

	if resp.StatusCode() != http.StatusOK {
		return output.NewError(output.ErrorDetail{
			What: fmt.Sprintf("could not determine auth status (HTTP %d)", resp.StatusCode()),
			Why:  fmt.Sprintf("%s answered the status request with an unexpected response — the stored login may belong to a different API host", cfg.APIURL),
			Fix:  "check `cbx config get api_url` points at the server you logged in to, or re-run `cbx login`",
			Code: "E_STATUS_HTTP",
		})
	}

	// Reload token from keyring in case AuthenticatedClient silently refreshed it.
	token, err := auth.LoadToken(kr)
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

	// Prefer the org returned by the server (always reflects the token's
	// current default_organisation_id), then fall back to the local
	// default-org config, then a dash for "not selected yet".
	org := ""
	if resp.JSON200 != nil && resp.JSON200.Org != nil {
		if resp.JSON200.Org.Slug != nil && *resp.JSON200.Org.Slug != "" {
			org = *resp.JSON200.Org.Slug
		} else if resp.JSON200.Org.Name != nil {
			org = *resp.JSON200.Org.Name
		}
	}
	if org == "" {
		org = cfg.DefaultOrg
	}
	if org == "" {
		org = "—"
	}

	if output.JSON() {
		return output.PrintJSON(map[string]string{
			"account":     email,
			"org":         org,
			"project":     "—",
			"fingerprint": fingerprint,
			"expiry":      expiry,
		}, nil)
	}

	fmt.Print(renderLoggedInCard(email, org, fingerprint, expiry))
	return nil
}

// renderNotLoggedInCard is the friendly "not logged in" surface. Two
// lines: a status chip + headline, then a dim hint pointing at the
// login command. Stays small so it doesn't dwarf the absence of state.
func renderNotLoggedInCard() string {
	card := output.Card{
		Label: output.Chip("AUTH", lipgloss.Color("231"), lipgloss.Color("236")),
		Title: "not logged in",
		Rows: []output.CardRow{
			{Key: "account", Value: output.Dim.Render("—")},
		},
		Footer: output.Dim.Render(output.Symbol("arrow")+" run ") +
			"cbx login" +
			output.Dim.Render(" to authenticate (or `cbx login --device-code` for headless / SSH)"),
	}
	return card.Render()
}

// renderLoggedInCard replaces the old two-column Field/Value table with a
// framed identity card. Account/org are the headline; token fingerprint
// and expiry are dim metadata. Mirrors the audit-aws header so the user
// learns one design pattern.
func renderLoggedInCard(email, org, fingerprint, expiry string) string {
	if email == "" {
		email = output.Dim.Render("—")
	}
	card := output.Card{
		Label: output.Chip("AUTH", lipgloss.Color("231"), lipgloss.Color("22")),
		Title: "logged in",
		Rows: []output.CardRow{
			{Key: "account", Value: email},
			{Key: "org", Value: org},
			{Key: "project", Value: output.Dim.Render("—")},
			{Key: "token", Value: output.Dim.Render(fingerprint)},
			{Key: "expires", Value: output.Dim.Render(expiry)},
		},
	}
	return card.Render()
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
		Example: `  # Log out of the CloudBooster platform
  cbx logout`,
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
