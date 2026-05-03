package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/llm"

	"github.com/spf13/cobra"
)

func newLLMCmd() *cobra.Command {
	llmCmd := &cobra.Command{
		Use:   "llm",
		Short: "Manage LLM provider authentication",
	}
	llmCmd.AddCommand(
		newLLMLoginCmd(),
		newLLMLogoutCmd(),
		newLLMListCmd(),
		newLLMDefaultCmd(),
	)
	return llmCmd
}

func newLLMLoginCmd() *cobra.Command {
	var tokenFlag string
	cmd := &cobra.Command{
		Use:   "login <provider>",
		Short: "Log in to an LLM provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]

			p, ok := llm.Providers[provider]
			if !ok {
				return fmt.Errorf("unknown provider: %s (supported: claude, codex)", provider)
			}

			token := tokenFlag
			if token == "" {
				token = os.Getenv("CBX_LLM_TOKEN")
			}

			fromOAuth := false
			if token == "" && provider == "claude" {
				var err error
				token, err = llm.ClaudeOAuthLogin()
				if err != nil {
					return fmt.Errorf("Claude OAuth login failed: %w", err)
				}
				fromOAuth = true
			}

			if token == "" {
				// Interactive prompt for token.
				fmt.Fprintf(cmd.OutOrStdout(), "Enter your %s API key: ", provider)
				// Read password-like input without echo.
				// For simplicity we read plain text; TTY masking can be added later.
				var input string
				if _, err := fmt.Fscanln(cmd.InOrStdin(), &input); err != nil {
					return fmt.Errorf("reading token: %w", err)
				}
				token = input
			}

			if !fromOAuth {
				if err := llm.ValidateTokenFormat(provider, token); err != nil {
					return err
				}
				if err := llm.ValidateToken(provider, token); err != nil {
					return fmt.Errorf("token validation failed: %w", err)
				}
			}

			if err := llm.StoreToken(provider, token); err != nil {
				return fmt.Errorf("storing token: %w", err)
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.LLM.Providers[provider] = config.LLMProvider{
				Name:     provider,
				BaseURL:  p.BaseURL,
				Model:    p.Model,
				LoggedIn: true,
			}
			if cfg.LLM.Default == "" {
				cfg.LLM.Default = provider
			}
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				out := map[string]any{
					"provider": provider,
					"status":   "logged_in",
					"default":  cfg.LLM.Default == provider,
				}
				b, _ := json.Marshal(out)
				fmt.Println(string(b))
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Logged in to %s\n", provider)
			return nil
		},
	}
	cmd.Flags().StringVar(&tokenFlag, "token", "", "API key (skips interactive prompt)")
	return cmd
}

func newLLMLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout <provider>",
		Short: "Log out of an LLM provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]

			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// Always attempt to delete from keychain, even if not in config.
			_ = llm.DeleteToken(provider)

			delete(cfg.LLM.Providers, provider)
			if cfg.LLM.Default == provider {
				cfg.LLM.Default = ""
			}
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				out := map[string]any{
					"provider": provider,
					"status":   "logged_out",
				}
				b, _ := json.Marshal(out)
				fmt.Println(string(b))
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Logged out of %s\n", provider)
			return nil
		},
	}
}

func newLLMListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured LLM providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			if jsonFlag {
				var providers []map[string]any
				for name, p := range cfg.LLM.Providers {
					providers = append(providers, map[string]any{
						"name":     name,
						"model":    p.Model,
						"default":  cfg.LLM.Default == name,
						"loggedIn": p.LoggedIn,
					})
				}
				out := map[string]any{"providers": providers}
				b, _ := json.Marshal(out)
				fmt.Println(string(b))
				return nil
			}

			if len(cfg.LLM.Providers) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No LLM providers configured.")
				return nil
			}
			for name, p := range cfg.LLM.Providers {
				marker := ""
				if cfg.LLM.Default == name {
					marker = " (default)"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s%s — %s\n", name, marker, p.Model)
			}
			return nil
		},
	}
}

func newLLMDefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "default <provider>",
		Short: "Set the default LLM provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if _, ok := cfg.LLM.Providers[provider]; !ok {
				return fmt.Errorf("provider %s is not logged in; run 'cbx llm login %s' first", provider, provider)
			}
			cfg.LLM.Default = provider
			if err := config.Save(cfg); err != nil {
				return err
			}

			if jsonFlag {
				out := map[string]any{
					"provider": provider,
					"status":   "set_default",
				}
				b, _ := json.Marshal(out)
				fmt.Println(string(b))
				return nil
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✓ Default LLM provider set to %s\n", provider)
			return nil
		},
	}
}
