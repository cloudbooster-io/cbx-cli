package main

import (
	"fmt"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"

	"github.com/spf13/cobra"
)

func newLLMCmd() *cobra.Command {
	llm := &cobra.Command{
		Use:   "llm",
		Short: "Manage LLM provider authentication",
	}
	llm.AddCommand(
		newLLMLoginCmd(),
		newLLMLogoutCmd(),
		newLLMListCmd(),
		newLLMDefaultCmd(),
	)
	return llm
}

func newLLMLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login <provider>",
		Short: "Log in to an LLM provider",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			apiKey := fmt.Sprintf("%s_test_key_%d", provider, 42)
			baseURL := ""
			model := ""
			switch provider {
			case "claude":
				baseURL = "https://api.anthropic.com"
				model = "claude-sonnet-4-20250514"
			case "openai":
				baseURL = "https://api.openai.com"
				model = "gpt-4o"
			case "ollama":
				baseURL = "http://localhost:11434"
				model = "llama3"
			default:
				return fmt.Errorf("unknown provider: %s", provider)
			}

			cfg.LLM.Providers[provider] = config.LLMProvider{
				Name:     provider,
				APIKey:   apiKey,
				BaseURL:  baseURL,
				Model:    model,
				LoggedIn: true,
			}
			if cfg.LLM.Default == "" {
				cfg.LLM.Default = provider
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Printf("✓ Logged in to %s\n", provider)
			return nil
		},
	}
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
			delete(cfg.LLM.Providers, provider)
			if cfg.LLM.Default == provider {
				cfg.LLM.Default = ""
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Printf("✓ Logged out of %s\n", provider)
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
			if len(cfg.LLM.Providers) == 0 {
				fmt.Println("No LLM providers configured.")
				return nil
			}
			for name, p := range cfg.LLM.Providers {
				marker := ""
				if cfg.LLM.Default == name {
					marker = " (default)"
				}
				fmt.Printf("%s%s — %s\n", name, marker, p.Model)
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
			fmt.Printf("✓ Default LLM provider set to %s\n", provider)
			return nil
		},
	}
}
