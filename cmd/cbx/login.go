package main

import (
	"fmt"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"

	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Log in to CloudBooster",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.Auth.Token = "cbx_test_token_" + fmt.Sprintf("%d", 42)
			cfg.Auth.Email = "user@example.com"
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Println("✓ Logged in to CloudBooster")
			return nil
		},
	}
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Log out of CloudBooster",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			cfg.Auth = config.AuthConfig{}
			if err := config.Save(cfg); err != nil {
				return err
			}
			fmt.Println("✓ Logged out of CloudBooster")
			return nil
		},
	}
}

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show authentication status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if cfg.Auth.Token == "" {
				fmt.Println("Not logged in.")
				return nil
			}
			fmt.Printf("Logged in as %s\n", cfg.Auth.Email)
			return nil
		},
	}
}
