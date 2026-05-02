package main

import (
	"fmt"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"

	"github.com/spf13/cobra"
)

func newLoginCmd() *cobra.Command {
	var deviceCode bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in to CloudBooster",
		RunE: func(cmd *cobra.Command, args []string) error {
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
				result, err = auth.RunPKCEFlow(cmd.Context(), ocfg)
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

			if result.Email != "" {
				fmt.Printf("✓ Logged in to CloudBooster as %s\n", result.Email)
			} else {
				fmt.Println("✓ Logged in to CloudBooster")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&deviceCode, "device-code", false, "Use device-code flow for headless/SSH sessions")
	return cmd
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

			kr, err := auth.NewKeyring()
			if err != nil {
				return fmt.Errorf("keyring: %w", err)
			}
			loggedIn, err := auth.IsAuthenticated(kr)
			if err != nil {
				return fmt.Errorf("checking auth: %w", err)
			}
			if !loggedIn {
				fmt.Println("Not logged in.")
				return nil
			}
			if cfg.Auth.Email != "" {
				fmt.Printf("Logged in as %s\n", cfg.Auth.Email)
			} else {
				fmt.Println("Logged in.")
			}
			return nil
		},
	}
}
