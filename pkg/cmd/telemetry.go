package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
)

func newTelemetryCmd() *cobra.Command {
	tc := &cobra.Command{
		Use:   "telemetry",
		Short: "Manage anonymous error reports and usage metrics",
		Long: `Manage anonymous error reports and usage metrics sent to
CloudBooster's Sentry instance.

What's sent (only when enabled):
  • Error reports — crash traces and error messages, scrubbed for
    API keys, file paths, and AWS account IDs.
  • Usage metrics — command name, duration, success/failure.

What's NEVER sent:
  • Flag values, command arguments, environment variables
  • File contents, file paths, AWS account IDs, API keys, ARNs
  • Hostname or system user

Environment-variable overrides (highest priority):
  CBX_TELEMETRY=0|1        explicit on/off, overrides config
  DO_NOT_TRACK=1           disables telemetry (DNT standard)
  CI=true                  skips the first-run prompt
  CBX_SENTRY_DSN=...       redirect telemetry to a different Sentry
                           project (use "-" to disable Sentry init
                           entirely even when config says enabled)`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	tc.AddCommand(
		newTelemetryStatusCmd(),
		newTelemetryEnableCmd(),
		newTelemetryDisableCmd(),
	)
	return tc
}

func newTelemetryStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether telemetry is currently enabled",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if output.JSON() {
				return output.PrintJSON(map[string]any{
					"enabled":     cfg.Telemetry.Enabled,
					"prompted":    cfg.Telemetry.Prompted,
					"prompted_at": cfg.Telemetry.PromptedAt,
				}, nil)
			}
			state := "disabled"
			if cfg.Telemetry.Enabled {
				state = "enabled"
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Telemetry: %s\n", state)
			if cfg.Telemetry.PromptedAt != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Last asked: %s\n", cfg.Telemetry.PromptedAt)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Last asked: never (will prompt on next interactive run)")
			}
			return nil
		},
	}
}

func newTelemetryEnableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "enable",
		Short: "Enable error reports and usage metrics",
		RunE:  setTelemetry(true),
	}
}

func newTelemetryDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Disable error reports and usage metrics",
		RunE:  setTelemetry(false),
	}
}

func setTelemetry(v bool) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		cfg.Telemetry.Enabled = v
		cfg.Telemetry.Prompted = true
		cfg.Telemetry.PromptedAt = time.Now().UTC().Format(time.RFC3339)
		if err := config.Save(cfg); err != nil {
			return err
		}
		state := "disabled"
		if v {
			state = "enabled"
		}
		if output.JSON() {
			return output.PrintJSON(map[string]any{"enabled": v, "status": state}, nil)
		}
		output.Successf("Telemetry %s", state)
		return nil
	}
}
