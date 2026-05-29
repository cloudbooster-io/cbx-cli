package cmd

import (
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
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
			fmt.Fprint(cmd.OutOrStdout(), renderTelemetryStatusCard(cfg.Telemetry.Enabled, cfg.Telemetry.PromptedAt))
			return nil
		},
	}
}

// renderTelemetryStatusCard draws the current telemetry state as a card
// with a green/red status chip + the last-prompted timestamp + a hint
// for the toggle command. Mirrors the auth/version/doctor surfaces so
// the user reads the same visual pattern.
func renderTelemetryStatusCard(enabled bool, promptedAt string) string {
	var stateChip, toggleCmd string
	if enabled {
		stateChip = output.Chip("ENABLED", lipgloss.Color("231"), lipgloss.Color("22"))
		toggleCmd = "cbx telemetry disable"
	} else {
		stateChip = output.Chip("DISABLED", lipgloss.Color("231"), lipgloss.Color("124"))
		toggleCmd = "cbx telemetry enable"
	}
	asked := promptedAt
	if asked == "" {
		asked = output.Dim.Render("never · will prompt on next interactive run")
	} else {
		asked = output.Dim.Render(asked)
	}
	card := output.Card{
		Label: output.Chip("TELEMETRY", lipgloss.Color("231"), lipgloss.Color("236")),
		Title: "anonymous error reports & usage metrics",
		Rows: []output.CardRow{
			{Key: "state", Value: stateChip},
			{Key: "last asked", Value: asked},
		},
		Footer: output.Dim.Render(output.Symbol("arrow")+" ") + toggleCmd +
			output.Dim.Render(" to change · `cbx telemetry` for what's sent and what isn't"),
	}
	return card.Render()
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
