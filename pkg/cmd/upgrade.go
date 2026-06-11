package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
	"github.com/cloudbooster-io/cbx-cli/internal/update"

	"github.com/spf13/cobra"
)

type upgradeResult struct {
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
	InstallMethod  string `json:"install_method"`
	Upgraded       bool   `json:"upgraded"`
	Message        string `json:"message"`
}

func newUpgradeCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade cbx to the latest version",
		Example: `  # Upgrade in place via the detected install method
  cbx upgrade

  # Show what would be done without changing anything
  cbx upgrade --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if Version == "dev" || Version == "unknown" || Version == "" {
				if output.JSON() {
					return output.PrintJSON(upgradeResult{
						CurrentVersion: Version,
						Message:        "cannot upgrade development build",
					}, nil)
				}
				card := output.Card{
					Label: output.Chip("UPGRADE", lipgloss.Color("231"), lipgloss.Color("236")),
					Title: "cannot upgrade development build",
					Rows: []output.CardRow{
						{Key: "current", Value: output.Dim.Render(Version)},
					},
					Footer: output.Dim.Render(output.Symbol("arrow")+" install a release build from ") +
						"https://github.com/cloudbooster-io/cbx-cli/releases",
				}
				fmt.Print(card.Render())
				return nil
			}

			checker := update.NewChecker(Version)
			// `cbx upgrade` is the explicit "tell me what's out there
			// right now" path; the daily cache is for the cheap
			// background banner on every other command.
			checker.IgnoreCache = true
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := checker.Check(ctx)
			if err != nil {
				if output.JSON() {
					return output.PrintJSON(upgradeResult{
						CurrentVersion: Version,
						Message:        fmt.Sprintf("failed to check for updates: %v", err),
					}, nil)
				}
				return fmt.Errorf("checking for updates: %w", err)
			}

			if !result.HasUpdate {
				if output.JSON() {
					return output.PrintJSON(upgradeResult{
						CurrentVersion: Version,
						LatestVersion:  result.LatestVersion,
						HasUpdate:      false,
						InstallMethod:  string(result.InstallMethod),
						Upgraded:       false,
						Message:        "Already up to date",
					}, nil)
				}
				output.Infof("Already up to date (%s).", Version)
				return nil
			}

			if dryRun {
				if output.JSON() {
					return output.PrintJSON(upgradeResult{
						CurrentVersion: Version,
						LatestVersion:  result.LatestVersion,
						HasUpdate:      true,
						InstallMethod:  string(result.InstallMethod),
						Upgraded:       false,
						Message:        fmt.Sprintf("would run: %s", update.UpgradeCommand(result)),
					}, nil)
				}
				fmt.Print(renderUpgradePlanCard(Version, result, false))
				return nil
			}

			if output.JSON() {
				// JSON mode: report what would happen but don't actually run package manager
				return output.PrintJSON(upgradeResult{
					CurrentVersion: Version,
					LatestVersion:  result.LatestVersion,
					HasUpdate:      true,
					InstallMethod:  string(result.InstallMethod),
					Upgraded:       false,
					Message:        fmt.Sprintf("run `%s` to upgrade", update.UpgradeCommand(result)),
				}, nil)
			}

			fmt.Print(renderUpgradePlanCard(Version, result, true))
			if result.InstallMethod == update.InstallDirect {
				directCard := output.Card{
					Label: output.Chip("UPGRADE", lipgloss.Color("231"), lipgloss.Color("166")),
					Title: "direct-download upgrade is not automated",
					Rows: []output.CardRow{
						{Key: "release", Value: result.ReleaseURL},
						{Key: "command", Value: update.UpgradeCommand(result)},
					},
					Footer: output.Dim.Render(output.Symbol("arrow") + " run the command above or open the release URL"),
				}
				fmt.Print(directCard.Render())
				return nil
			}
			if result.InstallMethod == update.InstallDeb || result.InstallMethod == update.InstallRPM {
				// Package upgrades need sudo; cbx never sudoes on the
				// user's behalf, so hand back the command instead.
				pkgCard := output.Card{
					Label: output.Chip("UPGRADE", lipgloss.Color("231"), lipgloss.Color("166")),
					Title: "package-manager upgrade needs sudo",
					Rows: []output.CardRow{
						{Key: "release", Value: result.ReleaseURL},
						{Key: "command", Value: update.UpgradeCommand(result)},
					},
					Footer: output.Dim.Render(output.Symbol("arrow") + " run the command above to upgrade via your package manager"),
				}
				fmt.Print(pkgCard.Render())
				return nil
			}
			if err := update.Upgrade(ctx, result); err != nil {
				return fmt.Errorf("upgrade failed: %w", err)
			}
			output.Successf("Upgraded to %s", result.LatestVersion)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without upgrading")
	return cmd
}

// renderUpgradePlanCard composes the "update available" card. inProgress
// flips the verb from "would run" to "running" so the same card serves
// both --dry-run and the real upgrade path.
func renderUpgradePlanCard(current string, r *update.Result, inProgress bool) string {
	from := output.Dim.Render(current)
	arrow := output.Dim.Render(" " + output.Symbol("arrow") + " ")
	to := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42")).Render(r.LatestVersion)
	if !output.Enabled() {
		to = r.LatestVersion
	}
	verb := "would run"
	title := "upgrade plan"
	if inProgress {
		verb = "running"
		title = "upgrading cbx"
	}
	card := output.Card{
		Label: output.Chip("UPGRADE", lipgloss.Color("231"), lipgloss.Color("22")),
		Title: title,
		Rows: []output.CardRow{
			{Key: "version", Value: from + arrow + to},
			{Key: "via", Value: string(r.InstallMethod)},
			{Key: verb, Value: update.UpgradeCommand(r)},
		},
	}
	return card.Render()
}
