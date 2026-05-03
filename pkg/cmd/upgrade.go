package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/update"

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
		RunE: func(cmd *cobra.Command, args []string) error {
			if Version == "dev" || Version == "unknown" || Version == "" {
				if jsonFlag {
					out, _ := json.MarshalIndent(upgradeResult{
						CurrentVersion: Version,
						Message:        "cannot upgrade development build",
					}, "", "  ")
					fmt.Println(string(out))
					return nil
				}
				fmt.Println("Cannot upgrade development build. Install a release build from:")
				fmt.Println("  https://github.com/cloudbooster/cbx-cli/releases")
				return nil
			}

			checker := update.NewChecker(Version)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := checker.Check(ctx)
			if err != nil {
				if jsonFlag {
					out, _ := json.MarshalIndent(upgradeResult{
						CurrentVersion: Version,
						Message:        fmt.Sprintf("failed to check for updates: %v", err),
					}, "", "  ")
					fmt.Println(string(out))
					return nil
				}
				return fmt.Errorf("checking for updates: %w", err)
			}

			if !result.HasUpdate {
				if jsonFlag {
					out, _ := json.MarshalIndent(upgradeResult{
						CurrentVersion: Version,
						LatestVersion:  result.LatestVersion,
						HasUpdate:      false,
						InstallMethod:  string(result.InstallMethod),
						Upgraded:       false,
						Message:        "Already up to date",
					}, "", "  ")
					fmt.Println(string(out))
					return nil
				}
				fmt.Printf("Already up to date (%s).\n", Version)
				return nil
			}

			if dryRun {
				if jsonFlag {
					out, _ := json.MarshalIndent(upgradeResult{
						CurrentVersion: Version,
						LatestVersion:  result.LatestVersion,
						HasUpdate:      true,
						InstallMethod:  string(result.InstallMethod),
						Upgraded:       false,
						Message:        fmt.Sprintf("would run: %s", update.UpgradeCommand(result)),
					}, "", "  ")
					fmt.Println(string(out))
					return nil
				}
				fmt.Printf("Update available: %s → %s\n", Version, result.LatestVersion)
				fmt.Printf("Install method: %s\n", result.InstallMethod)
				fmt.Printf("Would run: %s\n", update.UpgradeCommand(result))
				return nil
			}

			if jsonFlag {
				// JSON mode: report what would happen but don't actually run package manager
				out, _ := json.MarshalIndent(upgradeResult{
					CurrentVersion: Version,
					LatestVersion:  result.LatestVersion,
					HasUpdate:      true,
					InstallMethod:  string(result.InstallMethod),
					Upgraded:       false,
					Message:        fmt.Sprintf("run `%s` to upgrade", update.UpgradeCommand(result)),
				}, "", "  ")
				fmt.Println(string(out))
				return nil
			}

			fmt.Printf("Upgrading cbx %s → %s (%s)\n", Version, result.LatestVersion, result.InstallMethod)
			if result.InstallMethod == update.InstallDirect {
				fmt.Printf("Direct download upgrade is not automated.\n")
				fmt.Printf("Download the latest release from:\n  %s\n", result.ReleaseURL)
				fmt.Printf("Or run:\n  %s\n", update.UpgradeCommand(result))
				return nil
			}
			if err := update.Upgrade(ctx, result); err != nil {
				return fmt.Errorf("upgrade failed: %w", err)
			}
			fmt.Printf("✓ Upgraded to %s\n", result.LatestVersion)
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be done without upgrading")
	return cmd
}
