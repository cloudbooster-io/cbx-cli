package main

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the health of your cbx installation",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			apiURL := cfg.APIURL
			networkOK, networkInfo := checkAPIConnectivity(apiURL)

			tbl := output.NewTable([]string{"Check", "Status", "Detail"})
			tbl.AddRow("Go version", output.Symbol("check"), runtime.Version())
			tbl.AddRow("OS/Arch", output.Symbol("check"), fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH))
			tbl.AddRow("Config directory", output.Symbol("check"), config.Dir())
			if networkOK {
				tbl.AddRow("API connectivity", output.Symbol("check"), networkInfo)
			} else {
				tbl.AddRow("API connectivity", output.Symbol("cross"), networkInfo)
			}

			fmt.Print(tbl.Render())

			if !networkOK {
				return fmt.Errorf("some health checks failed")
			}
			fmt.Println("\nYour cbx installation is healthy.")
			return nil
		},
	}
}

func checkAPIConnectivity(apiURL string) (bool, string) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL + "/health")
	if err != nil {
		return false, fmt.Sprintf(" unreachable (%v)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf(" HTTP %d", resp.StatusCode)
	}
	return true, fmt.Sprintf(" %s/health OK", apiURL)
}
