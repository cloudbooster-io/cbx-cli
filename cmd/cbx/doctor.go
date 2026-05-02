package main

import (
	"fmt"
	"net/http"
	"runtime"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"

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

			checks := []struct {
				name string
				ok   bool
				info string
			}{
				{"Go version", true, runtime.Version()},
				{"OS/Arch", true, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)},
				{"Config directory", true, config.Dir()},
				{"API connectivity", networkOK, networkInfo},
			}

			allOK := true
			for _, c := range checks {
				status := "✓"
				if !c.ok {
					status = "✗"
					allOK = false
				}
				fmt.Printf("%s %s: %s\n", status, c.name, c.info)
			}

			if !allOK {
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
