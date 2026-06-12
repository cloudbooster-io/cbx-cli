package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
	"github.com/cloudbooster-io/cbx-cli/internal/update"

	"github.com/spf13/cobra"
)

// doctorCheck represents a single health check.
type doctorCheck struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	Info string `json:"info"`
}

type doctorReport struct {
	Healthy bool          `json:"healthy"`
	Checks  []doctorCheck `json:"checks"`
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the health of your cbx installation",
		Example: `  # Run all health checks
  cbx doctor

  # Machine-readable output
  cbx doctor --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			checks := runChecks(cfg)
			allOK := true
			for _, c := range checks {
				if !c.OK {
					allOK = false
					break
				}
			}

			if output.JSON() {
				report := doctorReport{Healthy: allOK, Checks: checks}
				if !allOK {
					if err := output.PrintJSON(report, output.JSONErrorf("some health checks failed")); err != nil {
						return err
					}
					// The card/envelope already said everything; exit 1
					// without re-printing through the central error path.
					return &audit.ExitCodeError{Code: 1}
				}
				return output.PrintJSON(report, nil)
			}

			fmt.Print(renderDoctorCard(checks, allOK))

			if !allOK {
				return &audit.ExitCodeError{Code: 1}
			}
			return nil
		},
	}
}

// renderDoctorCard composes the health-check output as a framed card so
// every cbx surface shares the same visual language. Per-row layout is
// ✓/✗ chip + bold name + dim detail; the footer summarises the run with
// a green "healthy" or red "N failed" + a one-command "what next" hint.
func renderDoctorCard(checks []doctorCheck, allOK bool) string {
	// Compute name column width so all detail strings start at the same
	// indent regardless of which check name is longest.
	nameW := 0
	for _, c := range checks {
		if w := lipgloss.Width(c.Name); w > nameW {
			nameW = w
		}
	}

	card := output.Card{
		Label: output.Chip("HEALTH", lipgloss.Color("231"), lipgloss.Color("236")),
		Title: "cbx · doctor",
	}
	for _, c := range checks {
		symbol := output.Success.Render(output.Symbol("check"))
		if !c.OK {
			symbol = output.Error.Render(output.Symbol("cross"))
		}
		// Pad the name in its plain form so styled widths line up.
		name := c.Name + strings.Repeat(" ", nameW-lipgloss.Width(c.Name))
		nameStyled := lipgloss.NewStyle().Bold(true).Render(name)
		if !output.Enabled() {
			nameStyled = name
		}
		row := fmt.Sprintf("%s  %s  %s", symbol, nameStyled, output.Dim.Render(c.Info))
		card.Rows = append(card.Rows, output.CardRow{Key: "", Value: row})
	}
	if allOK {
		card.Footer = output.Success.Render(output.Symbol("check")+" all systems healthy") +
			"  " + output.Dim.Render("· run `cbx audit aws` to get going")
	} else {
		failed := 0
		for _, c := range checks {
			if !c.OK {
				failed++
			}
		}
		card.Footer = output.Error.Render(fmt.Sprintf("%s %d check(s) failed", output.Symbol("cross"), failed)) +
			"  " + output.Dim.Render("· rerun cbx doctor after addressing the items above")
	}
	return card.Render()
}

func runChecks(cfg *config.Config) []doctorCheck {
	var checks []doctorCheck

	// 1. cbx version
	checks = append(checks, doctorCheck{
		Name: "cbx version",
		OK:   Version != "dev" && Version != "unknown" && Version != "",
		Info: Version,
	})

	// 2. OS/Arch
	checks = append(checks, doctorCheck{
		Name: "OS/Arch",
		OK:   true,
		Info: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	})

	// 3. Config directory
	checks = append(checks, doctorCheck{
		Name: "Config directory",
		OK:   true,
		Info: config.Dir(),
	})

	// 4. API connectivity
	apiURL := cfg.APIURL
	if apiURL == "" {
		apiURL = "https://api.cloudbooster.io"
	}
	networkOK, networkInfo := checkAPIConnectivity(apiURL)
	checks = append(checks, doctorCheck{
		Name: "API connectivity",
		OK:   networkOK,
		Info: networkInfo,
	})

	// 5. LLM provider auth
	llmOK, llmInfo := checkLLMAuth(cfg)
	checks = append(checks, doctorCheck{
		Name: "LLM auth",
		OK:   llmOK,
		Info: llmInfo,
	})

	// 6. claude CLI on PATH — required by `cbx audit aws` (always-grounded
	//    via Claude Code).
	claudeOK, claudeInfo := checkClaudeBinary()
	checks = append(checks, doctorCheck{
		Name: "claude CLI",
		OK:   claudeOK,
		Info: claudeInfo,
	})

	// 7. Version current
	versionOK, versionInfo := checkVersionCurrent()
	checks = append(checks, doctorCheck{
		Name: "Version current",
		OK:   versionOK,
		Info: versionInfo,
	})

	// 8. Keychain accessible
	keychainOK, keychainInfo := checkKeychain()
	checks = append(checks, doctorCheck{
		Name: "Keychain accessible",
		OK:   keychainOK,
		Info: keychainInfo,
	})

	return checks
}

func checkAPIConnectivity(apiURL string) (bool, string) {
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(apiURL + "/health")
	if err != nil {
		return false, fmt.Sprintf("unreachable (%v)", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return true, fmt.Sprintf("%s/health OK", apiURL)
}

func checkLLMAuth(cfg *config.Config) (bool, string) {
	// Two independent ways to satisfy the LLM requirement: an api provider
	// with a stored key, or a local CLI executor on PATH (Claude Code /
	// Codex own their own auth — nothing to store on the cbx side).
	// Settings-only entries (model pins, AuthModeCLIExecutor) are not auth.
	var loggedIn []string
	for name, p := range cfg.LLM.Providers {
		if p.LoggedIn {
			loggedIn = append(loggedIn, name)
		}
	}
	var executors []string
	for _, e := range cliExecutors {
		if _, err := exec.LookPath(e.Binary); err == nil {
			executors = append(executors, e.Name)
		}
	}
	switch {
	case len(loggedIn) > 0 && len(executors) > 0:
		return true, fmt.Sprintf("api: %s · cli: %s", strings.Join(loggedIn, ", "), strings.Join(executors, ", "))
	case len(loggedIn) > 0:
		return true, fmt.Sprintf("api key stored: %s", strings.Join(loggedIn, ", "))
	case len(executors) > 0:
		return true, fmt.Sprintf("cli executor on PATH: %s", strings.Join(executors, ", "))
	default:
		return false, "no api key stored and no CLI executor on PATH — run `cbx llm api login claude` or install Claude Code"
	}
}

// checkClaudeBinary verifies the `claude` (Claude Code) CLI is on PATH.
// `cbx audit aws` is always grounded through this binary, so without it
// the live-AWS audit cannot run. The legacy scanner-binary check
// (prowler/trivy/checkov/tfsec) was removed: the CLI no longer shells
// out to those tools.
func checkClaudeBinary() (bool, string) {
	p, err := exec.LookPath("claude")
	if err != nil {
		return false, "not found on PATH (install Claude Code from https://claude.com/code)"
	}
	return true, p
}

func checkVersionCurrent() (bool, string) {
	if Version == "dev" || Version == "unknown" || Version == "" {
		return true, "running dev build"
	}
	checker := update.NewChecker(Version)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := checker.Check(ctx)
	if err != nil {
		if errors.Is(err, update.ErrNoReleases) {
			return true, "no releases yet"
		}
		return false, fmt.Sprintf("unable to check: %v", err)
	}
	if result.HasUpdate {
		return false, fmt.Sprintf("%s available (current: %s)", result.LatestVersion, Version)
	}
	return true, fmt.Sprintf("up to date (%s)", Version)
}

func checkKeychain() (bool, string) {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err == nil {
			return true, "security available"
		}
		return false, "security not found on PATH"
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil {
			return true, "secret-tool available"
		}
		return true, "no keyring helper found (optional)"
	case "windows":
		return true, "Windows Credential Manager available"
	default:
		return true, "keychain check not implemented for this OS"
	}
}
