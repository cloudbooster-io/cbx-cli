//go:build e2e_staging

package e2e

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestStagingConnectivity verifies that the CLI can communicate with the
// staging API endpoint configured via CB_API_URL. This is the gating test
// for AC#5 — it must pass before merge.
func TestStagingConnectivity(t *testing.T) {
	t.Parallel()

	apiURL := os.Getenv("CB_API_URL")
	if apiURL == "" {
		t.Fatal("CB_API_URL is not set — required for staging E2E tests")
	}

	t.Run("doctor_reports_staging_api_reachable", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := tmpDir + "/home"

		stdout, stderr, code := runCBXWithHomeAndDir(t, homeDir, "", map[string]string{
			"CB_API_URL": apiURL,
		}, "doctor")

		if code != 0 {
			t.Fatalf("cbx doctor exited %d against staging; stderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, apiURL) {
			t.Fatalf("expected doctor output to contain staging URL %q, got:\n%s", apiURL, stdout)
		}
		if !strings.Contains(stdout, "OK") {
			t.Fatalf("expected doctor to report staging API as OK, got:\n%s", stdout)
		}
	})

	t.Run("staging_health_endpoint_responds", func(t *testing.T) {
		client := http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(apiURL + "/health")
		if err != nil {
			t.Fatalf("staging health endpoint unreachable: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("staging health endpoint returned HTTP %d, expected 200", resp.StatusCode)
		}
	})

	t.Run("staging_auth_flow", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := tmpDir + "/home"
		keyringDir := tmpDir + "/keyring"

		env := map[string]string{
			"CB_API_URL":          apiURL,
			"CB_KEYRING_BACKEND":  "file",
			"CB_KEYRING_FILE_DIR": keyringDir,
		}

		// Before login: status should report not logged in.
		stdout, stderr, code := runCBXWithHomeAndDir(t, homeDir, "", env, "status")
		if code != 0 {
			t.Fatalf("cbx status exited %d before login; stderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "not logged in") {
			t.Fatalf("expected 'not logged in' before login, got:\n%s", stdout)
		}

		// Login via device-code flow against staging.
		// (We cannot open a browser in CI, so device-code is the only viable
		// option for an automated end-to-end test.)
		_, stderr, code = runCBXWithHomeAndDir(t, homeDir, "", env, "login", "--device-code")
		if code != 0 {
			t.Fatalf("cbx login --device-code exited %d against staging; stderr:\n%s", code, stderr)
		}

		// After login: status should report the user email.
		stdout, stderr, code = runCBXWithHomeAndDir(t, homeDir, "", env, "status")
		if code != 0 {
			t.Fatalf("cbx status exited %d after login; stderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "Account") {
			t.Fatalf("expected status table with 'Account' after login, got:\n%s", stdout)
		}

		// Logout.
		_, stderr, code = runCBXWithHomeAndDir(t, homeDir, "", env, "logout")
		if code != 0 {
			t.Fatalf("cbx logout exited %d against staging; stderr:\n%s", code, stderr)
		}

		// After logout: status should report not logged in.
		stdout, stderr, code = runCBXWithHomeAndDir(t, homeDir, "", env, "status")
		if code != 0 {
			t.Fatalf("cbx status exited %d after logout; stderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "not logged in") {
			t.Fatalf("expected 'not logged in' after logout, got:\n%s", stdout)
		}
	})

	t.Run("plan_headless_against_staging", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := tmpDir + "/home"

		llmEnv := map[string]string{
			"CBX_KEYCHAIN_MOCK":     "1",
			"CBX_LLM_SKIP_VALIDATE": "1",
			"CB_API_URL":            apiURL,
		}

		// Login
		_, _, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, llmEnv, "llm", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("login failed with code %d", code)
		}

		// Plan headless against staging
		stdout, stderr, code := runCBXWithHomeAndDir(t, homeDir, tmpDir, map[string]string{
			"CB_API_URL": apiURL,
		}, "plan", "--no-tui", "static site with auth")
		if code != 0 {
			t.Fatalf("cbx plan exited %d against staging; stderr:\n%s", code, stderr)
		}

		// Byte-stable summary line assertion
		if !strings.Contains(stdout, "Wrote") {
			t.Fatalf("expected summary line with 'Wrote', got:\n%s", stdout)
		}
		if !strings.Contains(stdout, "components") {
			t.Fatalf("expected summary line with 'components', got:\n%s", stdout)
		}

		// plan.md must exist and be valid
		mdPath := tmpDir + "/plan.md"
		requireFileExists(t, mdPath)
		requireFileContains(t, mdPath, "ADR:")
		requireFileContains(t, mdPath, "static site with auth")
	})
}
