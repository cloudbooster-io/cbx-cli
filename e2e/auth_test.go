package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthFlow(t *testing.T) {
	t.Parallel()

	t.Run("login_logout_status_cycle", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")
		keyringDir := filepath.Join(tmpDir, "keyring")

		// Start a mock OAuth server.
		mux := http.NewServeMux()
		server := httptest.NewServer(mux)
		defer server.Close()

		mux.HandleFunc("/v1/auth/cli/device", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":               "device-123",
				"user_code":                 "ABCD-EFGH",
				"verification_uri":          server.URL + "/verify",
				"verification_uri_complete": server.URL + "/verify?user_code=ABCD-EFGH",
				"expires_in":                600,
				"interval":                  1,
			})
		})

		mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "test-access-token",
				"token_type":    "Bearer",
				"refresh_token": "test-refresh-token",
				"expires_in":    3600,
				"email":         "alice@example.com",
			})
		})

		mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"email": "alice@example.com"})
		})

		env := map[string]string{
			"CB_API_URL":            server.URL,
			"CB_KEYRING_BACKEND":    "file",
			"CB_KEYRING_FILE_DIR":   keyringDir,
		}

		// Initial status: not logged in
		stdout, _, code := runCBXWithHome(t, homeDir, env, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "Not logged in") {
			t.Fatalf("expected 'Not logged in', got: %s", stdout)
		}

		// Login via device-code flow (avoids browser dependency).
		_, _, code = runCBXWithHome(t, homeDir, env, "login", "--device-code")
		if code != 0 {
			t.Fatalf("login failed: %d", code)
		}

		// Status after login
		stdout, _, code = runCBXWithHome(t, homeDir, env, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "alice@example.com") {
			t.Fatalf("expected email in status, got: %s", stdout)
		}

		// Logout
		_, _, code = runCBXWithHome(t, homeDir, env, "logout")
		if code != 0 {
			t.Fatalf("logout failed: %d", code)
		}

		// Status after logout
		stdout, _, code = runCBXWithHome(t, homeDir, env, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "Not logged in") {
			t.Fatalf("expected 'Not logged in' after logout, got: %s", stdout)
		}
	})

	t.Run("llm_login_list_default_logout", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")
		env := map[string]string{
			"CBX_KEYCHAIN_MOCK":     "1",
			"CBX_LLM_SKIP_VALIDATE": "1",
		}

		// List: empty
		stdout, _, code := runCBXWithHome(t, homeDir, env, "llm", "list")
		if code != 0 {
			t.Fatalf("llm list failed: %d", code)
		}
		if !strings.Contains(stdout, "No LLM providers") {
			t.Fatalf("expected empty list, got: %s", stdout)
		}

		// Login claude with fake token that passes format validation
		_, _, code = runCBXWithHome(t, homeDir, env, "llm", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("llm login claude failed: %d", code)
		}

		// List: shows claude
		stdout, _, code = runCBXWithHome(t, homeDir, env, "llm", "list")
		if code != 0 {
			t.Fatalf("llm list failed: %d", code)
		}
		if !strings.Contains(stdout, "claude") {
			t.Fatalf("expected claude in list, got: %s", stdout)
		}
		if !strings.Contains(stdout, "(default)") {
			t.Fatalf("expected claude marked as default, got: %s", stdout)
		}

		// Login codex
		_, _, code = runCBXWithHome(t, homeDir, env, "llm", "login", "codex", "--token", "sk-test456")
		if code != 0 {
			t.Fatalf("llm login codex failed: %d", code)
		}

		// Set default to codex
		_, _, code = runCBXWithHome(t, homeDir, env, "llm", "default", "codex")
		if code != 0 {
			t.Fatalf("llm default codex failed: %d", code)
		}

		// List: codex is default
		stdout, _, code = runCBXWithHome(t, homeDir, env, "llm", "list")
		if code != 0 {
			t.Fatalf("llm list failed: %d", code)
		}
		if !strings.Contains(stdout, "codex (default)") {
			t.Fatalf("expected codex as default, got: %s", stdout)
		}

		// Logout claude
		_, _, code = runCBXWithHome(t, homeDir, env, "llm", "logout", "claude")
		if code != 0 {
			t.Fatalf("llm logout claude failed: %d", code)
		}

		// List: only codex
		stdout, _, code = runCBXWithHome(t, homeDir, env, "llm", "list")
		if code != 0 {
			t.Fatalf("llm list failed: %d", code)
		}
		if strings.Contains(stdout, "claude") {
			t.Fatalf("expected claude removed, got: %s", stdout)
		}
	})

	t.Run("llm_default_without_login_fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		_, stderr, code := runCBXWithHome(t, homeDir, nil, "llm", "default", "claude")
		if code == 0 {
			t.Fatal("expected llm default to fail for unknown provider")
		}
		if !strings.Contains(stderr, "not logged in") {
			t.Fatalf("expected 'not logged in' error, got: %s", stderr)
		}
	})
}
