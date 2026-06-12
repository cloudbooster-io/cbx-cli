package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
			"CB_API_URL":          server.URL,
			"CB_KEYRING_BACKEND":  "file",
			"CB_KEYRING_FILE_DIR": keyringDir,
		}

		// Initial status: not logged in
		stdout, _, code := runCBXWithHome(t, homeDir, env, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "not logged in") {
			t.Fatalf("expected 'not logged in', got: %s", stdout)
		}

		// Login via device-code flow (avoids browser dependency).
		_, _, code = runCBXWithHome(t, homeDir, env, "login", "--device-code")
		if code != 0 {
			t.Fatalf("login failed: %d", code)
		}

		// Status after login — should show table with email
		stdout, _, code = runCBXWithHome(t, homeDir, env, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "alice@example.com") {
			t.Fatalf("expected email in status, got: %s", stdout)
		}
		if !strings.Contains(strings.ToLower(stdout), "account") {
			t.Fatalf("expected account row in status, got: %s", stdout)
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
		if !strings.Contains(stdout, "not logged in") {
			t.Fatalf("expected 'not logged in' after logout, got: %s", stdout)
		}
	})

	t.Run("login_no_browser_paste_back", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")
		keyringDir := filepath.Join(tmpDir, "keyring")

		mux := http.NewServeMux()
		server := httptest.NewServer(mux)
		defer server.Close()

		mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "no-browser-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"email":        "paste@example.com",
			})
		})

		env := map[string]string{
			"CB_API_URL":          server.URL,
			"CB_KEYRING_BACKEND":  "file",
			"CB_KEYRING_FILE_DIR": keyringDir,
		}

		// Run login --no-browser with piped stdin containing the code.
		_, stderr, code := runCBXInteractive(t, homeDir, "", env, []string{"my-auth-code"}, "login", "--no-browser")
		if code != 0 {
			t.Fatalf("login --no-browser failed: %d", code)
		}
		if !strings.Contains(stderr, "Please open the following URL") {
			t.Fatalf("expected auth URL prompt, got: %s", stderr)
		}

		// Verify status shows the new user
		mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"email": "paste@example.com"})
		})

		stdout, _, code := runCBXWithHome(t, homeDir, env, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "paste@example.com") {
			t.Fatalf("expected paste@example.com in status, got: %s", stdout)
		}
	})

	t.Run("login_logout_status_json", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")
		keyringDir := filepath.Join(tmpDir, "keyring")

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
				"access_token": "json-test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"email":        "json@example.com",
			})
		})

		mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"email": "json@example.com"})
		})

		env := map[string]string{
			"CB_API_URL":          server.URL,
			"CB_KEYRING_BACKEND":  "file",
			"CB_KEYRING_FILE_DIR": keyringDir,
		}

		// JSON status before login
		stdout, _, code := runCBXWithHome(t, homeDir, env, "status", "--json")
		if code != 0 {
			t.Fatalf("status --json failed: %d", code)
		}
		requireJSONValid(t, stdout)
		if !strings.Contains(stdout, "not_logged_in") {
			t.Fatalf("expected not_logged_in in JSON, got: %s", stdout)
		}

		// JSON login
		stdout, _, code = runCBXWithHome(t, homeDir, env, "login", "--device-code", "--json")
		if code != 0 {
			t.Fatalf("login --json failed: %d", code)
		}
		requireJSONValid(t, stdout)
		if !strings.Contains(stdout, "json@example.com") {
			t.Fatalf("expected email in JSON login, got: %s", stdout)
		}

		// JSON status after login
		stdout, _, code = runCBXWithHome(t, homeDir, env, "status", "--json")
		if code != 0 {
			t.Fatalf("status --json failed: %d", code)
		}
		requireJSONValid(t, stdout)
		if !strings.Contains(stdout, "json@example.com") {
			t.Fatalf("expected email in JSON status, got: %s", stdout)
		}
		if !strings.Contains(stdout, "fingerprint") {
			t.Fatalf("expected fingerprint in JSON status, got: %s", stdout)
		}

		// JSON logout
		stdout, _, code = runCBXWithHome(t, homeDir, env, "logout", "--json")
		if code != 0 {
			t.Fatalf("logout --json failed: %d", code)
		}
		requireJSONValid(t, stdout)
		if !strings.Contains(stdout, "logged_out") {
			t.Fatalf("expected logged_out in JSON logout, got: %s", stdout)
		}
	})

	t.Run("status_dead_token", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")
		keyringDir := filepath.Join(tmpDir, "keyring")

		mux := http.NewServeMux()
		server := httptest.NewServer(mux)
		defer server.Close()

		// exchangeShouldFail controls whether the exchange endpoint returns 401.
		var exchangeShouldFail atomic.Bool
		mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
			if exchangeShouldFail.Load() {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "dead-token",
				"token_type":    "Bearer",
				"refresh_token": "dead-refresh",
				"expires_in":    1, // expires in 1 second
				"email":         "dead@example.com",
			})
		})

		// /v1/me returns 401 once the token is dead.
		mux.HandleFunc("/v1/me", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})

		mux.HandleFunc("/v1/auth/cli/device", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"device_code":      "device-123",
				"user_code":        "ABCD-EFGH",
				"verification_uri": server.URL + "/verify",
				"expires_in":       600,
				"interval":         1,
			})
		})

		env := map[string]string{
			"CB_API_URL":          server.URL,
			"CB_KEYRING_BACKEND":  "file",
			"CB_KEYRING_FILE_DIR": keyringDir,
		}

		// First, log in with a token that expires quickly.
		_, _, code := runCBXWithHome(t, homeDir, env, "login", "--device-code")
		if code != 0 {
			t.Fatalf("login failed: %d", code)
		}

		// Wait for token to expire.
		time.Sleep(2 * time.Second)

		// Now make exchange return 401 so refresh fails.
		exchangeShouldFail.Store(true)

		// Status should report expired token.
		_, stderr, code := runCBXWithHome(t, homeDir, env, "status")
		if code == 0 {
			t.Fatal("expected status to fail with expired token")
		}
		if !strings.Contains(stderr, "expired") && !strings.Contains(stderr, "cbx login") {
			t.Fatalf("expected expired token error pointing to login, got stderr: %s", stderr)
		}
	})

	t.Run("llm_login_list_default_logout", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")
		env := map[string]string{
			"CBX_KEYCHAIN_MOCK":     "1",
			"CBX_LLM_SKIP_VALIDATE": "1",
		}

		// List api providers: empty
		stdout, stderr, code := runCBXWithHome(t, homeDir, env, "llm", "api", "list")
		if code != 0 {
			t.Fatalf("llm api list failed: %d\nstderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "no providers configured") {
			t.Fatalf("expected empty api list, got: %s", stdout)
		}

		// Login claude with fake token that passes format validation
		_, stderr, code = runCBXWithHome(t, homeDir, env, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
		if code != 0 {
			t.Fatalf("llm api login claude failed: %d\nstderr:\n%s", code, stderr)
		}

		// List: shows claude
		stdout, stderr, code = runCBXWithHome(t, homeDir, env, "llm", "api", "list")
		if code != 0 {
			t.Fatalf("llm api list failed: %d\nstderr:\n%s", code, stderr)
		}
		if !strings.Contains(stdout, "claude") {
			t.Fatalf("expected claude in api list, got: %s", stdout)
		}
		if !strings.Contains(strings.ToLower(stdout), "default") {
			t.Fatalf("expected claude marked as default, got: %s", stdout)
		}

		// Login codex
		_, stderr, code = runCBXWithHome(t, homeDir, env, "llm", "api", "login", "codex", "--token", "sk-test456")
		if code != 0 {
			t.Fatalf("llm api login codex failed: %d\nstderr:\n%s", code, stderr)
		}

		// Set default to codex
		_, stderr, code = runCBXWithHome(t, homeDir, env, "llm", "default", "codex")
		if code != 0 {
			t.Fatalf("llm default codex failed: %d\nstderr:\n%s", code, stderr)
		}

		// List: codex is default
		stdout, stderr, code = runCBXWithHome(t, homeDir, env, "llm", "api", "list")
		if code != 0 {
			t.Fatalf("llm api list failed: %d\nstderr:\n%s", code, stderr)
		}
		// Match "codex" appearing on a row containing "default" (chip rendering).
		if !strings.Contains(stdout, "codex") || !strings.Contains(strings.ToLower(stdout), "default") {
			t.Fatalf("expected codex as default, got: %s", stdout)
		}

		// Logout claude
		_, stderr, code = runCBXWithHome(t, homeDir, env, "llm", "api", "logout", "claude")
		if code != 0 {
			t.Fatalf("llm api logout claude failed: %d\nstderr:\n%s", code, stderr)
		}

		// List: only codex
		stdout, stderr, code = runCBXWithHome(t, homeDir, env, "llm", "api", "list")
		if code != 0 {
			t.Fatalf("llm api list failed: %d\nstderr:\n%s", code, stderr)
		}
		if strings.Contains(stdout, "claude") {
			t.Fatalf("expected claude removed from api list, got: %s", stdout)
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
