package e2e

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthFlow(t *testing.T) {
	t.Parallel()

	t.Run("login_logout_status_cycle", func(t *testing.T) {
		tmpDir := t.TempDir()
		homeDir := filepath.Join(tmpDir, "home")

		// Initial status: not logged in
		stdout, _, code := runCBXWithHome(t, homeDir, nil, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "Not logged in") {
			t.Fatalf("expected 'Not logged in', got: %s", stdout)
		}

		// Login
		_, _, code = runCBXWithHome(t, homeDir, nil, "login")
		if code != 0 {
			t.Fatalf("login failed: %d", code)
		}

		// Status after login
		stdout, _, code = runCBXWithHome(t, homeDir, nil, "status")
		if code != 0 {
			t.Fatalf("status failed: %d", code)
		}
		if !strings.Contains(stdout, "user@example.com") {
			t.Fatalf("expected email in status, got: %s", stdout)
		}

		// Logout
		_, _, code = runCBXWithHome(t, homeDir, nil, "logout")
		if code != 0 {
			t.Fatalf("logout failed: %d", code)
		}

		// Status after logout
		stdout, _, code = runCBXWithHome(t, homeDir, nil, "status")
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

		// List: empty
		stdout, _, code := runCBXWithHome(t, homeDir, nil, "llm", "list")
		if code != 0 {
			t.Fatalf("llm list failed: %d", code)
		}
		if !strings.Contains(stdout, "No LLM providers") {
			t.Fatalf("expected empty list, got: %s", stdout)
		}

		// Login claude
		_, _, code = runCBXWithHome(t, homeDir, nil, "llm", "login", "claude")
		if code != 0 {
			t.Fatalf("llm login claude failed: %d", code)
		}

		// List: shows claude
		stdout, _, code = runCBXWithHome(t, homeDir, nil, "llm", "list")
		if code != 0 {
			t.Fatalf("llm list failed: %d", code)
		}
		if !strings.Contains(stdout, "claude") {
			t.Fatalf("expected claude in list, got: %s", stdout)
		}
		if !strings.Contains(stdout, "(default)") {
			t.Fatalf("expected claude marked as default, got: %s", stdout)
		}

		// Login openai
		_, _, code = runCBXWithHome(t, homeDir, nil, "llm", "login", "openai")
		if code != 0 {
			t.Fatalf("llm login openai failed: %d", code)
		}

		// Set default to openai
		_, _, code = runCBXWithHome(t, homeDir, nil, "llm", "default", "openai")
		if code != 0 {
			t.Fatalf("llm default openai failed: %d", code)
		}

		// List: openai is default
		stdout, _, code = runCBXWithHome(t, homeDir, nil, "llm", "list")
		if code != 0 {
			t.Fatalf("llm list failed: %d", code)
		}
		if !strings.Contains(stdout, "openai (default)") {
			t.Fatalf("expected openai as default, got: %s", stdout)
		}

		// Logout claude
		_, _, code = runCBXWithHome(t, homeDir, nil, "llm", "logout", "claude")
		if code != 0 {
			t.Fatalf("llm logout claude failed: %d", code)
		}

		// List: only openai
		stdout, _, code = runCBXWithHome(t, homeDir, nil, "llm", "list")
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
