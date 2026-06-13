package e2e

import (
	"os"
	"path/filepath"
	"testing"
)

// llmEnv mocks the keychain and skips live token validation so `cbx llm
// api login` works hermetically in tests.
var llmEnv = map[string]string{
	"CBX_KEYCHAIN_MOCK":     "1",
	"CBX_LLM_SKIP_VALIDATE": "1",
}

// TestConfigIsolationFromRunnerXDG reproduces the GitHub-runner condition
// behind issue #13: the host environment sets XDG_CONFIG_HOME, which
// config.Dir() prefers over $HOME. Before the helpers pinned the XDG vars
// inside the per-test home, every cbx child process shared — and raced
// on — one runner-level config.json. Deliberately not parallel: t.Setenv
// mutates this test process's environment, which cbx children inherit.
func TestConfigIsolationFromRunnerXDG(t *testing.T) {
	hostXDG := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", hostXDG)

	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatalf("creating fake home: %v", err)
	}

	_, stderr, code := runCBXWithHome(t, home, llmEnv, "llm", "api", "login", "claude", "--token", "sk-ant-test123")
	if code != 0 {
		t.Fatalf("login failed with code %d\nstderr:\n%s", code, stderr)
	}

	if _, err := os.Stat(filepath.Join(home, ".config", "cbx", "config.json")); err != nil {
		t.Fatalf("expected config.json under the isolated home: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hostXDG, "cbx", "config.json")); err == nil {
		t.Fatal("config.json leaked into the host-level XDG_CONFIG_HOME")
	}
}
