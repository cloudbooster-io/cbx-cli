package cmd

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// writeFakeCodexCLI installs a fake `codex` on PATH that drains stdin and
// serves a canned completion. A non-zero promptExit prints promptOut on
// STDOUT — mirroring how the real CLI reports prompt-time failures (auth,
// model, limits). Mirrors writeFakeClaudeCLI.
func writeFakeCodexCLI(t *testing.T, promptOut string, promptExit int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"cat > /dev/null\n" +
		"printf '%s' '" + strings.ReplaceAll(promptOut, "'", `'\''`) + "'\n" +
		"exit " + itoaCodex(promptExit) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "codex"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake codex: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func itoaCodex(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestResolveAuditExecutor(t *testing.T) {
	for _, name := range []string{audit.ClaudeCodeProvider, audit.CodexProvider} {
		got, err := resolveAuditExecutor(name)
		if err != nil {
			t.Errorf("resolveAuditExecutor(%q) errored: %v", name, err)
		}
		if got != name {
			t.Errorf("resolveAuditExecutor(%q) = %q, want %q", name, got, name)
		}
	}
	_, err := resolveAuditExecutor("gpt-4o")
	if err == nil {
		t.Fatal("expected error for an unknown executor")
	}
	if !strings.Contains(err.Error(), "E_LLM_EXECUTOR") {
		t.Errorf("error should carry the E_LLM_EXECUTOR code; got %v", err)
	}
}

// TestResolveAuditExecutor_HonorsConfigDefault pins the fix for the gap
// where `cbx audit aws` ignored `cbx llm default`: an empty --llm-executor
// (flag not set) must fall back to the configured default when it names a
// grounded-capable CLI executor, and to claude-code otherwise.
func TestResolveAuditExecutor_HonorsConfigDefault(t *testing.T) {
	cases := []struct {
		name       string
		configDflt string
		wantExec   string
	}{
		{"unset default falls back to claude-code", "", audit.ClaudeCodeProvider},
		{"codex default is honored", audit.CodexProvider, audit.CodexProvider},
		{"claude-code default is honored", audit.ClaudeCodeProvider, audit.ClaudeCodeProvider},
		{"api-provider default the grounded loop can't drive falls back", "claude", audit.ClaudeCodeProvider},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CBX_CONFIG_DIR", t.TempDir())
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("load config: %v", err)
			}
			cfg.LLM.Default = tc.configDflt
			if err := config.Save(cfg); err != nil {
				t.Fatalf("save config: %v", err)
			}
			// Empty flag = "--llm-executor not passed" → consult config.
			got, err := resolveAuditExecutor("")
			if err != nil {
				t.Fatalf("resolveAuditExecutor(\"\"): %v", err)
			}
			if got != tc.wantExec {
				t.Errorf("with cbx llm default %q, audit executor = %q, want %q", tc.configDflt, got, tc.wantExec)
			}
		})
	}

	// An explicit flag always wins over the configured default.
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	cfg, _ := config.Load()
	cfg.LLM.Default = audit.CodexProvider
	_ = config.Save(cfg)
	if got, _ := resolveAuditExecutor(audit.ClaudeCodeProvider); got != audit.ClaudeCodeProvider {
		t.Errorf("explicit --llm-executor claude-code should win over codex default; got %q", got)
	}
}

func TestExecutorBinaryName(t *testing.T) {
	if got := executorBinaryName(audit.CodexProvider); got != "codex" {
		t.Errorf("executorBinaryName(codex) = %q, want codex", got)
	}
	if got := executorBinaryName(audit.ClaudeCodeProvider); got != "claude" {
		t.Errorf("executorBinaryName(claude-code) = %q, want claude", got)
	}
}

func TestResolveAuditLLMModel_PerExecutorPin(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	cfg, _ := config.Load()
	cfg.LLM.Providers[audit.CodexProvider] = config.LLMProvider{
		Name: audit.CodexProvider, Model: "gpt-5-codex",
		ModelPinned: true, AuthMode: config.AuthModeCLIExecutor,
	}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// No flag → falls back to the codex executor's pinned model.
	if got := resolveAuditLLMModel("", audit.CodexProvider); got != "gpt-5-codex" {
		t.Errorf("resolveAuditLLMModel(\"\", codex) = %q, want gpt-5-codex", got)
	}
	// The flag always wins.
	if got := resolveAuditLLMModel("o4-mini", audit.CodexProvider); got != "o4-mini" {
		t.Errorf("--llm-model must win; got %q", got)
	}
	// A different executor with no pin → CLI's own default ("").
	if got := resolveAuditLLMModel("", audit.ClaudeCodeProvider); got != "" {
		t.Errorf("unpinned claude-code should resolve to empty; got %q", got)
	}
}

func TestPreflightAuditLLM_Codex_OK(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	writeFakeCodexCLI(t, "ok", 0)

	if err := preflightAuditLLM(context.Background(), audit.CodexProvider, ""); err != nil {
		t.Fatalf("preflightAuditLLM(codex) should pass with a working fake: %v", err)
	}
}

func TestPreflightAuditLLM_Codex_MissingBinaryAborts(t *testing.T) {
	// Empty PATH so the codex probe can't resolve the binary — the audit
	// must abort here (E_LLM_PREFLIGHT) before any AWS spend.
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	t.Setenv("PATH", "")

	err := preflightAuditLLM(context.Background(), audit.CodexProvider, "")
	if err == nil {
		t.Fatal("expected preflight to abort when codex is missing")
	}
	if !strings.Contains(err.Error(), "E_LLM_PREFLIGHT") {
		t.Errorf("error should carry E_LLM_PREFLIGHT; got %v", err)
	}
	if !strings.Contains(err.Error(), "codex") {
		t.Errorf("error should name the codex CLI; got %v", err)
	}
}

func TestPreflightAuditLLM_Codex_FailureSurfacesCLIMessage(t *testing.T) {
	// The binary resolves but the prompt fails — the gap the probe exists
	// to close. The error must carry the CLI's own message + the debug hint
	// pointing at `cbx llm cli test codex`.
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	writeFakeCodexCLI(t, "stream error: 401 Unauthorized", 1)

	err := preflightAuditLLM(context.Background(), audit.CodexProvider, "")
	if err == nil {
		t.Fatal("expected the prompt probe to fail the preflight")
	}
	if !strings.Contains(err.Error(), "401 Unauthorized") {
		t.Errorf("error should carry the CLI's own message; got %v", err)
	}
	if !strings.Contains(err.Error(), "cbx llm cli test codex") {
		t.Errorf("fix hint should target codex; got %v", err)
	}
}
