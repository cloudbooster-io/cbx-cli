package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// runLLMModel executes `cbx llm model <args...>` against an isolated config
// dir and returns stdout.
func runLLMModel(t *testing.T, args ...string) string {
	t.Helper()
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"llm", "model"}, args...))
	if err := cmd.Execute(); err != nil {
		t.Fatalf("llm model %v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

func TestLLMModel_SetGetClear_CLIExecutor(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())

	// Set: creates a settings-only executor entry.
	runLLMModel(t, "claude-code", "claude-opus-4-8")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.LLM.Providers["claude-code"]
	if p.Model != "claude-opus-4-8" {
		t.Fatalf("stored model = %q, want claude-opus-4-8", p.Model)
	}
	if p.AuthMode != config.AuthModeCLIExecutor {
		t.Fatalf("auth mode = %q, want %q (no token must be implied)", p.AuthMode, config.AuthModeCLIExecutor)
	}
	if p.LoggedIn {
		t.Fatal("executor settings entry must not claim logged_in")
	}

	// Clear: drops the settings-only entry entirely.
	runLLMModel(t, "claude-code", "--clear")
	cfg, _ = config.Load()
	if _, ok := cfg.LLM.Providers["claude-code"]; ok {
		t.Fatal("clear must remove the settings-only executor entry")
	}
}

func TestLLMModel_ClearAPIProvider_RevertsToRegistryDefault(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())

	// Simulate a logged-in api provider with a custom model.
	cfg, _ := config.Load()
	cfg.LLM.Providers["claude"] = config.LLMProvider{
		Name: "claude", Model: "claude-opus-4-8",
		LoggedIn: true, AuthMode: config.AuthModeAPIKey,
	}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	runLLMModel(t, "claude", "--clear")
	cfg, _ = config.Load()
	p, ok := cfg.LLM.Providers["claude"]
	if !ok {
		t.Fatal("clear must keep the logged-in api entry")
	}
	if p.Model != "claude-sonnet-4-6" {
		t.Fatalf("cleared model = %q, want registry default claude-sonnet-4-6", p.Model)
	}
	if !p.LoggedIn {
		t.Fatal("clear must not log the provider out")
	}
}

func TestLLMModel_UnknownName(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"llm", "model", "gemini", "gemini-pro"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for unknown provider name")
	}
}

func TestLLMModel_List_ShowsDefaults(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())
	out := runLLMModel(t)
	for _, want := range []string{"claude-sonnet-4-6", "claude-code", "codex"} {
		if !strings.Contains(out, want) {
			t.Errorf("list output missing %q:\n%s", want, out)
		}
	}
}

func TestLLMModel_SetMarksPin_ClearUnmarks(t *testing.T) {
	t.Setenv("CBX_CONFIG_DIR", t.TempDir())

	// api provider with login-seeded (unpinned) model.
	cfg, _ := config.Load()
	cfg.LLM.Providers["codex"] = config.LLMProvider{
		Name: "codex", Model: "gpt-5", LoggedIn: true, AuthMode: config.AuthModeAPIKey,
	}
	if err := config.Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	runLLMModel(t, "codex", "gpt-5-codex")
	cfg, _ = config.Load()
	if p := cfg.LLM.Providers["codex"]; !p.ModelPinned || p.Model != "gpt-5-codex" {
		t.Fatalf("set must pin: got model=%q pinned=%v", p.Model, p.ModelPinned)
	}

	runLLMModel(t, "codex", "--clear")
	cfg, _ = config.Load()
	if p := cfg.LLM.Providers["codex"]; p.ModelPinned || p.Model != "gpt-5" {
		t.Fatalf("clear must unpin and restore registry default: got model=%q pinned=%v", p.Model, p.ModelPinned)
	}
}
