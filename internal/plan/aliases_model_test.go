package plan

import (
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// The "codex" config slot is shared between the api provider and the CLI
// executor. A login-seeded (unpinned) model must not leak into the local
// CLI's argv; a deliberate `cbx llm model` pin must ride through.
func TestRunnerConfigFromConfig_UnpinnedExecutorModelBlanked(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Providers: map[string]config.LLMProvider{
		"codex":  {Name: "codex", Model: "gpt-5", AuthMode: config.AuthModeAPIKey},
		"claude": {Name: "claude", Model: "claude-sonnet-4-6", AuthMode: config.AuthModeAPIKey},
	}}}

	rc := RunnerConfigFromConfig(cfg)
	if m := rc.Providers["codex"].Model; m != "" {
		t.Errorf("unpinned model on the codex CLI-executor slot must be blanked, got %q", m)
	}
	if m := rc.Providers["claude"].Model; m != "claude-sonnet-4-6" {
		t.Errorf("api-only provider model must be kept, got %q", m)
	}
}

func TestRunnerConfigFromConfig_PinnedExecutorModelKept(t *testing.T) {
	cfg := &config.Config{LLM: config.LLMConfig{Providers: map[string]config.LLMProvider{
		"codex":       {Name: "codex", Model: "gpt-5-codex", ModelPinned: true, AuthMode: config.AuthModeAPIKey},
		"claude-code": {Name: "claude-code", Model: "claude-opus-4-8", ModelPinned: true, AuthMode: config.AuthModeCLIExecutor},
	}}}

	rc := RunnerConfigFromConfig(cfg)
	if m := rc.Providers["codex"].Model; m != "gpt-5-codex" {
		t.Errorf("pinned codex model must ride through, got %q", m)
	}
	if m := rc.Providers["claude-code"].Model; m != "claude-opus-4-8" {
		t.Errorf("pinned claude-code model must ride through, got %q", m)
	}
}
