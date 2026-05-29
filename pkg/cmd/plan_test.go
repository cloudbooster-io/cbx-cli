package cmd

import (
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// TestPlanLLMSatisfied guards the `cbx plan` LLM precondition (E_NO_LLM). The
// load-bearing case is the reported bug: a CLI-executor default (no api
// provider configured) must satisfy the gate so `cbx plan` runs via the local
// CLI instead of failing with "no LLM provider configured".
func TestPlanLLMSatisfied(t *testing.T) {
	withProviders := func(names ...string) *config.Config {
		c := &config.Config{}
		c.LLM.Providers = map[string]config.LLMProvider{}
		for _, n := range names {
			c.LLM.Providers[n] = config.LLMProvider{Name: n}
		}
		return c
	}

	tests := []struct {
		name     string
		cfg      *config.Config
		override string
		want     bool
	}{
		{
			name: "no providers, no default — blocked",
			cfg:  &config.Config{},
			want: false,
		},
		{
			name: "no providers, claude-code default — allowed (the bug)",
			cfg: func() *config.Config {
				c := &config.Config{}
				c.LLM.Default = "claude-code"
				return c
			}(),
			want: true,
		},
		{
			name:     "no providers, --llm claude-code override — allowed",
			cfg:      &config.Config{},
			override: "claude-code",
			want:     true,
		},
		{
			name: "no providers, codex default — allowed (codex CLI executor)",
			cfg: func() *config.Config {
				c := &config.Config{}
				c.LLM.Default = "codex"
				return c
			}(),
			want: true,
		},
		{
			name:     "no providers, --llm codex override — allowed",
			cfg:      &config.Config{},
			override: "codex",
			want:     true,
		},
		{
			name: "one api provider, no default — allowed",
			cfg:  withProviders("claude"),
			want: true,
		},
		{
			name:     "api provider configured but --llm claude-code override — allowed via CLI",
			cfg:      withProviders("claude"),
			override: "claude-code",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := planLLMSatisfied(tt.cfg, tt.override); got != tt.want {
				t.Errorf("planLLMSatisfied(override=%q) = %v, want %v", tt.override, got, tt.want)
			}
		})
	}
}
