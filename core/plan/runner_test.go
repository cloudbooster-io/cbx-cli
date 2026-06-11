package plan

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetProvider(t *testing.T) {
	cfg := RunnerConfig{DefaultProvider: "claude"}

	if got := GetProvider(&Session{}, cfg); got != "claude" {
		t.Errorf("GetProvider with no session override = %q, want %q", got, "claude")
	}
	if got := GetProvider(&Session{ActiveProvider: "openai"}, cfg); got != "openai" {
		t.Errorf("GetProvider with session override = %q, want %q", got, "openai")
	}
}

func TestRunner_UnconfiguredProvider(t *testing.T) {
	// An HTTP api provider that is missing from cfg.Providers must fail fast.
	runner := NewRunner(RunnerConfig{DefaultProvider: "claude"}, "", "", nil)
	_, err := runner.Run(context.Background(), "static site", &captureProgress{})
	if err == nil {
		t.Fatal("expected error for an unconfigured provider")
	}
	if !strings.Contains(err.Error(), "provider claude not configured") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestRunner_ConfiguredProviderPlumbing verifies RunnerConfig end to end: the
// Providers map entry and the injected llmToken resolver reach the LLMCaller,
// and the streamed tokens come back through Progress.
func TestRunner_ConfiguredProviderPlumbing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if key := r.Header.Get("x-api-key"); key != "sk-test" {
			t.Errorf("unexpected api key: %s", key)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"ranked\"}}")
		fmt.Fprintln(w, "data: [DONE]")
	}))
	defer srv.Close()

	cfg := RunnerConfig{
		DefaultProvider: "claude",
		Providers: map[string]LLMProvider{
			"claude": {Name: "claude", BaseURL: srv.URL, Model: "claude-test"},
		},
	}
	llmToken := func(provider string) string {
		if provider != "claude" {
			t.Errorf("llmToken resolver called with %q, want %q", provider, "claude")
		}
		return "sk-test"
	}

	runner := NewRunner(cfg, "", "", llmToken)
	var streamed strings.Builder
	prog := &captureProgress{onToken: func(tok string) { streamed.WriteString(tok) }}

	plan, err := runner.Run(context.Background(), "S3 + Lambda image processor", prog)
	if err != nil {
		t.Fatalf("Run with configured provider: %v", err)
	}
	if plan == nil {
		t.Fatal("expected a plan, got nil")
	}
	if !strings.Contains(streamed.String(), "ranked") {
		t.Errorf("expected the fake LLM output to be streamed; got %q", streamed.String())
	}
}
