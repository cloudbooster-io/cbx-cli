package llm

import (
	"testing"
)

func TestValidateTokenFormatClaude(t *testing.T) {
	if err := ValidateTokenFormat("claude", "sk-ant-api03-test"); err != nil {
		t.Fatalf("expected valid claude token, got: %v", err)
	}
	if err := ValidateTokenFormat("claude", "bad-token"); err == nil {
		t.Fatal("expected error for invalid claude token format")
	}
}

func TestValidateTokenFormatCodex(t *testing.T) {
	if err := ValidateTokenFormat("codex", "sk-test123"); err != nil {
		t.Fatalf("expected valid codex token, got: %v", err)
	}
	if err := ValidateTokenFormat("codex", "bad-token"); err == nil {
		t.Fatal("expected error for invalid codex token format")
	}
}

func TestValidateTokenFormatUnknownProvider(t *testing.T) {
	if err := ValidateTokenFormat("openai", "sk-test"); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestProvidersMap(t *testing.T) {
	if _, ok := Providers["claude"]; !ok {
		t.Fatal("expected claude in Providers map")
	}
	if _, ok := Providers["codex"]; !ok {
		t.Fatal("expected codex in Providers map")
	}
	if _, ok := Providers["openai"]; ok {
		t.Fatal("expected openai to be removed from Providers map")
	}
	if _, ok := Providers["ollama"]; ok {
		t.Fatal("expected ollama to be removed from Providers map")
	}
}
