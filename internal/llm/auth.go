// Package llm handles LLM provider authentication and token management.
package llm

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/keychain"
)

// Provider represents a supported LLM provider.
type Provider struct {
	Name    string
	BaseURL string
	Model   string
}

// Supported providers. Model is the default the provider starts with after
// `cbx llm api login`; users override it per provider with `cbx llm model`.
var Providers = map[string]Provider{
	"claude": {
		Name:    "claude",
		BaseURL: "https://api.anthropic.com",
		Model:   "claude-sonnet-4-6",
	},
	"codex": {
		Name:    "codex",
		BaseURL: "https://api.openai.com",
		Model:   "gpt-5",
	},
}

// ValidateTokenFormat checks that a token looks plausible for the provider.
// This is a lightweight local validation (no network call).
func ValidateTokenFormat(provider, token string) error {
	switch provider {
	case "claude":
		if !strings.HasPrefix(token, "sk-ant-") {
			return fmt.Errorf("invalid Anthropic API key format: expected sk-ant-... prefix")
		}
	case "codex":
		if !strings.HasPrefix(token, "sk-") {
			return fmt.Errorf("invalid OpenAI API key format: expected sk-... prefix")
		}
	default:
		return fmt.Errorf("unknown provider: %s", provider)
	}
	return nil
}

// ValidateToken makes a lightweight HTTP call to verify the token is active.
// It can be skipped in tests by setting CBX_LLM_SKIP_VALIDATE=1.
func ValidateToken(provider, token string) error {
	if skip := os.Getenv("CBX_LLM_SKIP_VALIDATE"); skip == "1" {
		return nil
	}

	client := &http.Client{Timeout: 10 * time.Second}
	switch provider {
	case "claude":
		return validateClaude(client, token)
	case "codex":
		return validateCodex(client, token)
	default:
		return fmt.Errorf("unknown provider: %s", provider)
	}
}

func validateClaude(client *http.Client, token string) error {
	req, err := http.NewRequest("GET", "https://api.anthropic.com/v1/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("x-api-key", token)
	req.Header.Set("anthropic-version", "2023-06-01")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("validating Claude token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid Claude API key")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("claude API returned status %d", resp.StatusCode)
	}
	return nil
}

func validateCodex(client *http.Client, token string) error {
	req, err := http.NewRequest("GET", "https://api.openai.com/v1/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("validating Codex token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid OpenAI API key")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OpenAI API returned status %d", resp.StatusCode)
	}
	return nil
}

// StoreToken saves a provider token to the keychain.
func StoreToken(provider, token string) error {
	return keychain.Set(provider, token)
}

// GetToken retrieves a provider token from the keychain.
func GetToken(provider string) (string, error) {
	return keychain.Get(provider)
}

// DeleteToken removes a provider token from the keychain.
func DeleteToken(provider string) error {
	return keychain.Delete(provider)
}
