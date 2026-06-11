// Package llm implements the concrete LLM providers (Claude, Codex) behind
// the provider-agnostic contract defined in core/llm. The contract types are
// aliased below so existing internal consumers keep importing this package
// unchanged.
package llm

import (
	"fmt"

	corellm "github.com/cloudbooster-io/cbx-cli/core/llm"
)

// CompleteOptions, LLMClient and Stream are defined in core/llm (the shared,
// internal-free contract) and aliased here for internal consumers.
type (
	// CompleteOptions tunes a single completion request.
	CompleteOptions = corellm.CompleteOptions
	// LLMClient is the abstract interface for all LLM providers.
	LLMClient = corellm.LLMClient
	// Stream yields tokens from an LLM completion one at a time.
	Stream = corellm.Stream
)

// NewTestStream creates a Stream for use in tests outside this package.
func NewTestStream(tokens <-chan string) *Stream {
	return corellm.NewTestStream(tokens)
}

// newStream creates a Stream from a token channel. The caller must close the
// channel when the stream is finished and then call SetErr if an error occurred.
func newStream(tokens <-chan string) *Stream {
	return corellm.NewStream(tokens)
}

// ClientConfig holds the minimal credentials needed to instantiate a provider.
type ClientConfig struct {
	BaseURL string
	APIKey  string
	Model   string
}

// Validate returns an error if the config is insufficient.
func (c ClientConfig) Validate() error {
	if c.APIKey == "" {
		return fmt.Errorf("API key is required")
	}
	return nil
}
