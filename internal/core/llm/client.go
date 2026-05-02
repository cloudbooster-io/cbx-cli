// Package llm provides an abstract LLM caller with streaming support.
// It is a clean package boundary — no CloudBooster API client types are
// imported here.
package llm

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// CompleteOptions tunes a single completion request.
type CompleteOptions struct {
	Model       string
	Temperature float64
	MaxTokens   int
	System      string
}

// LLMClient is the abstract interface for all LLM providers.
type LLMClient interface {
	Complete(ctx context.Context, prompt string, opts CompleteOptions) (*Stream, error)
}

// Stream yields tokens from an LLM completion one at a time.
type Stream struct {
	tokens <-chan string
	err    error
	mu     sync.Mutex
}

// newStream creates a Stream from a token channel. The caller must close the
// channel when the stream is finished and then call setErr if an error occurred.
func newStream(tokens <-chan string) *Stream {
	return &Stream{tokens: tokens}
}

// NewTestStream creates a Stream for use in tests outside this package.
func NewTestStream(tokens <-chan string) *Stream {
	return newStream(tokens)
}

// Next returns the next token from the stream. When the stream is exhausted it
// returns ("", io.EOF) or ("", error) if the underlying request failed.
func (s *Stream) Next() (string, error) {
	tok, ok := <-s.tokens
	if !ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.err != nil {
			return "", s.err
		}
		return "", io.EOF
	}
	return tok, nil
}

// setErr records a terminal error. It must be called after the token channel
// is closed.
func (s *Stream) setErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// ToChannel exposes the underlying token channel for consumers that prefer
// select-based loops (e.g. Bubble Tea tea.Cmd builders).
func (s *Stream) ToChannel() <-chan string {
	return s.tokens
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
