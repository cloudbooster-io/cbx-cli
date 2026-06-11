// Package llm defines the provider-agnostic LLM contract shared across cbx
// modules: the LLMClient interface, CompleteOptions, and the token Stream.
// It is a clean package boundary — no CloudBooster API client types and no
// internal/ packages are imported here. Concrete provider implementations
// (Claude, Codex, …) live in internal/core/llm.
package llm

import (
	"context"
	"errors"
	"io"
	"strings"
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

// NewStream creates a Stream from a token channel. The producer must close the
// channel when the stream is finished and then call SetErr if an error occurred.
func NewStream(tokens <-chan string) *Stream {
	return &Stream{tokens: tokens}
}

// NewTestStream creates a Stream for use in tests outside this package.
func NewTestStream(tokens <-chan string) *Stream {
	return NewStream(tokens)
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

// SetErr records a terminal error. It must be called after the token channel
// is closed.
func (s *Stream) SetErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// Collect drains the stream and returns the full accumulated text. A clean
// end of stream (io.EOF) is not an error; a terminal stream error is returned
// together with whatever text accumulated before it. It is the writer-less
// counterpart of internal/output.WriteStream.
func (s *Stream) Collect() (string, error) {
	var full strings.Builder
	for {
		tok, err := s.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return full.String(), nil
			}
			return full.String(), err
		}
		full.WriteString(tok)
	}
}

// ToChannel exposes the underlying token channel for consumers that prefer
// select-based loops (e.g. Bubble Tea tea.Cmd builders).
func (s *Stream) ToChannel() <-chan string {
	return s.tokens
}
