package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Caller streams prompts to the user's configured HTTP LLM provider.
type Caller struct {
	Provider Provider
	Token    string
	client   *http.Client
}

// NewCaller creates a new LLM streaming caller. token is the provider
// credential, resolved and injected by the caller (the CLI composition root)
// instead of being read from the OS keychain here. Keeping the keychain read
// out of this constructor is what lets unit tests construct the stack without
// triggering a keychain authorization prompt. An empty token is acceptable
// for offline providers like ollama.
func NewCaller(provider Provider, token string) *Caller {
	return &Caller{
		Provider: provider,
		Token:    token,
		// ResponseHeaderTimeout bounds how long we wait for the provider to
		// start responding (the hang case: an unresponsive endpoint with a
		// background context), without capping the total duration of a
		// legitimately long token stream the way http.Client.Timeout would.
		client: &http.Client{
			Transport: &http.Transport{ResponseHeaderTimeout: 60 * time.Second},
		},
	}
}

// Stream sends the prompt to the LLM and calls onToken for each received token.
func (c *Caller) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	switch c.Provider.Name {
	case "claude":
		return c.streamClaude(ctx, prompt, onToken)
	case "openai":
		return c.streamOpenAI(ctx, prompt, onToken)
	case "ollama":
		return c.streamOllama(ctx, prompt, onToken)
	default:
		return fmt.Errorf("unsupported provider: %s", c.Provider.Name)
	}
}

func (c *Caller) streamClaude(ctx context.Context, prompt string, onToken func(string)) error {
	body, err := json.Marshal(map[string]any{
		"model":      c.Provider.Model,
		"max_tokens": 1024,
		"messages":   []map[string]string{{"role": "user", "content": prompt}},
		"stream":     true,
	})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Provider.BaseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.Token)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("claude request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("claude returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			break
		}
		var event struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		if event.Type == "content_block_delta" {
			onToken(event.Delta.Text)
		}
	}
	return scanner.Err()
}

func (c *Caller) streamOpenAI(ctx context.Context, prompt string, onToken func(string)) error {
	body, err := json.Marshal(map[string]any{
		"model":    c.Provider.Model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
		"stream":   true,
	})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Provider.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("openai request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("openai returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := line[6:]
		if data == "[DONE]" {
			break
		}
		var event struct {
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		if len(event.Choices) > 0 {
			onToken(event.Choices[0].Delta.Content)
		}
	}
	return scanner.Err()
}

func (c *Caller) streamOllama(ctx context.Context, prompt string, onToken func(string)) error {
	body, err := json.Marshal(map[string]any{
		"model":  c.Provider.Model,
		"prompt": prompt,
		"stream": true,
	})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Provider.BaseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var event struct {
			Response string `json:"response"`
			Done     bool   `json:"done"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			continue
		}
		onToken(event.Response)
		if event.Done {
			break
		}
	}
	return scanner.Err()
}
