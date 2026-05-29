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

// DefaultClaudeBaseURL is the production Anthropic API endpoint.
const DefaultClaudeBaseURL = "https://api.anthropic.com"

// DefaultClaudeModel is the default Claude model identifier.
const DefaultClaudeModel = "claude-sonnet-4-20250514"

// ClaudeClient streams completions from the Anthropic Messages API.
type ClaudeClient struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

// NewClaudeClient creates a Claude LLM client from the supplied config.
func NewClaudeClient(cfg ClientConfig) *ClaudeClient {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultClaudeBaseURL
	}
	model := cfg.Model
	if model == "" {
		model = DefaultClaudeModel
	}
	return &ClaudeClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		apiKey:  cfg.APIKey,
		model:   model,
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

// Complete implements LLMClient.
func (c *ClaudeClient) Complete(ctx context.Context, prompt string, opts CompleteOptions) (*Stream, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("claude: missing API key")
	}

	model := opts.Model
	if model == "" {
		model = c.model
	}
	maxTokens := opts.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	body := map[string]any{
		"model":      model,
		"max_tokens": maxTokens,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"stream": true,
	}
	if opts.System != "" {
		body["system"] = opts.System
	}
	if opts.Temperature > 0 {
		body["temperature"] = opts.Temperature
	}

	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("claude: marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("claude: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("claude: request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		// If we got a 401 the bearer token may have expired. Surface a clear
		// error so the caller can trigger a silent refresh (handled at the
		// auth layer in CB-389).
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("claude: authentication expired (401); re-run 'cbx llm api login claude'")
		}
		return nil, fmt.Errorf("claude: unexpected status %d", resp.StatusCode)
	}

	tokens := make(chan string, 32)
	stream := newStream(tokens)

	go func() {
		defer close(tokens)
		defer resp.Body.Close()
		scanErr := scanClaudeSSE(bufio.NewReader(resp.Body), tokens)
		if scanErr != nil {
			stream.setErr(scanErr)
		}
	}()

	return stream, nil
}

func scanClaudeSSE(r *bufio.Reader, out chan<- string) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return fmt.Errorf("claude: reading SSE: %w", err)
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			return nil
		}

		var evt struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
				Type string `json:"type"`
			} `json:"delta"`
			ContentBlock struct {
				Text string `json:"text"`
				Type string `json:"type"`
			} `json:"content_block"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			// Skip malformed events rather than failing the whole stream.
			continue
		}

		switch evt.Type {
		case "content_block_delta":
			if evt.Delta.Text != "" {
				out <- evt.Delta.Text
			}
		case "content_block_start":
			if evt.ContentBlock.Text != "" {
				out <- evt.ContentBlock.Text
			}
		}
	}
}
