package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultCodexBaseURL is the default OpenAI API endpoint used by Codex CLI.
const DefaultCodexBaseURL = "https://api.openai.com"

// DefaultCodexModel is the default model identifier for Codex completions.
const DefaultCodexModel = "codex"

// CodexClient streams completions using the OpenAI Chat Completions API
// with a token obtained from the Codex CLI credential store.
type CodexClient struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

// NewCodexClient creates a Codex LLM client from the supplied config.
func NewCodexClient(cfg ClientConfig) *CodexClient {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultCodexBaseURL
	}
	model := cfg.Model
	if model == "" {
		model = DefaultCodexModel
	}
	return &CodexClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		apiKey:  cfg.APIKey,
		model:   model,
		client:  &http.Client{Timeout: 120 * time.Second},
	}
}

// ReadCodexToken attempts to read a stored Codex CLI token from well-known
// configuration paths. It returns ("", nil) when no token is found.
func ReadCodexToken() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	candidates := []string{
		filepath.Join(home, ".codex", "config.json"),
		filepath.Join(home, ".config", "codex", "config.json"),
	}
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg struct {
			APIKey string `json:"api_key"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		if cfg.APIKey != "" {
			return cfg.APIKey, nil
		}
	}
	return "", nil
}

// Complete implements LLMClient.
func (c *CodexClient) Complete(ctx context.Context, prompt string, opts CompleteOptions) (*Stream, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("codex: missing API key")
	}

	model := opts.Model
	if model == "" {
		model = c.model
	}
	maxTokens := opts.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	messages := []map[string]string{
		{"role": "user", "content": prompt},
	}
	if opts.System != "" {
		messages = append([]map[string]string{{"role": "system", "content": opts.System}}, messages...)
	}

	body := map[string]any{
		"model":          model,
		"messages":       messages,
		"max_tokens":     maxTokens,
		"stream":         true,
		"stream_options": map[string]bool{"include_usage": true},
	}
	if opts.Temperature > 0 {
		body["temperature"] = opts.Temperature
	}

	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("codex: marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("codex: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("codex: request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, fmt.Errorf("codex: authentication expired (401); re-run 'cbx llm login codex'")
		}
		return nil, fmt.Errorf("codex: unexpected status %d", resp.StatusCode)
	}

	tokens := make(chan string, 32)
	stream := newStream(tokens)

	go func() {
		defer close(tokens)
		defer resp.Body.Close()
		scanErr := scanOpenAISSE(bufio.NewReader(resp.Body), tokens)
		if scanErr != nil {
			stream.setErr(scanErr)
		}
	}()

	return stream, nil
}

func scanOpenAISSE(r *bufio.Reader, out chan<- string) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return fmt.Errorf("codex: reading SSE: %w", err)
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
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(data), &evt); err != nil {
			continue
		}
		for _, c := range evt.Choices {
			if c.Delta.Content != "" {
				out <- c.Delta.Content
			}
		}
	}
}
