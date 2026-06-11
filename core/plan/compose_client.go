package plan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// ComposeClient is a minimal HTTP client for the CloudBooster compose API.
type ComposeClient struct {
	BaseURL string
	Token   string
	client  *http.Client
}

// NewComposeClient creates a new compose API client.
//
// Propose may consume a long-lived SSE body, so a whole-request
// http.Client.Timeout would cut a healthy stream mid-body. Instead the
// transport bounds each phase that can hang on a dead server: dial, TLS
// handshake, and waiting for response headers.
func NewComposeClient(baseURL, token string) *ComposeClient {
	return &ComposeClient{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Token:   token,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ForceAttemptHTTP2:     true,
			},
		},
	}
}

// Propose calls /v1/compose/aws/propose and returns candidate components.
// It attempts to parse SSE streams; if that yields no components, it falls
// back to parsing the response body as a JSON array.
func (c *ComposeClient) Propose(ctx context.Context, intent string) ([]Component, error) {
	body, err := json.Marshal(map[string]string{"intent": intent})
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/compose/aws/propose", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("propose request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("propose returned status %d", resp.StatusCode)
	}

	var components []Component

	// If the response is explicitly JSON, decode directly.
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(resp.Body).Decode(&components); err != nil {
			return nil, fmt.Errorf("decoding propose response: %w", err)
		}
		return components, nil
	}

	// Otherwise attempt SSE parsing.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data := line[6:]
			if data == "[DONE]" {
				break
			}
			var comp Component
			if err := json.Unmarshal([]byte(data), &comp); err == nil {
				components = append(components, comp)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading propose response: %w", err)
	}

	return components, nil
}

// Resolve calls /v1/compose/aws/resolve and returns a fully-rendered Plan.
func (c *ComposeClient) Resolve(ctx context.Context, components []Component) (*Plan, error) {
	body, err := json.Marshal(map[string]any{"components": components})
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/compose/aws/resolve", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("resolve returned status %d", resp.StatusCode)
	}

	var result struct {
		Intent     string      `json:"intent"`
		Components []Component `json:"components"`
		Version    int         `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding resolve response: %w", err)
	}

	plan := &Plan{
		Intent:     result.Intent,
		Components: result.Components,
		Version:    result.Version,
	}
	plan.ADRContent = RenderADR(plan)
	plan.D2Content = RenderD2(plan)
	plan.MermaidContent = RenderMermaid(plan)
	plan.HTMLContent = RenderHTML(plan)
	return plan, nil
}
