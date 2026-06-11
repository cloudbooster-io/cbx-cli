// Package knowledge is a small HTTP client for CloudBooster's public AWS
// knowledge endpoints. It exists because the grounded audit path needs to
// fetch CB-curated knowledge from the Go side deterministically — calling
// the same endpoints the cbx-mcp Python sibling wraps, but without putting
// the LLM in the loop (the LLM would otherwise decide which tools to call,
// destroying reproducibility).
//
// Endpoints (all served by platform-app under /v1/knowledge/aws/*):
//   - GET  /v1/knowledge/aws/primitives/{type_id}
//   - GET  /v1/knowledge/aws/practices?workload=...
//   - POST /v1/knowledge/aws/composition  body: {"type_ids":[...]}
//
// All three return the same shape wrapped in the public-API envelope:
//
//	{"schema_version":"1","data":{"kb_version":N,"chunks":[...]},"meta":{...}}
//
// 404 is treated as "no CB entry" (returns ErrNotAuthored) — knowledge gaps
// are normal and the grounding enumerator surfaces them as placeholders
// rather than failing the whole audit.
package knowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrNotAuthored signals a 404 from the knowledge backend: the requested
// primitive / workload / composition is simply not in CB's authored set.
// Callers should record a placeholder, not abort.
var ErrNotAuthored = errors.New("knowledge: not authored")

// maxResponseBytes caps how much of a knowledge response body we read.
// The endpoints serve curated prose chunks — real payloads are tens of
// KiB — so 4 MiB is generous headroom while still bounding memory on a
// public unauthenticated endpoint.
const maxResponseBytes = 4 << 20 // 4 MiB

// Chunk mirrors KnowledgeChunkResponse from platform-app — the prose body
// the LLM will read. Only the fields the grounding enumerator actually
// puts in the prompt are kept; extras roll into Extra so callers can
// pull them without us editing this struct every time the backend grows
// a field.
type Chunk struct {
	DocPath    string   `json:"doc_path"`
	Heading    string   `json:"heading,omitempty"`
	ChunkText  string   `json:"chunk_text"`
	ChunkIndex int      `json:"chunk_index"`
	TokenCount int      `json:"token_count"`
	Category   string   `json:"category"`
	TypeIDs    []string `json:"type_ids,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

// Response is the unwrapped data block — uniform across all three
// endpoints, so one struct covers everything.
type Response struct {
	KBVersion int     `json:"kb_version"`
	Chunks    []Chunk `json:"chunks"`
}

// envelope matches platform-app's ResponseEnvelope. We only decode `data`
// — meta is request-id / rate-limit noise the grounding path doesn't need.
type envelope struct {
	SchemaVersion string          `json:"schema_version"`
	Data          json.RawMessage `json:"data"`
}

// Client is the HTTP client. Zero-value not usable — construct via New.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client against baseURL (must include scheme + host). The
// trailing slash is stripped so endpoint construction stays predictable.
// Default 20s timeout — the knowledge endpoints serve cached prose, so
// anything slower than that is a backend problem worth surfacing fast.
func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 20 * time.Second},
	}
}

// LookupPrimitive fetches CB's posture for a single AWS primitive id
// (e.g. "aws:s3/bucket@v1"). Returns ErrNotAuthored on 404 — caller
// should record a placeholder, not fail the audit.
func (c *Client) LookupPrimitive(ctx context.Context, typeID string) (*Response, error) {
	// The type_id is appended VERBATIM, not url.PathEscape'd, even though
	// it contains ':' and '/'. The backend route is a FastAPI :path
	// converter that matches the remaining path literally — it expects
	// the raw "aws:s3/bucket@v1" segments, and escaping '/' to %2F is
	// decoded inconsistently across proxies/routers, so escaping would
	// break the lookup rather than harden it.
	endpoint := c.baseURL + "/v1/knowledge/aws/primitives/" + typeID
	return c.getJSON(ctx, endpoint, nil)
}

// BestPracticesFor fetches CB's practices for a workload slug (e.g.
// "static-site-plus-api"). Returns ErrNotAuthored on 404.
func (c *Client) BestPracticesFor(ctx context.Context, workload string) (*Response, error) {
	q := url.Values{"workload": {workload}}
	endpoint := c.baseURL + "/v1/knowledge/aws/practices?" + q.Encode()
	return c.getJSON(ctx, endpoint, nil)
}

// CompositionFor fetches CB's recommended companions for a set of
// primitive ids. type_ids are sent verbatim — caller is responsible
// for sorting if determinism across runs matters (the enumerator does).
func (c *Client) CompositionFor(ctx context.Context, typeIDs []string) (*Response, error) {
	body, err := json.Marshal(map[string][]string{"type_ids": typeIDs})
	if err != nil {
		return nil, fmt.Errorf("knowledge: marshal composition body: %w", err)
	}
	endpoint := c.baseURL + "/v1/knowledge/aws/composition"
	return c.postJSON(ctx, endpoint, body)
}

func (c *Client) getJSON(ctx context.Context, endpoint string, _ map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("knowledge: build request: %w", err)
	}
	return c.do(req)
}

func (c *Client) postJSON(ctx context.Context, endpoint string, body []byte) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("knowledge: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req)
}

// Retry policy for transient failures: 2 attempts total with a short
// fixed backoff. Only transport errors and 5xx responses retry — every
// 4xx (including the 404 → ErrNotAuthored mapping) is deterministic and
// returns immediately. retryBackoff is a var so tests can shrink it.
const retryAttempts = 2

var retryBackoff = 500 * time.Millisecond

// do executes req with the bounded retry above. The request context is
// honored across the backoff sleep, and POST bodies are rewound via
// GetBody before a retry (set automatically by NewRequestWithContext
// for bytes.Reader bodies).
func (c *Client) do(req *http.Request) (*Response, error) {
	var lastErr error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-req.Context().Done():
				return nil, fmt.Errorf("knowledge: %s %s: %w", req.Method, req.URL, req.Context().Err())
			case <-time.After(retryBackoff):
			}
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err != nil {
					return nil, fmt.Errorf("knowledge: rewind request body for retry: %w", err)
				}
				req.Body = body
			}
		}
		out, err, retryable := c.doOnce(req)
		if err == nil || !retryable {
			return out, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// doOnce performs a single HTTP round trip. retryable marks failures
// worth a second attempt: transport errors, body-read errors, and 5xx
// statuses. 4xx responses, oversized bodies, and decode failures are
// deterministic — never retried.
func (c *Client) doOnce(req *http.Request) (out *Response, err error, retryable bool) {
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("knowledge: %s %s: %w", req.Method, req.URL, err), true
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotAuthored, false
	}
	// Read at most one byte past the cap so an oversized body is a clear
	// error rather than silently truncated (and broken) JSON.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("knowledge: read body: %w", err), true
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("knowledge: %s %s: response exceeds %d MiB", req.Method, req.URL, maxResponseBytes>>20), false
	}
	if resp.StatusCode >= 400 {
		// Surface the backend's message verbatim when it's short JSON —
		// otherwise truncate to keep the audit's error output tidy.
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 240 {
			msg = msg[:240] + "…"
		}
		return nil, fmt.Errorf("knowledge: %s %s returned %d: %s", req.Method, req.URL, resp.StatusCode, msg), resp.StatusCode >= 500
	}

	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("knowledge: decode envelope: %w", err), false
	}
	var data Response
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return nil, fmt.Errorf("knowledge: decode data: %w", err), false
	}
	return &data, nil, false
}
