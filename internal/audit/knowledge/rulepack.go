package knowledge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrNotModified signals a 304 from the rulepack endpoint: the caller's
// cached copy (identified by the If-None-Match ETag) is still current.
// Callers should serve from cache, refreshing its revalidation stamp.
var ErrNotModified = errors.New("knowledge: not modified")

// rulePackSchema is the bundle schema version this engine speaks. Sent
// as the ?schema= compat-handshake param so the server can refuse (or
// down-serve) packs the engine cannot parse. Must track
// rulesbundle's schema_version 1 (the two are pinned together by
// internal/audit's wire-contract test).
const rulePackSchema = 1

// RulePack fetches the audit rule bundle artifact from
// GET /v1/knowledge/aws/rulepack?channel=<channel>&schema=1[&version=<pin>].
//
// The endpoint streams the signed artifact bytes VERBATIM — it is
// deliberately NOT wrapped in the {schema_version,data,meta} envelope
// the chunk endpoints use (sign-then-serve: any re-serialization would
// break byte-level signature verification, plan §B.2). So this method
// returns the raw bytes; parsing and validation belong to
// internal/audit/rulesbundle, and the caller must cache these exact
// bytes for later signature verification (P3).
//
// etag may be "" on a first fetch; when non-empty it is sent as
// If-None-Match and a 304 response returns (nil, etag, ErrNotModified).
// pin 0 requests the latest pack on the channel; pin > 0 requests that
// exact pack_version. 404 → ErrNotAuthored (the endpoint is not
// deployed, or the pinned version does not exist) — callers fall down
// the resolve ladder, they do not abort.
//
// Transport, retry (2 attempts, 5xx/transport only), and the 4 MiB
// body cap follow the chunk endpoints' conventions above.
func (c *Client) RulePack(ctx context.Context, channel, etag string, pin int) ([]byte, string, error) {
	q := url.Values{"schema": {strconv.Itoa(rulePackSchema)}}
	if channel != "" {
		q.Set("channel", channel)
	}
	if pin > 0 {
		q.Set("version", strconv.Itoa(pin))
	}
	endpoint := c.baseURL + "/v1/knowledge/aws/rulepack?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", fmt.Errorf("knowledge: build request: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	return c.doRaw(req)
}

// doRaw mirrors do for endpoints that serve a raw artifact rather than
// the JSON envelope: same bounded retry, same context handling.
func (c *Client) doRaw(req *http.Request) ([]byte, string, error) {
	var lastErr error
	for attempt := 0; attempt < retryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-req.Context().Done():
				return nil, "", fmt.Errorf("knowledge: %s %s: %w", req.Method, req.URL, req.Context().Err())
			case <-time.After(retryBackoff):
			}
		}
		raw, respETag, err, retryable := c.doRawOnce(req)
		if err == nil || !retryable {
			return raw, respETag, err
		}
		lastErr = err
	}
	return nil, "", lastErr
}

// doRawOnce performs a single raw round trip. The retryable taxonomy
// matches doOnce: transport and body-read errors and 5xx retry; 304,
// 404, other 4xx, and oversized bodies are deterministic.
func (c *Client) doRawOnce(req *http.Request) (raw []byte, respETag string, err error, retryable bool) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("knowledge: %s %s: %w", req.Method, req.URL, err), true
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, req.Header.Get("If-None-Match"), ErrNotModified, false
	case http.StatusNotFound:
		return nil, "", ErrNotAuthored, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, "", fmt.Errorf("knowledge: read body: %w", err), true
	}
	if len(body) > maxResponseBytes {
		return nil, "", fmt.Errorf("knowledge: %s %s: response exceeds %d MiB", req.Method, req.URL, maxResponseBytes>>20), false
	}
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 240 {
			msg = msg[:240] + "…"
		}
		return nil, "", fmt.Errorf("knowledge: %s %s returned %d: %s", req.Method, req.URL, resp.StatusCode, msg), resp.StatusCode >= 500
	}
	return body, resp.Header.Get("ETag"), nil, false
}
