package v1

import (
	"net/http"
	"strconv"
)

// RateLimitTransport parses rate-limit headers and fires warnings when low.
type RateLimitTransport struct {
	Base      http.RoundTripper
	OnWarning func(remaining int)
}

// RoundTrip implements http.RoundTripper.
func (t *RateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	resp, err := base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}

	if t.OnWarning != nil {
		if rem := resp.Header.Get("X-RateLimit-Remaining"); rem != "" {
			if n, err := strconv.Atoi(rem); err == nil && n >= 0 && n < 10 {
				t.OnWarning(n)
			}
		}
	}

	return resp, nil
}
