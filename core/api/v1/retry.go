package v1

import (
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// RetryTransport retries transient HTTP failures with exponential backoff.
type RetryTransport struct {
	Base       http.RoundTripper
	MaxRetries int
}

// RoundTrip implements http.RoundTripper.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	maxRetries := t.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}

	for attempt := 0; attempt <= maxRetries; attempt++ {
		newReq, err := cloneRequest(req)
		if err != nil {
			return nil, err
		}

		resp, err := base.RoundTrip(newReq)
		if err != nil {
			if !isRetriableError(err) || attempt == maxRetries {
				return nil, err
			}
			backoff := t.backoff(attempt, nil)
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(backoff):
			}
			continue
		}

		if !isRetriableStatus(resp.StatusCode) {
			return resp, nil
		}

		if attempt == maxRetries {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return nil, fmt.Errorf("giving up after %d attempts: server returned %s", maxRetries+1, resp.Status)
		}

		// Drain body to allow connection reuse.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		backoff := t.backoff(attempt, resp)
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(backoff):
		}
	}

	return nil, fmt.Errorf("giving up after %d attempts", maxRetries+1)
}

func (t *RetryTransport) backoff(attempt int, resp *http.Response) time.Duration {
	// Respect Retry-After header if present.
	if resp != nil {
		if after := resp.Header.Get("Retry-After"); after != "" {
			if sec, err := strconv.Atoi(after); err == nil && sec > 0 {
				return time.Duration(sec) * time.Second
			}
			if date, err := http.ParseTime(after); err == nil {
				d := time.Until(date)
				if d > 0 {
					return d
				}
			}
		}
	}

	// Exponential backoff with full jitter.
	// attempt=0 -> ~100ms, attempt=1 -> ~200ms, attempt=2 -> ~400ms, ...
	base := 100 * time.Millisecond
	d := base * time.Duration(math.Pow(2, float64(attempt)))
	if d > 0 {
		jitter := time.Duration(rand.Int63n(int64(d)))
		d = d + jitter
	}
	return d
}

func isRetriableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func isRetriableError(err error) bool {
	// Network-level errors are generally retriable.
	return true
}

func cloneRequest(req *http.Request) (*http.Request, error) {
	newReq := req.Clone(req.Context())
	if req.Body != nil && req.GetBody != nil {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		newReq.Body = body
	}
	return newReq, nil
}
