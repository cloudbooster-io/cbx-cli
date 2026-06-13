package v1

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuthTransport_InjectsBearerToken(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	rt := &AuthTransport{Base: http.DefaultTransport, Token: "my-secret-token"}
	httpClient := &http.Client{Transport: rt}

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/v1/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()

	want := "Bearer my-secret-token"
	if gotAuth != want {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, want)
	}
}

func TestAuthTransport_SkipsHeaderWhenTokenEmpty(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	_, err = client.GetHealthWithResponse(context.Background())
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}

	if gotAuth != "" {
		t.Fatalf("expected no Authorization header, got %q", gotAuth)
	}
}

func TestRetryTransport_RetriesOn500(t *testing.T) {
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if count.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL, func(o *ClientOptions) {
		o.MaxRetries = 3
	})
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	resp, err := client.GetHealthWithResponse(context.Background())
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode())
	}
	if count.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", count.Load())
	}
}

func TestRetryTransport_RetriesOn429WithRetryAfter(t *testing.T) {
	var count atomic.Int32
	var delays []time.Duration
	start := time.Now()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delays = append(delays, time.Since(start))
		if count.Add(1) < 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL, func(o *ClientOptions) {
		o.MaxRetries = 3
	})
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	resp, err := client.GetHealthWithResponse(context.Background())
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode())
	}
	if count.Load() != 2 {
		t.Fatalf("expected 2 attempts, got %d", count.Load())
	}
	if len(delays) < 2 || delays[1] < 500*time.Millisecond {
		t.Fatalf("expected at least ~1s delay before second attempt, got %v", delays)
	}
}

func TestRetryTransport_RespectsContextCancellation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL, func(o *ClientOptions) {
		o.MaxRetries = 5
	})
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = client.GetHealthWithResponse(ctx)
	if err == nil {
		t.Fatal("expected error due to context cancellation")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Fatalf("expected context error, got: %v", err)
	}
}

func TestRetryTransport_ReturnsLastResponseWhenRetriesExhausted(t *testing.T) {
	var count atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"overloaded"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL, func(o *ClientOptions) {
		o.MaxRetries = 2
	})
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	resp, err := client.GetHealthWithResponse(context.Background())
	if err != nil {
		t.Fatalf("expected last response (nil error) when retries are exhausted, got: %v", err)
	}
	if resp.StatusCode() != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode())
	}
	if !strings.Contains(string(resp.Body), "overloaded") {
		t.Fatalf("expected error body to be preserved, got: %q", resp.Body)
	}
	if count.Load() != 3 {
		t.Fatalf("expected 3 attempts, got %d", count.Load())
	}
}

func TestRateLimitTransport_WarnsWhenLow(t *testing.T) {
	var warned bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "3")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL, func(o *ClientOptions) {
		o.OnRateLimit = func(remaining int) {
			warned = true
			if remaining != 3 {
				t.Errorf("remaining = %d, want 3", remaining)
			}
		}
	})
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	_, err = client.GetHealthWithResponse(context.Background())
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}

	if !warned {
		t.Fatal("expected rate-limit warning to fire")
	}
}

func TestRateLimitTransport_SuppressesWarningWhenQuiet(t *testing.T) {
	var warned bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "3")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL, func(o *ClientOptions) {
		o.Quiet = true
		o.OnRateLimit = func(remaining int) {
			warned = true
		}
	})
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	_, err = client.GetHealthWithResponse(context.Background())
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}

	if warned {
		t.Fatal("expected rate-limit warning to be suppressed in quiet mode")
	}
}

func TestRateLimitTransport_NoWarningWhenPlenty(t *testing.T) {
	var warned bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "50")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL, func(o *ClientOptions) {
		o.OnRateLimit = func(remaining int) {
			warned = true
		}
	})
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	_, err = client.GetHealthWithResponse(context.Background())
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}

	if warned {
		t.Fatal("expected no warning when remaining is high")
	}
}

func TestNewAPIClient_RequiresAPIURL(t *testing.T) {
	_, err := NewAPIClient("")
	if err == nil {
		t.Fatal("expected error when APIURL is empty")
	}
	if !strings.Contains(err.Error(), "API URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRetryTransport_BackoffExponential(t *testing.T) {
	rt := &RetryTransport{}

	// attempt 0 -> first retry delay ~100ms + jitter
	if d := rt.backoff(0, nil); d < 100*time.Millisecond || d > 200*time.Millisecond {
		t.Fatalf("backoff(0) = %v, expected 100ms-200ms", d)
	}

	// attempt 1 -> ~200ms + jitter
	if d := rt.backoff(1, nil); d < 200*time.Millisecond || d > 400*time.Millisecond {
		t.Fatalf("backoff(1) = %v, expected 200ms-400ms", d)
	}

	// attempt 2 -> ~400ms + jitter
	if d := rt.backoff(2, nil); d < 400*time.Millisecond || d > 800*time.Millisecond {
		t.Fatalf("backoff(2) = %v, expected 400ms-800ms", d)
	}
}

func TestRetryTransport_BackoffRespectsRetryAfterSeconds(t *testing.T) {
	rt := &RetryTransport{}
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{"5"}},
	}
	if d := rt.backoff(1, resp); d != 5*time.Second {
		t.Fatalf("backoff with Retry-After = %v, want 5s", d)
	}
}

func TestRetryTransport_BackoffRespectsRetryAfterDate(t *testing.T) {
	rt := &RetryTransport{}
	// Use a 5-second future to avoid flakiness from HTTP-date second truncation.
	future := time.Now().UTC().Add(5 * time.Second).Format(http.TimeFormat)
	resp := &http.Response{
		Header: http.Header{"Retry-After": []string{future}},
	}
	d := rt.backoff(1, resp)
	if d < 3*time.Second || d > 6*time.Second {
		t.Fatalf("backoff with Retry-After date = %v, expected ~4-5s", d)
	}
}

func TestRetryTransport_CloneRequestPreservesBody(t *testing.T) {
	bodyContent := `{"code":"abc"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(bodyContent))
	req.GetBody = func() (body io.ReadCloser, err error) {
		return io.NopCloser(strings.NewReader(bodyContent)), nil
	}

	cloned, err := cloneRequest(req)
	if err != nil {
		t.Fatalf("cloneRequest: %v", err)
	}

	b, err := io.ReadAll(cloned.Body)
	if err != nil {
		t.Fatalf("reading cloned body: %v", err)
	}
	if string(b) != bodyContent {
		t.Fatalf("cloned body = %q, want %q", string(b), bodyContent)
	}
}
