package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// NewAPIClient("") must error; the non-empty happy path must build. The empty
// case is also covered by TestNewAPIClient_RequiresAPIURL in client_test.go.
func TestNewAPIClient_BuildsWithValidURL(t *testing.T) {
	client, err := NewAPIClient("https://example.com")
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

// A nil ClientOptions.OnRateLimit means rate-limit warnings are silently
// dropped — firing the warning path must not panic.
func TestNewAPIClient_NilOnRateLimitDoesNotPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	client, err := NewAPIClient(ts.URL)
	if err != nil {
		t.Fatalf("NewAPIClient: %v", err)
	}

	if _, err := client.GetHealthWithResponse(context.Background()); err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
}

// RateLimitTransport itself must tolerate a nil OnWarning even when the
// remaining count is below the warning threshold.
func TestRateLimitTransport_NilOnWarningDoesNotPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "1")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	rt := &RateLimitTransport{Base: http.DefaultTransport}
	httpClient := &http.Client{Transport: rt}

	resp, err := httpClient.Get(ts.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	resp.Body.Close()
}
