package v1

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
)

// roundTripFunc adapts a function to http.RoundTripper for stubbing the
// retry transport's base.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestIsRetriableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		// Permanent: caller-driven context termination.
		{"context canceled", context.Canceled, false},
		{"context deadline exceeded", context.DeadlineExceeded, false},
		{"wrapped context canceled", fmt.Errorf("round trip: %w", context.Canceled), false},
		{
			"url.Error wrapping deadline exceeded",
			&url.Error{Op: "Get", URL: "https://api.example.com", Err: context.DeadlineExceeded},
			false,
		},
		// Permanent: TLS certificate / verification failures.
		{
			"url.Error wrapping unknown authority",
			&url.Error{Op: "Get", URL: "https://api.example.com", Err: x509.UnknownAuthorityError{}},
			false,
		},
		{
			"url.Error wrapping hostname mismatch",
			&url.Error{Op: "Get", URL: "https://api.example.com", Err: x509.HostnameError{Host: "api.example.com"}},
			false,
		},
		{"bare certificate invalid", x509.CertificateInvalidError{Reason: x509.Expired}, false},
		{"bare system roots error", x509.SystemRootsError{}, false},
		{
			"tls verification error",
			&url.Error{
				Op:  "Get",
				URL: "https://api.example.com",
				Err: &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}},
			},
			false,
		},
		// Transient: DNS timeouts, connection-level failures, generic errors.
		{
			"dns timeout",
			&net.DNSError{Err: "i/o timeout", Name: "api.example.com", IsTimeout: true},
			true,
		},
		{
			"connection refused",
			&net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)},
			true,
		},
		{
			"connection reset",
			&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)},
			true,
		},
		{"unexpected EOF", io.ErrUnexpectedEOF, true},
		{"generic transport error", errors.New("http2: server sent GOAWAY"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRetriableError(tt.err); got != tt.want {
				t.Fatalf("isRetriableError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRetryTransport_DoesNotRetryPermanentTransportError(t *testing.T) {
	permanent := []struct {
		name string
		err  error
	}{
		{"context canceled", context.Canceled},
		{"certificate error", &url.Error{Op: "Get", URL: "https://api.example.com", Err: x509.UnknownAuthorityError{}}},
	}

	for _, tt := range permanent {
		t.Run(tt.name, func(t *testing.T) {
			var attempts int
			rt := &RetryTransport{
				Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
					attempts++
					return nil, tt.err
				}),
				MaxRetries: 3,
			}

			req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/health", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}

			resp, err := rt.RoundTrip(req) //nolint:bodyclose // resp is expected to be nil
			if err == nil {
				resp.Body.Close()
				t.Fatal("expected error from permanent transport failure")
			}
			if !errors.Is(err, tt.err) {
				t.Fatalf("error = %v, want %v", err, tt.err)
			}
			if attempts != 1 {
				t.Fatalf("expected 1 attempt (no retries), got %d", attempts)
			}
		})
	}
}

func TestRetryTransport_RetriesTransientTransportError(t *testing.T) {
	var attempts int
	rt := &RetryTransport{
		Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			if attempts < 3 {
				return nil, &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
				Header:     http.Header{},
			}, nil
		}),
		MaxRetries: 3,
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetryTransport_ExhaustionPreservesStatusAndBody(t *testing.T) {
	var attempts int
	rt := &RetryTransport{
		Base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts++
			return &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Status:     "503 Service Unavailable",
				Body:       io.NopCloser(strings.NewReader(`{"error":"overloaded"}`)),
				Header:     http.Header{},
			}, nil
		}),
		MaxRetries: 2,
	}

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/health", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("expected last response (nil error) on exhaustion, got: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	if string(body) != `{"error":"overloaded"}` {
		t.Fatalf("body = %q, want error body preserved", body)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}
