package v1

import (
	"fmt"
	"net/http"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
)

// loadCBToken returns the user's CloudBooster access token from the keyring,
// or empty string if not authenticated.
func loadCBToken() string {
	kr, err := auth.NewKeyring()
	if err != nil {
		return ""
	}
	tok, err := auth.LoadToken(kr)
	if err != nil || tok == nil {
		return ""
	}
	return tok.AccessToken
}

// ClientOptions configures the behaviour of the wrapped API client.
type ClientOptions struct {
	Quiet       bool
	MaxRetries  int
	Timeout     time.Duration
	OnRateLimit func(remaining int)
}

// APIClient wraps the generated oapi-codegen client with auth, retry, and
// rate-limit awareness.
type APIClient struct {
	*ClientWithResponses
}

// NewAPIClient builds an APIClient from configuration.
//
// The returned client injects the bearer token from cfg.Auth.Token, retries
// transient 5xx and 429 responses with exponential backoff, and warns when
// X-RateLimit-Remaining drops below 10.
func NewAPIClient(cfg *config.Config, optFns ...func(*ClientOptions)) (*APIClient, error) {
	opts := &ClientOptions{
		MaxRetries: 3,
		Timeout:    30 * time.Second,
	}
	for _, fn := range optFns {
		fn(opts)
	}

	if cfg.APIURL == "" {
		return nil, fmt.Errorf("API URL is not configured")
	}

	// Build the transport stack from the network outward:
	// Auth -> Retry -> RateLimit -> caller
	var rt http.RoundTripper = http.DefaultTransport

	rt = &AuthTransport{
		Base:  rt,
		Token: loadCBToken(),
	}

	rt = &RetryTransport{
		Base:       rt,
		MaxRetries: opts.MaxRetries,
	}

	rt = &RateLimitTransport{
		Base: rt,
		OnWarning: func(remaining int) {
			if opts.Quiet {
				return
			}
			if opts.OnRateLimit != nil {
				opts.OnRateLimit(remaining)
			} else {
				output.WarnRateLimit(remaining)
			}
		},
	}

	httpClient := &http.Client{
		Timeout:   opts.Timeout,
		Transport: rt,
	}

	genClient, err := NewClientWithResponses(cfg.APIURL, WithHTTPClient(httpClient))
	if err != nil {
		return nil, fmt.Errorf("creating generated client: %w", err)
	}

	return &APIClient{genClient}, nil
}
