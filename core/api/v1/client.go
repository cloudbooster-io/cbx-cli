package v1

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// ClientOptions configures the behaviour of the wrapped API client.
type ClientOptions struct {
	Quiet       bool
	MaxRetries  int
	Timeout     time.Duration
	OnRateLimit func(remaining int)

	// Token is the CloudBooster bearer token injected into every request.
	// It is the caller's responsibility (the CLI composition root) to
	// resolve it — typically via auth.AccessToken(). Left empty, requests
	// go out unauthenticated. Keeping the keyring read out of this
	// constructor is deliberate: it stops unit tests and library consumers
	// from triggering the OS keychain authorization prompt.
	Token string
}

// APIClient wraps the generated oapi-codegen client with auth, retry, and
// rate-limit awareness.
type APIClient struct {
	*ClientWithResponses
}

// NewAPIClient builds an APIClient from configuration.
//
// The returned client injects the bearer token from opts.Token (resolve it
// at the composition root via auth.AccessToken()), retries transient 5xx and
// 429 responses with exponential backoff, and warns when X-RateLimit-Remaining
// drops below 10.
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
	rt := http.DefaultTransport

	rt = &AuthTransport{
		Base:  rt,
		Token: opts.Token,
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
