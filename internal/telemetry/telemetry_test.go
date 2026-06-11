package telemetry

import (
	"testing"

	"github.com/getsentry/sentry-go"
)

func TestScrubString(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "akia access key",
			in:   "denied for key AKIAIOSFODNN7EXAMPLE in request",
			want: "denied for key <aws-access-key> in request",
		},
		{
			name: "asia access key",
			in:   "sts key ASIAIOSFODNN7EXAMPLE expired",
			want: "sts key <aws-access-key> expired",
		},
		{
			name: "anthropic key",
			in:   "invalid x-api-key sk-ant-api03-AbCdEfGhIjKlMnOp",
			want: "invalid x-api-key sk-ant-<redacted>",
		},
		{
			name: "openai key",
			in:   "provider rejected sk-AbCdEfGhIjKlMnOpQrStUvWx",
			want: "provider rejected sk-<redacted>",
		},
		{
			name: "arn",
			in:   `cannot assume arn:aws:iam::123456789012:role/AdminRole today`,
			want: "cannot assume arn:aws:<redacted> today",
		},
		{
			name: "bare account id",
			in:   "account 123456789012 is not allowlisted",
			want: "account <aws-account> is not allowlisted",
		},
		{
			name: "account id inside sha not scrubbed",
			in:   "commit 123456789012abc looks fine",
			want: "commit 123456789012abc looks fine",
		},
		{
			name: "macos home path",
			in:   "open /Users/alice/projects/state.json: no such file",
			want: "open /Users/<redacted>/projects/state.json: no such file",
		},
		{
			name: "linux home path",
			in:   "open /home/bob/state.json: permission denied",
			want: "open /home/<redacted>/state.json: permission denied",
		},
		{
			name: "windows home path",
			in:   `open C:\Users\carol\state.json: not found`,
			want: `open C:\Users\<redacted>\state.json: not found`,
		},
		{
			name: "password key value",
			in:   "connect failed: password=hunter2 rejected",
			want: "connect failed: password=<redacted> rejected",
		},
		{
			name: "secret key value",
			in:   "env has secret=s3cr3tvalue set",
			want: "env has secret=<redacted> set",
		},
		{
			name: "token key value",
			in:   "request with token=eyJhbGciOiJIUzI1NiJ9 failed",
			want: "request with token=<redacted> failed",
		},
		{
			name: "api_key key value",
			in:   "api_key=abc123def is invalid",
			want: "api_key=<redacted> is invalid",
		},
		{
			name: "prefixed key value shapes",
			in:   "client_secret=foo access_token=bar AWS_SECRET=baz",
			want: "client_secret=<redacted> access_token=<redacted> AWS_SECRET=<redacted>",
		},
		{
			name: "key value with spaces around equals",
			in:   "password = hunter2",
			want: "password=<redacted>",
		},
		{
			name: "prose mentioning token survives",
			in:   "the token expired, run cbx login",
			want: "the token expired, run cbx login",
		},
		{
			name: "plain message untouched",
			in:   "failed to parse state file: unexpected EOF",
			want: "failed to parse state file: unexpected EOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := scrubString(tt.in); got != tt.want {
				t.Errorf("scrubString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestScrubEvent(t *testing.T) {
	event := &sentry.Event{
		Message:    "boom in /Users/alice/work",
		ServerName: "alices-macbook.local",
		User:       sentry.User{ID: "u1", IPAddress: "10.0.0.1", Username: "alice"},
		Exception: []sentry.Exception{
			{Type: "error in /home/bob/app", Value: "key AKIAIOSFODNN7EXAMPLE leaked"},
		},
		Breadcrumbs: []*sentry.Breadcrumb{
			{Message: "ran with token=abc123"},
		},
		Contexts: map[string]sentry.Context{
			"app": {
				"cwd":  "/home/bob/repo",
				"key":  "sk-ant-api03-AbCdEfGhIjKlMnOp",
				"pid":  1234,
				"meta": map[string]interface{}{"nested": true},
			},
		},
		Request: &sentry.Request{
			Cookies:     "session=abc",
			QueryString: "token=xyz",
			Env:         map[string]string{"HOME": "/Users/alice"},
			Headers:     map[string]string{"Authorization": "Bearer tok"},
		},
	}

	got := scrubEvent(event, nil)

	if got.Message != "boom in /Users/<redacted>/work" {
		t.Errorf("Message not scrubbed: %q", got.Message)
	}
	if got.ServerName != "" {
		t.Errorf("ServerName not stripped: %q", got.ServerName)
	}
	if !got.User.IsEmpty() {
		t.Errorf("User not stripped: %+v", got.User)
	}
	if got.Exception[0].Type != "error in /home/<redacted>/app" {
		t.Errorf("Exception.Type not scrubbed: %q", got.Exception[0].Type)
	}
	if got.Exception[0].Value != "key <aws-access-key> leaked" {
		t.Errorf("Exception.Value not scrubbed: %q", got.Exception[0].Value)
	}
	if got.Breadcrumbs[0].Message != "ran with token=<redacted>" {
		t.Errorf("Breadcrumb not scrubbed: %q", got.Breadcrumbs[0].Message)
	}

	app := got.Contexts["app"]
	if app["cwd"] != "/home/<redacted>/repo" {
		t.Errorf("Contexts string not scrubbed: %q", app["cwd"])
	}
	if app["key"] != "sk-ant-<redacted>" {
		t.Errorf("Contexts api key not scrubbed: %q", app["key"])
	}
	if app["pid"] != 1234 {
		t.Errorf("non-string Contexts value mutated: %v", app["pid"])
	}

	if got.Request.Cookies != "" || got.Request.QueryString != "" ||
		got.Request.Env != nil || got.Request.Headers != nil {
		t.Errorf("Request not stripped: %+v", got.Request)
	}
}

// TestInitEmptyDSNIsNoOp verifies that Init without a DSN (no ldflags bake,
// no CBX_SENTRY_DSN) leaves telemetry uninitialized — and therefore makes no
// network calls — even when telemetry is enabled.
func TestInitEmptyDSNIsNoOp(t *testing.T) {
	if initialized {
		t.Skip("telemetry already initialized by another test")
	}
	t.Setenv("CBX_TELEMETRY", "1")
	t.Setenv("CBX_SENTRY_DSN", "")

	Init("test-version", "test-commit")

	if initialized {
		t.Fatal("Init with empty DSN must not initialize Sentry")
	}
	// All entry points must be safe no-ops in the uninitialized state.
	SetTag("command", "test")
	CaptureError(errStub("boom"))
	Flush(0)
}

func TestInitDisabledByEnvIsNoOp(t *testing.T) {
	if initialized {
		t.Skip("telemetry already initialized by another test")
	}
	t.Setenv("CBX_TELEMETRY", "0")
	t.Setenv("CBX_SENTRY_DSN", "")

	Init("test-version", "test-commit")

	if initialized {
		t.Fatal("Init with CBX_TELEMETRY=0 must not initialize Sentry")
	}
}

func TestIsEnabledEnvPrecedence(t *testing.T) {
	t.Setenv("CBX_TELEMETRY", "0")
	if IsEnabled() {
		t.Error("CBX_TELEMETRY=0 should disable telemetry")
	}

	t.Setenv("CBX_TELEMETRY", "1")
	if !IsEnabled() {
		t.Error("CBX_TELEMETRY=1 should enable telemetry")
	}

	// DO_NOT_TRACK wins when CBX_TELEMETRY is unset (and short-circuits
	// before the config file is consulted).
	t.Setenv("CBX_TELEMETRY", "")
	t.Setenv("DO_NOT_TRACK", "1")
	if IsEnabled() {
		t.Error("DO_NOT_TRACK=1 should disable telemetry")
	}

	// Explicit opt-in beats DO_NOT_TRACK.
	t.Setenv("CBX_TELEMETRY", "on")
	if !IsEnabled() {
		t.Error("CBX_TELEMETRY=on should override DO_NOT_TRACK")
	}
}

// errStub is a minimal error type so CaptureError can be exercised without
// constructing anything through the Sentry SDK.
type errStub string

func (e errStub) Error() string { return string(e) }
