// Package telemetry wires anonymous error reports and usage metrics to a
// Sentry instance. Everything in this package is gated on explicit user
// opt-in: nothing is sent until the user answers "yes" to the first-run
// prompt or runs `cbx telemetry enable`. The opt-in choice is also
// preempted by env vars (CBX_TELEMETRY, DO_NOT_TRACK) so power users
// and CI can override the stored config without a config edit.
package telemetry

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/getsentry/sentry-go"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// defaultDSN is the Sentry DSN baked in at build time via:
//
//	go build -ldflags "-X github.com/cloudbooster-io/cbx-cli/internal/telemetry.defaultDSN=https://..."
//
// (the Makefile wires this up for normal `make build` invocations).
//
// Left empty by default so that:
//   - `go build ./cmd/cbx` (no ldflags) produces a binary with telemetry
//     effectively disabled even if the user opts in — useful for local
//     development and downstream forks (downstream consumers) that want their own DSN.
//   - Open-source contributors don't unknowingly ship events to our
//     production Sentry project when building from source.
//
// DSNs themselves are designed to be public identifiers — Sentry's
// abuse protection lives at the project level. So baking it into the
// binary is normal practice, not a secret leak. We just want the
// choice to be explicit at build time.
//
// Runtime override: CBX_SENTRY_DSN=... beats the baked-in value;
// CBX_SENTRY_DSN=- disables Sentry init even when config says enabled.
var defaultDSN = ""

var initialized bool

// Init initializes the Sentry client iff telemetry is enabled per config
// and not overridden off by env. Safe to call multiple times; subsequent
// calls are no-ops. The version/commit are surfaced as Sentry tags so
// crashes can be diff'd by build.
func Init(version, commit string) {
	if initialized {
		return
	}
	if !IsEnabled() {
		return
	}
	dsn := os.Getenv("CBX_SENTRY_DSN")
	if dsn == "" {
		dsn = defaultDSN
	}
	if dsn == "-" {
		// Sentinel for "explicitly disable Sentry init even if config says
		// enabled" — useful for tests and local dev.
		return
	}
	if dsn == "" {
		// No DSN baked in and none provided via env — there is nowhere to
		// send events, so skip Sentry init entirely (see defaultDSN above:
		// plain `go build` produces such binaries on purpose).
		return
	}

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          fmt.Sprintf("cbx@%s", version),
		Environment:      environment(),
		AttachStacktrace: true,
		// Performance tracing off by default; flip up later if we want
		// per-command latency histograms in Sentry. Errors are always
		// captured at 100% — that's the whole point of opting in.
		TracesSampleRate: 0.0,
		BeforeSend:       scrubEvent,
		BeforeSendTransaction: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			return scrubEvent(event, hint)
		},
		// CBX_SENTRY_DEBUG=1 prints transport requests/responses to
		// stderr — useful when verifying end-to-end delivery from a
		// new build, or chasing why an event isn't appearing in the
		// dashboard. Off by default to keep normal runs quiet.
		Debug:       os.Getenv("CBX_SENTRY_DEBUG") == "1",
		DebugWriter: os.Stderr,
	})
	if err != nil {
		// Never let a Sentry init failure crash the CLI — telemetry is
		// best-effort. Silently disable.
		return
	}
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag("cbx_version", version)
		scope.SetTag("cbx_commit", commit)
		scope.SetTag("os", runtime.GOOS)
		scope.SetTag("arch", runtime.GOARCH)
		scope.SetTag("go_version", runtime.Version())
	})
	initialized = true
}

// IsEnabled reports whether telemetry should be active given env + config.
// Precedence (highest wins):
//  1. CBX_TELEMETRY=0|off|false|no  → off
//  2. CBX_TELEMETRY=1|on|true|yes   → on
//  3. DO_NOT_TRACK=1                → off (standard https://consoledonottrack.com)
//  4. config file (Telemetry.Enabled)
func IsEnabled() bool {
	switch strings.ToLower(os.Getenv("CBX_TELEMETRY")) {
	case "0", "off", "false", "no":
		return false
	case "1", "on", "true", "yes":
		return true
	}
	if os.Getenv("DO_NOT_TRACK") == "1" {
		return false
	}
	cfg, err := config.Load()
	if err != nil {
		return false
	}
	return cfg.Telemetry.Enabled
}

// SetTag adds a tag to the current Sentry scope. No-op when telemetry
// is disabled. Use for low-cardinality breadcrumbs like "command":
// SetTag("command", "audit aws").
func SetTag(key, value string) {
	if !initialized {
		return
	}
	sentry.ConfigureScope(func(scope *sentry.Scope) {
		scope.SetTag(key, value)
	})
}

// CaptureError reports a non-nil error to Sentry. No-op when telemetry
// is disabled or err is nil. The error message is run through the
// scrubber by BeforeSend before transmission.
func CaptureError(err error) {
	if !initialized || err == nil {
		return
	}
	sentry.CaptureException(err)
}

// Recover is intended for use as `defer telemetry.Recover()` at the
// top of main(). It captures any in-flight panic, flushes the Sentry
// buffer, then re-panics so the runtime's default crash behavior is
// preserved. No-op when telemetry is disabled.
func Recover() {
	if r := recover(); r != nil {
		if initialized {
			sentry.CurrentHub().Recover(r)
			sentry.Flush(2 * time.Second)
		}
		panic(r)
	}
}

// Flush blocks for up to d, allowing the Sentry transport to drain
// before the process exits. No-op when telemetry is disabled.
func Flush(d time.Duration) {
	if !initialized {
		return
	}
	sentry.Flush(d)
}

func environment() string {
	if env := os.Getenv("CBX_SENTRY_ENV"); env != "" {
		return env
	}
	if os.Getenv("CI") == "true" {
		return "ci"
	}
	return "production"
}

// --- PII scrubbing ---------------------------------------------------------

// Pre-compiled patterns for the most common leaks we'd see in stack
// traces and error messages. The set is deliberately small and
// conservative; missing a regex here is safer than over-matching and
// breaking the error message into uselessness.
var (
	// /Users/<name>/ on macOS, /home/<name>/ on Linux, C:\Users\<name>\ on Windows.
	homePathMacOS   = regexp.MustCompile(`/Users/[^/\s"']+`)
	homePathLinux   = regexp.MustCompile(`/home/[^/\s"']+`)
	homePathWindows = regexp.MustCompile(`(?i)C:\\Users\\[^\\\s"']+`)

	// 12-digit standalone runs — AWS account IDs. Conservative: must be
	// surrounded by word boundaries to avoid eating SHA fragments etc.
	awsAccountID = regexp.MustCompile(`\b\d{12}\b`)

	// Common API key prefixes.
	anthropicKey = regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{10,}`)
	openaiKey    = regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`)
	awsAccessKey = regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`)

	// ARNs carry account IDs and resource names; redact the variable tail.
	arnPattern = regexp.MustCompile(`arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{12}:[^\s"']+`)

	// Generic key=value secret shapes (password=…, secret=…, token=…,
	// api_key=…), as they'd appear in env dumps, URLs, or error messages.
	// The optional word prefix also catches client_secret=, access_token=,
	// etc. Requires an explicit "=" so prose like "token expired" survives.
	secretKVPattern = regexp.MustCompile(`(?i)\b([\w.-]*(?:password|passwd|secret|token|api[_-]?key))\s*=\s*[^\s"']+`)
)

func scrubString(s string) string {
	s = homePathMacOS.ReplaceAllString(s, "/Users/<redacted>")
	s = homePathLinux.ReplaceAllString(s, "/home/<redacted>")
	s = homePathWindows.ReplaceAllString(s, `C:\Users\<redacted>`)
	s = awsAccessKey.ReplaceAllString(s, "<aws-access-key>")
	s = anthropicKey.ReplaceAllString(s, "sk-ant-<redacted>")
	s = openaiKey.ReplaceAllString(s, "sk-<redacted>")
	s = arnPattern.ReplaceAllString(s, "arn:aws:<redacted>")
	s = awsAccountID.ReplaceAllString(s, "<aws-account>")
	s = secretKVPattern.ReplaceAllString(s, "${1}=<redacted>")
	return s
}

// scrubEvent runs every user-visible string field of the Sentry event
// through scrubString and strips any host/user identifiers Sentry might
// have collected automatically (hostname, OS user). Keep this list in
// sync with sentry-go's event fields if the SDK adds new sources of PII.
func scrubEvent(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	event.Message = scrubString(event.Message)
	event.ServerName = ""
	event.User = sentry.User{} // strip auto-populated IP/username
	for i := range event.Exception {
		event.Exception[i].Value = scrubString(event.Exception[i].Value)
		event.Exception[i].Type = scrubString(event.Exception[i].Type)
	}
	for i := range event.Breadcrumbs {
		event.Breadcrumbs[i].Message = scrubString(event.Breadcrumbs[i].Message)
	}
	// Scrub the string leaves of structured context data too (the SDK and
	// integrations populate Contexts; the sentry-go version we pin has no
	// Event.Extra field — extras land in Contexts instead).
	for _, ctx := range event.Contexts {
		for k, v := range ctx {
			if s, ok := v.(string); ok {
				ctx[k] = scrubString(s)
			}
		}
	}
	if event.Request != nil {
		event.Request.Cookies = ""
		event.Request.QueryString = ""
		event.Request.Env = nil
		event.Request.Headers = nil
	}
	return event
}
