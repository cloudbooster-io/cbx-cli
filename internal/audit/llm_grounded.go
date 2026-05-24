package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// defaultLLMMaxCostUSD is the default --llm-max-cost cap (USD per audit).
// Sourced from `2026-05-11-phase-f-uptime-cost.md` §3: $2.00 covered the
// previous MCP-tool-loop audit with room for noise. The deterministic
// grounding path is dramatically cheaper (one prompt, no tool turns),
// so the cap mostly serves as a guardrail against future model drift.
const defaultLLMMaxCostUSD = 2.00

// cbAPIURLEnv lets users override the CB knowledge backend URL used by
// the grounding enumerator. Empty falls back to defaultCBAPIURL. The
// audit always grounds against a live backend; an unreachable URL
// fails fast with the backend's actual error.
const cbAPIURLEnv = "CB_API_URL"

// defaultCBAPIURL is the CloudBooster knowledge backend the audit
// grounds against by default. Currently pointed at the local
// platform-app dev backend (host-published on port 18000) because
// api.cloudbooster.io is not yet reachable from outside the cluster.
// Flip this to the production URL once it ships; override via
// CB_API_URL for any other endpoint.
const defaultCBAPIURL = "http://localhost:18000"

// GroundingEvent records one CB-knowledge fetch as a flat
// (tool, input, result) triple. Historically these came from parsing
// the LLM's MCP tool-call stream; in the deterministic path they are
// synthesised by GroundingBundle.toEvents() from Go-side fetches. The
// shape stays the same so snippetForCitation / postProcessGrounded
// keep working unchanged.
type GroundingEvent struct {
	Tool             string                 `json:"tool"`
	Input            map[string]interface{} `json:"input,omitempty"`
	StructuredResult map[string]interface{} `json:"structured_result,omitempty"`
	TextResult       string                 `json:"text_result,omitempty"`
}

// groundedClaudeStreamer shells out to `claude -p` with NO MCP
// configuration, so the model literally cannot call tools. All
// CB-knowledge grounding is fetched Go-side and inlined in the prompt
// (see buildGroundedPrompt + BuildGrounding). The streamer keeps the
// GroundingTrail() interface for backward compat with
// postProcessGrounded — InstallBundle wires the pre-fetched events in.
type groundedClaudeStreamer struct {
	binary string

	// trail is the deterministic grounding trail, set by InstallBundle
	// before Stream runs. We seed it from the Go-side fetch rather than
	// parsing LLM tool calls — that's the whole reason this rewrite
	// exists.
	trail []GroundingEvent

	// Populated by Stream, surfaced via TotalCostUSD for the cost-cap
	// finding in postProcessGrounded.
	totalCostUSD float64
}

// newGroundedClaudeStreamer resolves the local claude binary and
// preflights the CB knowledge backend. The backend check is up-front
// so the audit fails before discovery if grounding is going to be
// unreachable.
func newGroundedClaudeStreamer() (*groundedClaudeStreamer, error) {
	bin, err := exec.LookPath(claudeCodeBinary)
	if err != nil {
		return nil, fmt.Errorf(
			"cbx audit aws requires the 'claude' CLI on PATH; install Claude Code from https://claude.com/code",
		)
	}

	apiURL := resolvedCBAPIURL()
	if err := preflightCBBackend(apiURL); err != nil {
		return nil, err
	}

	return &groundedClaudeStreamer{binary: bin}, nil
}

// resolvedCBAPIURL returns the CB knowledge backend URL the audit will
// use: CB_API_URL when set, otherwise defaultCBAPIURL.
func resolvedCBAPIURL() string {
	if u := os.Getenv(cbAPIURLEnv); u != "" {
		return u
	}
	return defaultCBAPIURL
}

// preflightCBBackend confirms the CB knowledge backend is reachable
// before we launch claude and the grounding enumerator. Without this
// check, an unreachable backend silently degrades into a half-fetched
// bundle → mostly-empty grounding context → spurious findings. Ping
// /health with a short timeout; non-2xx and network errors both abort
// with an actionable message naming the URL and the override env var.
func preflightCBBackend(apiURL string) error {
	u, err := url.Parse(apiURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid CB API URL %q (set %s to a reachable backend)", apiURL, cbAPIURLEnv)
	}
	healthURL := strings.TrimRight(apiURL, "/") + "/health"
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(healthURL)
	if err != nil {
		return fmt.Errorf(
			"CB knowledge backend at %s is unreachable: %v\n  set %s to a reachable backend (e.g. http://localhost:18000 for a local platform-app)",
			apiURL, err, cbAPIURLEnv,
		)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf(
			"CB knowledge backend at %s returned HTTP %d on /health; set %s to a reachable backend",
			apiURL, resp.StatusCode, cbAPIURLEnv,
		)
	}
	return nil
}

// InstallBundle stores the pre-fetched grounding bundle's events on
// the streamer so GroundingTrail() reports the deterministic Go-side
// fetches that actually produced the model's context. Called by the
// analyzer before Stream.
func (g *groundedClaudeStreamer) InstallBundle(bundle *GroundingBundle) {
	if bundle == nil {
		g.trail = nil
		return
	}
	g.trail = bundle.toEvents()
}

// Stream invokes `claude -p` with text output and the prompt on
// stdin. No --mcp-config / --allowedTools / --output-format stream-json
// — the model has no tools to call and we don't need to parse the
// stream-json envelope. stdout accumulates into the final text result.
func (g *groundedClaudeStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	cmd := exec.CommandContext(ctx, g.binary, "-p", "--output-format", "text")
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return fmt.Errorf("%s exited %d: %s", g.binary, exitErr.ExitCode(), msg)
			}
			return fmt.Errorf("%s exited %d", g.binary, exitErr.ExitCode())
		}
		return fmt.Errorf("running %s: %w", g.binary, runErr)
	}

	onToken(stdout.String())
	return nil
}

// GroundingTrail exposes the pre-fetched grounding events surfaced by
// InstallBundle. Returns nil when no bundle was installed (e.g. unit
// tests using a fake streamer).
func (g *groundedClaudeStreamer) GroundingTrail() []GroundingEvent { return g.trail }

// TotalCostUSD reports the model's reported cost. With no MCP tool
// loop and a single non-stream invocation, claude -p does not surface
// a structured cost back to us — this returns 0. The cost-cap finding
// in postProcessGrounded therefore only fires for legacy MCP-driven
// streamers (kept for future use if/when claude -p exposes a cost
// header).
func (g *groundedClaudeStreamer) TotalCostUSD() float64 { return g.totalCostUSD }

// groundingTrailer is the optional capability postProcessGrounded
// probes via type assertion to backfill snippets and emit cost-cap
// findings. The deterministic streamer implements both methods.
type groundingTrailer interface {
	GroundingTrail() []GroundingEvent
	TotalCostUSD() float64
}
