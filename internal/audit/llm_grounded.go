package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// cbAPIURLEnv lets users override the CB knowledge backend URL used by
// the grounding enumerator. Empty falls back to defaultCBAPIURL. The
// audit always grounds against a live backend; an unreachable URL
// fails fast with the backend's actual error.
const cbAPIURLEnv = "CB_API_URL"

// defaultCBAPIURL is the CloudBooster knowledge backend the audit
// grounds against by default: the public CloudBooster API. Override via
// CB_API_URL to point at a local dev backend (e.g. on port 18000) or
// any other endpoint.
const defaultCBAPIURL = "https://api.cloudbooster.io"

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

	// model, when non-empty, is appended as --model; empty means the
	// CLI's own configured default. Carries Options.LLMModel (the
	// --llm-model flag, falling back to the `cbx llm model claude-code`
	// pin) into the grounded invocation.
	model string

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
// unreachable. model, when non-empty, pins the claude model for the
// grounded run (see the struct field).
func newGroundedClaudeStreamer(model string) (*groundedClaudeStreamer, error) {
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

	return &groundedClaudeStreamer{binary: bin, model: model}, nil
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
			"CB knowledge backend at %s is unreachable: %v\n  set %s to a reachable backend (e.g. http://localhost:18000 for a local dev backend)",
			apiURL, err, cbAPIURLEnv,
		)
	}
	defer func() { _ = resp.Body.Close() }()
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

// Stream invokes `claude -p` with stream-json output and the prompt on
// stdin. No --mcp-config / --allowedTools — the model has no tools to
// call. We ask for stream-json (which in print mode requires --verbose)
// because the final `result` event is the only place claude surfaces
// total_cost_usd, the field that makes --llm-max-cost enforceable.
// Parsing is tolerant: when the output isn't recognisable stream-json
// (an older claude that ignored the flag, a shim emitting plain text),
// the raw stdout is surfaced as the response and the cost stays 0
// rather than failing the audit.
func (g *groundedClaudeStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	args := []string{"-p", "--output-format", "stream-json", "--verbose"}
	if g.model != "" {
		args = append(args, "--model", g.model)
	}
	cmd := exec.CommandContext(ctx, g.binary, args...)
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return cliExitError(g.binary, exitErr, &stdout, &stderr)
		}
		return fmt.Errorf("running %s: %w", g.binary, runErr)
	}

	if text, cost, ok := parseClaudeStreamJSON(stdout.Bytes()); ok {
		g.totalCostUSD = cost
		onToken(text)
		return nil
	}
	// Degraded fallback: treat stdout as the plain-text response.
	onToken(stdout.String())
	return nil
}

// claudeStreamResultEvent is the subset of the stream-json `result`
// event we read: the final response text and the run's reported cost.
// Older claude builds emitted the cost as cost_usd, so both spellings
// are accepted (total_cost_usd wins when present).
type claudeStreamResultEvent struct {
	Type         string   `json:"type"`
	Result       *string  `json:"result"`
	TotalCostUSD *float64 `json:"total_cost_usd"`
	CostUSD      *float64 `json:"cost_usd"`
}

// parseClaudeStreamJSON scans `claude -p --output-format stream-json`
// output (one JSON event per line) for the `result` event and returns
// its response text + reported cost. The result event is not guaranteed
// to be the last line (hook/system events can trail it), so every line
// is scanned and the last result event wins. ok is false when no result
// event carrying a `result` text field is found — the caller falls back
// to treating the raw output as plain text (older claude versions, test
// shims), with cost 0.
func parseClaudeStreamJSON(out []byte) (text string, cost float64, ok bool) {
	var found *claudeStreamResultEvent
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev claudeStreamResultEvent
		if err := json.Unmarshal(line, &ev); err != nil || ev.Type != "result" {
			continue
		}
		found = &ev
	}
	if found == nil || found.Result == nil {
		return "", 0, false
	}
	switch {
	case found.TotalCostUSD != nil:
		cost = *found.TotalCostUSD
	case found.CostUSD != nil:
		cost = *found.CostUSD
	}
	return *found.Result, cost, true
}

// GroundingTrail exposes the pre-fetched grounding events surfaced by
// InstallBundle. Returns nil when no bundle was installed (e.g. unit
// tests using a fake streamer).
func (g *groundedClaudeStreamer) GroundingTrail() []GroundingEvent { return g.trail }

// TotalCostUSD reports the run's cost as surfaced by the stream-json
// `result` event's total_cost_usd field, assigned by Stream. It feeds
// the LLM-CB-COST-CAP finding in postProcessGrounded. Returns 0 before
// Stream runs, and stays 0 on the plain-text fallback path (output that
// wasn't parseable stream-json) — the cost cap is best-effort there.
func (g *groundedClaudeStreamer) TotalCostUSD() float64 { return g.totalCostUSD }

// groundingTrailer is the optional capability postProcessGrounded
// probes via type assertion to backfill snippets and emit cost-cap
// findings. The deterministic streamer implements both methods.
type groundingTrailer interface {
	GroundingTrail() []GroundingEvent
	TotalCostUSD() float64
}
