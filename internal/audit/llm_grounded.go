package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// defaultLLMMaxCostUSD is the default --llm-max-cost cap (USD per audit).
// Sourced from `2026-05-11-phase-f-uptime-cost.md` §3: $2.00 covers a typical
// Sonnet/Opus audit with prompt-cache discount and leaves headroom for a
// noisy tool-loop without runaway spend.
const defaultLLMMaxCostUSD = 2.00

// cbxMCPPathEnv is the env-var users set to point the wrapper at a local
// cbx-mcp working tree (typical when iterating on cbx-mcp + cbx-cli together).
// When unset we fall back to `uvx --from <discovered-path> cbx-mcp` against
// the sibling checkout. There's no published-package path yet — `uvx
// cbx-mcp@latest` will be wired once the package ships.
const cbxMCPPathEnv = "CBX_MCP_PATH"

// cbxMCPUseBackendEnv, when set to any non-empty value, opts the cbx-mcp
// subprocess **out** of stub mode — i.e. cbx-mcp will hit the real backend
// (api.cloudbooster.io) instead of reading from a local platform-app
// knowledge tree. Default is stub-on because `api.cloudbooster.io` was
// NXDOMAIN at Phase F implementation time (see Session 2 doc).
const cbxMCPUseBackendEnv = "CBX_MCP_USE_BACKEND"

// cbxMCPKBStubEnv is the cbx-mcp side env flag this wrapper sets when stub
// mode is in force. Keep in sync with cbx-mcp/src/cbx_mcp/kb_stub.py:_ENV_FLAG.
const cbxMCPKBStubEnv = "CBX_MCP_KB_STUB"

// cbxMCPServerName is the key under "mcpServers" in the generated .mcp.json
// AND the prefix claude uses in its tool namespace (`mcp__cbx__*`). Both
// callers of `--allowedTools` and the init-event assertion depend on this
// value being exactly "cbx" — keep them in sync.
const cbxMCPServerName = "cbx"

// GroundingEvent records one tool_use / tool_result pair pulled from the
// claude stream-json output. Snippet pulls from structuredContent when
// present, falling back to the plain-text result. Used to (a) decorate
// Finding.CBSource when the model emitted only a partial citation, and (b)
// surface a structured grounding trail to the renderer/JSON envelope.
type GroundingEvent struct {
	Tool             string                 `json:"tool"`
	Input            map[string]interface{} `json:"input,omitempty"`
	StructuredResult map[string]interface{} `json:"structured_result,omitempty"`
	TextResult       string                 `json:"text_result,omitempty"`
}

// streamJSONEvent is the subset of fields the parser needs. Untyped fields
// (`message`, `tool_use_result`) are kept as json.RawMessage so we can decode
// them with shape-specific structs when relevant.
type streamJSONEvent struct {
	Type           string          `json:"type"`
	Subtype        string          `json:"subtype,omitempty"`
	MCPServers     []mcpServerInfo `json:"mcp_servers,omitempty"`
	Message        json.RawMessage `json:"message,omitempty"`
	ToolUseResult  json.RawMessage `json:"tool_use_result,omitempty"`
	Result         string          `json:"result,omitempty"`
	NumTurns       int             `json:"num_turns,omitempty"`
	TotalCostUSD   float64         `json:"total_cost_usd,omitempty"`
	DurationMS     int             `json:"duration_ms,omitempty"`
	IsError        bool            `json:"is_error,omitempty"`
}

type mcpServerInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type assistantMessage struct {
	Content []assistantContent `json:"content"`
}

type assistantContent struct {
	Type  string                 `json:"type"`
	ID    string                 `json:"id,omitempty"`
	Name  string                 `json:"name,omitempty"`
	Input map[string]interface{} `json:"input,omitempty"`
}

type userMessage struct {
	Content []userContent `json:"content"`
}

type userContent struct {
	Type       string `json:"type"`
	ToolUseID  string `json:"tool_use_id,omitempty"`
	Content    string `json:"content,omitempty"`
}

type toolUseResultPayload struct {
	StructuredContent map[string]interface{} `json:"structuredContent,omitempty"`
}

// groundedClaudeStreamer shells out to `claude -p` with --output-format
// stream-json and an --mcp-config pointing at cbx-mcp, parses NDJSON events
// to build a grounding trail, and exposes the model's final text result via
// the existing onToken/Stream contract. Holds per-call state populated by
// Stream — callers MUST treat one streamer instance as single-use per audit.
type groundedClaudeStreamer struct {
	binary     string
	cbxMCPPath string // resolved path passed to `uvx --from`
	useStub    bool   // when true, inject CBX_MCP_KB_STUB=1 into the MCP subprocess

	// Populated by Stream:
	trail        []GroundingEvent
	finalText    string
	totalCostUSD float64
	numTurns     int
	isError      bool
	resultSeen   bool
}

// newGroundedClaudeStreamer resolves the local claude binary, the cbx-mcp
// install path (CBX_MCP_PATH env > "../cbx-mcp" sibling > error), and the
// stub-vs-backend toggle. Same posture as newClaudeCLIStreamer for binary
// resolution — explicit error so the user sees "install Claude Code" instead
// of a generic exec failure.
func newGroundedClaudeStreamer() (*groundedClaudeStreamer, error) {
	bin, err := exec.LookPath(claudeCodeBinary)
	if err != nil {
		return nil, fmt.Errorf(
			"--cb-knowledge requires the 'claude' CLI on PATH; install Claude Code from https://claude.com/code",
		)
	}

	cbxPath, err := resolveCBXMCPPath()
	if err != nil {
		return nil, err
	}

	useStub := os.Getenv(cbxMCPUseBackendEnv) == ""

	return &groundedClaudeStreamer{
		binary:     bin,
		cbxMCPPath: cbxPath,
		useStub:    useStub,
	}, nil
}

// resolveCBXMCPPath returns the directory containing cbx-mcp's pyproject.toml.
// Honours CBX_MCP_PATH first; otherwise probes the sibling checkout that
// CloudBooster contributors maintain side-by-side with cbx-cli. We don't fall
// back to a published-package path: cbx-mcp isn't on PyPI yet, and silently
// hitting `uvx cbx-mcp` without `--from` would download whatever happens to
// be cached, which is the opposite of "deterministic subprocess."
func resolveCBXMCPPath() (string, error) {
	if p := os.Getenv(cbxMCPPathEnv); p != "" {
		abs, err := filepath.Abs(p)
		if err != nil {
			return "", fmt.Errorf("resolving %s=%q: %w", cbxMCPPathEnv, p, err)
		}
		if _, err := os.Stat(filepath.Join(abs, "pyproject.toml")); err != nil {
			return "", fmt.Errorf(
				"%s=%q does not look like a cbx-mcp checkout (no pyproject.toml): %w",
				cbxMCPPathEnv, p, err,
			)
		}
		return abs, nil
	}

	// Probe for a sibling cbx-mcp checkout next to the cbx-cli working dir.
	// Walks up from cwd; supports both `cd cbx-cli && cbx audit …` and
	// running cbx from inside a nested directory.
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolving cbx-mcp path: getwd: %w", err)
	}
	dir := cwd
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "cbx-mcp", "pyproject.toml")
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Dir(candidate), nil
		}
		// Also check sibling layout when cwd is itself cbx-cli.
		sibling := filepath.Join(filepath.Dir(dir), "cbx-mcp", "pyproject.toml")
		if _, err := os.Stat(sibling); err == nil {
			return filepath.Dir(sibling), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf(
		"--cb-knowledge needs cbx-mcp on disk; set %s to a cbx-mcp checkout or run from inside the cloudbooster/platform workspace",
		cbxMCPPathEnv,
	)
}

// Stream implements llmStreamer. Writes a temp .mcp.json wiring "cbx" to
// `uvx --from <cbxMCPPath> cbx-mcp`, invokes claude with the mandatory Phase F
// flags, parses NDJSON events as they arrive, and finally surfaces
// result.result as a single onToken callback (matching the existing analyzer's
// stream-accumulate-then-parse model).
func (g *groundedClaudeStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	tmpDir, err := os.MkdirTemp("", "cbx-audit-grounded-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cfgPath, err := writeMCPConfig(tmpDir, g.cbxMCPPath, g.useStub)
	if err != nil {
		return err
	}

	// --verbose is required by claude when combining -p with --output-format
	// stream-json; without it claude rejects the flag combination. Verified
	// 2026-05-11 against claude 2.1.138 by the grounded-streamer test fixture.
	//
	// --bare was intentionally dropped 2026-05-11: it strips Claude Code's
	// keychain along with auto-memory/plugins/CLAUDE.md discovery, so the
	// subprocess could connect MCP but couldn't authenticate to Anthropic.
	// --strict-mcp-config alone already enforces the controlled tool
	// surface (no `~/.claude.json` or project `.mcp.json` leakage). The
	// remaining --bare side-effects (auto-memory, plugins, CLAUDE.md
	// discovery) are noise for an audit run and don't affect finding
	// correctness; accept the trade-off for the v1 ship.
	args := []string{
		"-p",
		"--mcp-config", cfgPath,
		"--strict-mcp-config",
		"--allowedTools", "mcp__" + cbxMCPServerName + "__*",
		"--permission-mode", "auto",
		"--output-format", "stream-json",
		"--verbose",
	}
	cmd := exec.CommandContext(ctx, g.binary, args...)
	cmd.Stdin = strings.NewReader(prompt)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("attaching stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", g.binary, err)
	}

	parseErr := g.parseStream(stdout)

	// Drain stdout closure / process exit before composing the error.
	waitErr := cmd.Wait()
	if parseErr != nil {
		return parseErr
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return fmt.Errorf("%s exited %d: %s", g.binary, exitErr.ExitCode(), msg)
			}
			return fmt.Errorf("%s exited %d", g.binary, exitErr.ExitCode())
		}
		return fmt.Errorf("waiting on %s: %w", g.binary, waitErr)
	}

	if !g.resultSeen {
		return fmt.Errorf("claude stream-json ended without a `result` event")
	}
	onToken(g.finalText)
	return nil
}

// parseStream reads NDJSON events from r and updates streamer state. Returns
// fast when the init event reports cbx as not-connected; this is the most
// common Phase F failure mode (cbx-mcp not installed / uvx unreachable) and
// failing here surfaces a clear error instead of "the LLM didn't cite cb_source."
func (g *groundedClaudeStreamer) parseStream(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	// Stream-json lines can hold large tool_use_result payloads — bump the
	// max token to avoid bufio.ErrTooLong on real audits.
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20)

	pendingToolUse := map[string]assistantContent{} // id → tool_use call

	initSeen := false
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev streamJSONEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			// Tolerate non-JSON noise; only stream-json events matter for
			// grounding. claude with --bare doesn't emit such noise in
			// practice, but be defensive against future stream shapes.
			continue
		}

		switch ev.Type {
		case "system":
			if ev.Subtype == "init" {
				initSeen = true
				if err := assertCBXConnected(ev.MCPServers); err != nil {
					return err
				}
			}
		case "assistant":
			var msg assistantMessage
			if err := json.Unmarshal(ev.Message, &msg); err != nil {
				continue
			}
			for _, c := range msg.Content {
				if c.Type == "tool_use" && c.ID != "" {
					pendingToolUse[c.ID] = c
				}
			}
		case "user":
			var msg userMessage
			if err := json.Unmarshal(ev.Message, &msg); err != nil {
				continue
			}
			for _, c := range msg.Content {
				if c.Type != "tool_result" || c.ToolUseID == "" {
					continue
				}
				use, ok := pendingToolUse[c.ToolUseID]
				if !ok {
					continue
				}
				ge := GroundingEvent{
					Tool:       stripMCPPrefix(use.Name),
					Input:      use.Input,
					TextResult: c.Content,
				}
				if len(ev.ToolUseResult) > 0 {
					var tur toolUseResultPayload
					if err := json.Unmarshal(ev.ToolUseResult, &tur); err == nil {
						ge.StructuredResult = tur.StructuredContent
					}
				}
				g.trail = append(g.trail, ge)
				delete(pendingToolUse, c.ToolUseID)
			}
		case "result":
			g.resultSeen = true
			g.finalText = ev.Result
			g.totalCostUSD = ev.TotalCostUSD
			g.numTurns = ev.NumTurns
			g.isError = ev.IsError
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading stream-json: %w", err)
	}
	if !initSeen {
		return fmt.Errorf("claude stream-json missing init event; cbx-mcp connection unverified")
	}
	return nil
}

// assertCBXConnected enforces §4.3's init-event gate: bail fast when the cbx
// MCP server didn't connect (no need to wait for an empty or hallucinated
// model output) and bail just as fast when claude didn't even surface it.
func assertCBXConnected(servers []mcpServerInfo) error {
	for _, s := range servers {
		if s.Name == cbxMCPServerName {
			if s.Status == "connected" {
				return nil
			}
			return fmt.Errorf(
				"cbx-mcp connection failed: status=%q (check %s; run `uvx --from <path> cbx-mcp --help` to debug)",
				s.Status, cbxMCPPathEnv,
			)
		}
	}
	return fmt.Errorf(
		"claude init event does not list the %q MCP server; check --mcp-config and --strict-mcp-config",
		cbxMCPServerName,
	)
}

// stripMCPPrefix turns "mcp__cbx__aws_lookup_primitive" into
// "aws_lookup_primitive" so cb_source.tool matches the cbx-mcp tool name a
// human would read in CLAUDE.md.
func stripMCPPrefix(name string) string {
	prefix := "mcp__" + cbxMCPServerName + "__"
	return strings.TrimPrefix(name, prefix)
}

// writeMCPConfig materialises the .mcp.json claude consumes. When useStub is
// true we inject CBX_MCP_KB_STUB=1 into the cbx-mcp subprocess env so the
// stub Python module short-circuits backend calls. The server name must
// match cbxMCPServerName — both the init assertion and the --allowedTools
// glob key off it.
func writeMCPConfig(dir, cbxMCPPath string, useStub bool) (string, error) {
	env := map[string]string{}
	if useStub {
		env[cbxMCPKBStubEnv] = "1"
	}
	cfg := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			cbxMCPServerName: map[string]interface{}{
				"command": "uvx",
				"args":    []string{"--from", cbxMCPPath, "cbx-mcp"},
				"env":     env,
			},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding .mcp.json: %w", err)
	}
	cfgPath := filepath.Join(dir, ".mcp.json")
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		return "", fmt.Errorf("writing .mcp.json: %w", err)
	}
	return cfgPath, nil
}

// GroundingTrail exposes the parsed tool_use/tool_result pairs the streamer
// observed during the last Stream call. Returns nil if Stream hasn't run.
// Surfaced via the groundingTrailer interface so the analyzer can backfill
// Finding.CBSource without depending on the concrete streamer type.
func (g *groundedClaudeStreamer) GroundingTrail() []GroundingEvent { return g.trail }

// TotalCostUSD reports the model's reported cost from the terminating
// `result` event (zero when not provided by claude). Used by the analyzer to
// emit the --llm-max-cost warning.
func (g *groundedClaudeStreamer) TotalCostUSD() float64 { return g.totalCostUSD }

// groundingTrailer is the optional capability the analyzer probes via type
// assertion. Concrete groundedClaudeStreamer implements it; the legacy
// claudeCLIStreamer does not, which is exactly how the analyzer distinguishes
// "ungrounded run" from "grounded run with zero citations."
type groundingTrailer interface {
	GroundingTrail() []GroundingEvent
	TotalCostUSD() float64
}
