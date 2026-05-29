package plan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// CLIExecutorClaudeCode is the special-cased provider/default name that makes
// cbx plan shell out to the local `claude` CLI (Claude Code) instead of going
// through the HTTP LLMCaller. It is selected via `cbx llm default claude-code`
// (or `cbx plan --llm claude-code`) and reuses the user's own Claude Code
// authentication — cbx never sees a token. This mirrors the audit pipeline's
// own `claude-code` provider (internal/audit), kept as a separate constant
// here so core/plan stays importable without dragging in internal/audit.
const CLIExecutorClaudeCode = "claude-code"

// claudeCodeBinary is the executable name resolved from PATH. Variable so
// tests can swap in a fake (mirrors internal/audit/llm_subprocess.go).
var claudeCodeBinary = "claude"

// IsCLIExecutor reports whether the given provider name resolves to a local
// CLI executor rather than an HTTP API provider. Only claude-code is wired up
// today; codex (the other entry in `cbx llm cli list`) has no streamer yet.
// Exported so the CLI composition root (pkg/cmd) can decide whether a
// CLI-only setup (no `llm api login`) satisfies the plan precondition.
func IsCLIExecutor(provider string) bool {
	return provider == CLIExecutorClaudeCode
}

// cliStreamer shells out to a local LLM CLI binary in non-interactive print
// mode and accumulates its stdout into a single onToken callback. There is no
// token-level streaming — `claude -p` returns the whole completion at once —
// which is fine for the plan pipeline (Phase 2 output is rendered as a block).
type cliStreamer struct {
	binary string
}

// newCLIStreamer resolves the local CLI binary for the given executor name.
// Returns an actionable error if the binary is not on PATH.
func newCLIStreamer(provider string) (*cliStreamer, error) {
	if provider != CLIExecutorClaudeCode {
		return nil, fmt.Errorf("no CLI executor wired for %q (only %q is supported)", provider, CLIExecutorClaudeCode)
	}
	bin, err := exec.LookPath(claudeCodeBinary)
	if err != nil {
		return nil, fmt.Errorf(
			"--llm %s requires the 'claude' CLI on PATH; install Claude Code from https://claude.com/code",
			CLIExecutorClaudeCode,
		)
	}
	return &cliStreamer{binary: bin}, nil
}

// Stream feeds the prompt to the CLI over stdin (so we don't have to escape it
// for argv) and emits the model's completion via onToken. --output-format text
// returns the completion verbatim without the SSE/JSON envelope.
func (c *cliStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	cmd := exec.CommandContext(ctx, c.binary, "-p", "--output-format", "text")
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Surface stderr on exit-status errors so the user sees the real
		// cause (auth expired, rate limit, …) rather than just "exit 1".
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return fmt.Errorf("%s exited %d: %s", c.binary, exitErr.ExitCode(), msg)
			}
			return fmt.Errorf("%s exited %d", c.binary, exitErr.ExitCode())
		}
		return fmt.Errorf("invoking %s: %w", c.binary, err)
	}

	onToken(stdout.String())
	return nil
}
