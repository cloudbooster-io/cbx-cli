package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ClaudeCodeProvider is the special-cased --llm value that delegates to the
// `claude` CLI (Claude Code) instead of going through cbx's HTTP path.
// Selected by `--llm claude-code`. Reuses the user's existing Claude Code
// authentication; cbx never sees a token. Within Anthropic's policy because
// Claude Code is the permitted client — cbx merely invokes it as a tool.
const ClaudeCodeProvider = "claude-code"

// claudeCodeBinary is the executable name resolved from PATH. Variable so
// tests can swap in a fake.
var claudeCodeBinary = "claude"

// claudeCLIStreamer shells out to `claude -p` and accumulates stdout into
// a single onToken callback. There's no token-level streaming — the binary
// returns the whole completion at once when invoked in print mode. That's
// fine for the audit analyzer (the parser only consumes the joined output).
type claudeCLIStreamer struct {
	binary string
}

func newClaudeCLIStreamer() (*claudeCLIStreamer, error) {
	bin, err := exec.LookPath(claudeCodeBinary)
	if err != nil {
		return nil, fmt.Errorf(
			"--llm %s requires the 'claude' CLI on PATH; install Claude Code from https://claude.com/code",
			ClaudeCodeProvider,
		)
	}
	return &claudeCLIStreamer{binary: bin}, nil
}

// Stream satisfies the llmStreamer interface. Prompt is fed via stdin so we
// don't have to escape it for argv; --output-format text returns the model's
// completion verbatim without the SSE wrapper that --output-format json adds.
func (c *claudeCLIStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	cmd := exec.CommandContext(ctx, c.binary, "-p", "--output-format", "text")
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// exit-status errors carry the stderr message; surface it so the
		// LLM-ERROR finding tells the user something useful (auth expired,
		// rate limit, …) rather than just "exit 1".
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
