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
	// model, when non-empty, is appended as --model; empty means the
	// CLI's own configured default.
	model string
}

// newClaudeCLIStreamer resolves the claude binary. model, when non-empty, is
// the user's model override (`cbx llm model claude-code …` or --llm-model) and
// is passed to the CLI via --model; when empty the CLI's own default applies.
func newClaudeCLIStreamer(model string) (*claudeCLIStreamer, error) {
	bin, err := exec.LookPath(claudeCodeBinary)
	if err != nil {
		return nil, fmt.Errorf(
			"--llm %s requires the 'claude' CLI on PATH; install Claude Code from https://claude.com/code",
			ClaudeCodeProvider,
		)
	}
	return &claudeCLIStreamer{binary: bin, model: model}, nil
}

// Stream satisfies the llmStreamer interface. Prompt is fed via stdin so we
// don't have to escape it for argv; --output-format text returns the model's
// completion verbatim without the SSE wrapper that --output-format json adds.
func (c *claudeCLIStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	args := []string{"-p", "--output-format", "text"}
	if c.model != "" {
		args = append(args, "--model", c.model)
	}
	cmd := exec.CommandContext(ctx, c.binary, args...)
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return claudeExitError(c.binary, exitErr, &stdout, &stderr)
		}
		return fmt.Errorf("invoking %s: %w", c.binary, err)
	}

	onToken(stdout.String())
	return nil
}

// claudeExitError builds the error for a non-zero claude exit, carrying
// the CLI's own failure message so the LLM-ERROR finding tells the user
// something useful (auth expired, rate limit, …) rather than just
// "exit 1". stderr wins when non-empty, but `claude -p` reports many
// failures on STDOUT with an empty stderr (invalid API key, model
// access, usage limits) — fall back to stdout before giving up.
func claudeExitError(binary string, exitErr *exec.ExitError, stdout, stderr *bytes.Buffer) error {
	msg := strings.TrimSpace(stderr.String())
	if msg == "" {
		msg = strings.TrimSpace(stdout.String())
		// A non-zero exit can leave a partial completion on stdout;
		// cap it so the message still reads as an error.
		const max = 500
		if len(msg) > max {
			msg = msg[:max] + "…"
		}
	}
	if msg != "" {
		return fmt.Errorf("%s exited %d: %s", binary, exitErr.ExitCode(), msg)
	}
	return fmt.Errorf("%s exited %d", binary, exitErr.ExitCode())
}
