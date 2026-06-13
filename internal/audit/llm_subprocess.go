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

// CodexProvider is the analogous --llm value that delegates to the local
// OpenAI Codex CLI (`codex exec`) instead of cbx's HTTP path. Selected by
// `cbx audit aws --llm-executor codex`. Like claude-code it reuses the
// user's own Codex authentication; cbx never sees a token. The name matches
// the `codex` CLI executor registered in internal/llm + pkg/cmd/llm.go.
const CodexProvider = "codex"

// claudeCodeBinary / codexBinary are the executable names resolved from
// PATH. Variables so tests can swap in fakes.
var (
	claudeCodeBinary = "claude"
	codexBinary      = "codex"
)

// isCLIExecutorProvider reports whether an LLMProvider names a local CLI
// executor cbx shells out to (claude-code / codex) rather than an HTTP API
// provider. Audit-local mirror of internal/llm.IsCLIExecutor — the two
// packages stay decoupled (see the note in internal/llm/cli_streamer.go).
func isCLIExecutorProvider(provider string) bool {
	switch provider {
	case ClaudeCodeProvider, CodexProvider:
		return true
	default:
		return false
	}
}

// ruleIDLabelFor maps a CLI-executor provider to the short label embedded
// in synthesised rule_ids (LLM-<label>-<hash>) and Finding.Resource for
// LLM-meta findings.
func ruleIDLabelFor(provider string) string {
	if provider == CodexProvider {
		return "codex"
	}
	return "claudecode"
}

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
			return cliExitError(c.binary, exitErr, &stdout, &stderr)
		}
		return fmt.Errorf("invoking %s: %w", c.binary, err)
	}

	onToken(stdout.String())
	return nil
}

// codexCLIStreamer shells out to `codex exec` (non-interactive) and
// accumulates stdout into a single onToken callback — the codex analog of
// claudeCLIStreamer. Used by the non-grounded source/library path when
// --llm-executor codex is selected. `codex exec` returns the whole final
// agent message at once (no token-level streaming), with progress/reasoning
// on stderr, so reading stdout yields just the completion text.
type codexCLIStreamer struct {
	binary string
	// model, when non-empty, is appended as --model; empty means the
	// codex CLI's own configured default.
	model string
}

// newCodexCLIStreamer resolves the codex binary. model, when non-empty, is
// the user's override (`cbx llm model codex …` or --llm-model), passed to
// the CLI via --model; empty means the CLI's own default.
func newCodexCLIStreamer(model string) (*codexCLIStreamer, error) {
	bin, err := exec.LookPath(codexBinary)
	if err != nil {
		return nil, fmt.Errorf(
			"--llm %s requires the 'codex' CLI on PATH; install OpenAI Codex from https://github.com/openai/codex",
			CodexProvider,
		)
	}
	return &codexCLIStreamer{binary: bin, model: model}, nil
}

// Stream satisfies the llmStreamer interface. Prompt is fed via stdin (the
// trailing `-` argument) so we don't have to escape it for argv. The flag
// shape mirrors internal/llm/cli_streamer.go's codex invocation
// (--skip-git-repo-check so it runs outside a git tree, --color never to
// strip ANSI); the stdin marker must stay last.
func (c *codexCLIStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	args := []string{"exec", "--skip-git-repo-check", "--color", "never"}
	if c.model != "" {
		args = append(args, "--model", c.model)
	}
	args = append(args, "-")
	cmd := exec.CommandContext(ctx, c.binary, args...)
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// cliExitError is binary-parameterised, so the message names
			// codex correctly and reuses the stdout-fallback logic.
			return cliExitError(c.binary, exitErr, &stdout, &stderr)
		}
		return fmt.Errorf("invoking %s: %w", c.binary, err)
	}

	onToken(stdout.String())
	return nil
}

// newCLIExecutorStreamer builds the non-grounded streamer for a CLI
// executor provider (claude-code / codex). Used by the source/library path
// when --cb-knowledge is off.
func newCLIExecutorStreamer(provider, model string) (llmStreamer, error) {
	switch provider {
	case ClaudeCodeProvider:
		return newClaudeCLIStreamer(model)
	case CodexProvider:
		return newCodexCLIStreamer(model)
	default:
		return nil, fmt.Errorf("no CLI executor wired for %q (supported: %q, %q)", provider, ClaudeCodeProvider, CodexProvider)
	}
}

// newGroundedCLIStreamer builds the grounded streamer for a CLI executor
// provider. Both returned streamers satisfy llmStreamer, bundleInstaller,
// and groundingTrailer so the analyzer's grounded post-processing works
// uniformly across executors.
func newGroundedCLIStreamer(provider, model string) (llmStreamer, error) {
	switch provider {
	case ClaudeCodeProvider:
		return newGroundedClaudeStreamer(model)
	case CodexProvider:
		return newGroundedCodexStreamer(model)
	default:
		return nil, fmt.Errorf("no grounded CLI executor wired for %q (supported: %q, %q)", provider, ClaudeCodeProvider, CodexProvider)
	}
}

// cliExitError builds the error for a non-zero CLI-executor exit, carrying
// the CLI's own failure message so the LLM-ERROR finding tells the user
// something useful (auth expired, rate limit, …) rather than just
// "exit 1". stderr wins when non-empty, but `claude -p` reports many
// failures on STDOUT with an empty stderr (invalid API key, model
// access, usage limits) — fall back to stdout before giving up. Shared by
// the claude and codex streamers (both grounded and not).
func cliExitError(binary string, exitErr *exec.ExitError, stdout, stderr *bytes.Buffer) error {
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
