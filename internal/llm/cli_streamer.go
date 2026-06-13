package llm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// CLIExecutorClaudeCode is the special-cased provider/default name that makes
// cbx shell out to the local `claude` CLI (Claude Code) instead of going
// through the HTTP Caller. It is selected via `cbx llm default claude-code`
// and reuses the user's own Claude Code authentication — cbx never sees a
// token. This mirrors the audit pipeline's own `claude-code` provider
// (internal/audit), kept as a separate constant here so the two packages
// stay decoupled.
const CLIExecutorClaudeCode = "claude-code"

// CLIExecutorCodex is the analogous name for the local OpenAI Codex CLI: it
// makes cbx shell out to `codex exec`, selected via `cbx llm default codex`,
// reusing the user's own Codex authentication. Note the asymmetry with Claude
// (api `claude` vs cli `claude-code`): the codex CLI executor shares its name
// with the `codex` HTTP api provider, matching the `cliExecutors` registry in
// pkg/cmd/llm.go. That collision is harmless — the HTTP Caller only speaks
// claude/openai/ollama, so routing `codex` to the local CLI here is strictly
// additive.
const CLIExecutorCodex = "codex"

// Executable names resolved from PATH. Variables so tests can swap in fakes
// (mirrors internal/audit/llm_subprocess.go).
var (
	claudeCodeBinary = "claude"
	codexBinary      = "codex"
)

// IsCLIExecutor reports whether the given provider name resolves to a local
// CLI executor rather than an HTTP API provider. claude-code and codex are the
// wired executors (the two entries in `cbx llm cli list`). Exported so the CLI
// composition root (pkg/cmd) can route a CLI-only setup (no `llm api login`)
// to the local binary.
func IsCLIExecutor(provider string) bool {
	switch provider {
	case CLIExecutorClaudeCode, CLIExecutorCodex:
		return true
	default:
		return false
	}
}

// cliStreamer shells out to a local LLM CLI binary in non-interactive print
// mode and accumulates its stdout into a single onToken callback. There is no
// token-level streaming — both `claude -p` and `codex exec` return the whole
// completion at once. Both binaries write the clean completion to stdout and
// route diagnostics/progress to stderr, so reading stdout yields just the text.
type cliStreamer struct {
	binary string
	args   []string
}

// newCLIStreamer resolves the local CLI binary and its non-interactive args for
// the given executor name. model, when non-empty, is the user's `cbx llm model`
// override and is passed through to the binary via --model; when empty no flag
// is passed and the CLI's own configured default applies. Returns an actionable
// error if the binary is not on PATH.
func newCLIStreamer(provider, model string) (*cliStreamer, error) {
	switch provider {
	case CLIExecutorClaudeCode:
		bin, err := exec.LookPath(claudeCodeBinary)
		if err != nil {
			return nil, fmt.Errorf(
				"--llm %s requires the 'claude' CLI on PATH; install Claude Code from https://claude.com/code",
				CLIExecutorClaudeCode,
			)
		}
		// --output-format text returns the completion verbatim without the
		// SSE/JSON envelope.
		args := []string{"-p", "--output-format", "text"}
		if model != "" {
			args = append(args, "--model", model)
		}
		return &cliStreamer{binary: bin, args: args}, nil
	case CLIExecutorCodex:
		bin, err := exec.LookPath(codexBinary)
		if err != nil {
			return nil, fmt.Errorf(
				"--llm %s requires the 'codex' CLI on PATH; install OpenAI Codex from https://github.com/openai/codex",
				CLIExecutorCodex,
			)
		}
		// `codex exec` runs non-interactively, reading the prompt from stdin (the
		// trailing `-`). It writes only the final agent message to stdout and
		// sends its progress log / reasoning to stderr, so reading stdout gives
		// clean text. --color never strips ANSI; --skip-git-repo-check lets it
		// run outside a git working tree.
		args := []string{"exec", "--skip-git-repo-check", "--color", "never"}
		if model != "" {
			args = append(args, "--model", model)
		}
		// The stdin marker must stay last.
		args = append(args, "-")
		return &cliStreamer{binary: bin, args: args}, nil
	default:
		return nil, fmt.Errorf("no CLI executor wired for %q (supported: %q, %q)", provider, CLIExecutorClaudeCode, CLIExecutorCodex)
	}
}

// Stream feeds the prompt to the CLI over stdin (so we don't have to escape it
// for argv) and emits the model's completion via onToken.
func (c *cliStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	cmd := exec.CommandContext(ctx, c.binary, c.args...)
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Surface stderr on exit-status errors so the user sees the real
		// cause (auth expired, rate limit, …) rather than just "exit 1".
		// `claude -p` reports many of those failures on STDOUT with an
		// empty stderr (invalid API key, model access, usage limits), so
		// fall back to stdout before giving up on a message.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = truncateForError(strings.TrimSpace(stdout.String()))
			}
			if msg != "" {
				return fmt.Errorf("%s exited %d: %s", c.binary, exitErr.ExitCode(), msg)
			}
			return fmt.Errorf("%s exited %d", c.binary, exitErr.ExitCode())
		}
		return fmt.Errorf("invoking %s: %w", c.binary, err)
	}

	onToken(stdout.String())
	return nil
}

// truncateForError caps a CLI's failure output at a size that still reads
// as an error message — a non-zero exit can leave a partial completion on
// stdout, and quoting all of it would bury the cause.
func truncateForError(s string) string {
	const max = 500
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// probePrompt is the minimal one-shot prompt ProbeCLIExecutor sends. The
// response content is deliberately not validated — shims and unusual
// models are fine — only that the executor exits 0 with a non-empty
// completion.
const probePrompt = "Reply with the single word: ok"

// ProbeCLIExecutor runs a minimal one-shot prompt through the given local
// CLI executor — the same binary, non-interactive flags, and model pin the
// real audit invocation uses — and returns the trimmed response text.
// This is the "does prompting actually work" check that a --version probe
// cannot provide: expired auth, a revoked/unknown model, or an exhausted
// usage limit all pass --version and only surface on a real completion.
func ProbeCLIExecutor(ctx context.Context, provider, model string) (string, error) {
	s, err := newCLIStreamer(provider, model)
	if err != nil {
		return "", err
	}
	var sb strings.Builder
	if err := s.Stream(ctx, probePrompt, func(tok string) { sb.WriteString(tok) }); err != nil {
		return "", err
	}
	resp := strings.TrimSpace(sb.String())
	if resp == "" {
		return "", fmt.Errorf("%s returned an empty completion for the probe prompt", provider)
	}
	return resp, nil
}
