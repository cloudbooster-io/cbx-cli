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

// CLIExecutorCodex is the analogous name for the local OpenAI Codex CLI: it
// makes cbx plan shell out to `codex exec`, selected via `cbx llm default codex`
// (or `cbx plan --llm codex`), reusing the user's own Codex authentication.
// Note the asymmetry with Claude (api `claude` vs cli `claude-code`): the codex
// CLI executor shares its name with the `codex` HTTP api provider, matching the
// `cliExecutors` registry in pkg/cmd/llm.go. That collision is harmless — the
// HTTP `codex` provider has no working plan path anyway (core/plan's LLMCaller
// only speaks claude/openai/ollama), so routing `codex` to the local CLI here
// is strictly additive.
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
// composition root (pkg/cmd) can decide whether a CLI-only setup (no
// `llm api login`) satisfies the plan precondition.
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
// completion at once — which is fine for the plan pipeline (Phase 2 output is
// rendered as a block). Both binaries write the clean completion to stdout and
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
