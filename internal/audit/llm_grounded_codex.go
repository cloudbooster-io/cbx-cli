package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// groundedCodexStreamer is the OpenAI Codex analog of
// groundedClaudeStreamer: it shells out to `codex exec` with the big
// grounded prompt on stdin and surfaces the final agent message for
// findings parsing. Like the claude grounded streamer, ALL CB-knowledge
// grounding is fetched Go-side and inlined into the prompt (see
// buildGroundedPrompt + BuildGrounding) — codex calls no tools — and the
// deterministic grounding trail is wired in via InstallBundle so
// postProcessGrounded's snippet backfill keeps working unchanged.
//
// Feature parity vs claude (deliberate v1 degradation):
//   - findings: full — parsed from the response JSON.
//   - connections: full — parsed from the same response JSON
//     (parseLLMConnections is provider-agnostic).
//   - cb_source snippet backfill: full — sourced from the Go-side trail,
//     not the model's output.
//   - cost cap (--llm-max-cost): NOT enforced. `codex exec` surfaces no
//     per-run cost, so TotalCostUSD() always returns 0 and the cost-cap
//     branch in postProcessGrounded is a no-op (no panic, no finding). The
//     CLI prints an explicit note when codex is selected with a cap.
type groundedCodexStreamer struct {
	binary string

	// model, when non-empty, is appended as --model; empty means the
	// codex CLI's own configured default. Carries Options.LLMModel (the
	// --llm-model flag, falling back to the `cbx llm model codex` pin).
	model string

	// trail is the deterministic grounding trail, set by InstallBundle
	// before Stream runs — seeded from the Go-side fetch, identical to the
	// claude grounded streamer.
	trail []GroundingEvent
}

// newGroundedCodexStreamer resolves the local codex binary and preflights
// the CB knowledge backend, mirroring newGroundedClaudeStreamer so an
// unreachable backend aborts before discovery rather than silently
// degrading the grounding bundle. model, when non-empty, pins the codex
// model for the grounded run.
func newGroundedCodexStreamer(model string) (*groundedCodexStreamer, error) {
	bin, err := exec.LookPath(codexBinary)
	if err != nil {
		return nil, fmt.Errorf(
			"cbx audit aws --llm-executor codex requires the 'codex' CLI on PATH; install OpenAI Codex from https://github.com/openai/codex",
		)
	}

	apiURL := resolvedCBAPIURL()
	if err := preflightCBBackend(apiURL); err != nil {
		return nil, err
	}

	return &groundedCodexStreamer{binary: bin, model: model}, nil
}

// InstallBundle stores the pre-fetched grounding bundle's events on the
// streamer so GroundingTrail() reports the deterministic Go-side fetches.
// Mirrors groundedClaudeStreamer.InstallBundle.
func (g *groundedCodexStreamer) InstallBundle(bundle *GroundingBundle) {
	if bundle == nil {
		g.trail = nil
		return
	}
	g.trail = bundle.toEvents()
}

// Stream invokes `codex exec` with the prompt on stdin. The flag shape
// matches internal/llm/cli_streamer.go's codex invocation
// (--skip-git-repo-check, --color never; stdin marker last). Codex returns
// the whole final agent message at once on stdout — no stream-json, so no
// cost is available (see TotalCostUSD). The response text is surfaced
// verbatim for parseLLMFindings / parseLLMConnections.
func (g *groundedCodexStreamer) Stream(ctx context.Context, prompt string, onToken func(string)) error {
	args := []string{"exec", "--skip-git-repo-check", "--color", "never"}
	if g.model != "" {
		args = append(args, "--model", g.model)
	}
	args = append(args, "-")
	cmd := exec.CommandContext(ctx, g.binary, args...)
	cmd.Stdin = strings.NewReader(prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if runErr := cmd.Run(); runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return cliExitError(g.binary, exitErr, &stdout, &stderr)
		}
		return fmt.Errorf("running %s: %w", g.binary, runErr)
	}

	onToken(stdout.String())
	return nil
}

// GroundingTrail exposes the pre-fetched grounding events surfaced by
// InstallBundle. Returns nil when no bundle was installed.
func (g *groundedCodexStreamer) GroundingTrail() []GroundingEvent { return g.trail }

// TotalCostUSD always returns 0: `codex exec` reports no per-run cost the
// way `claude -p --output-format stream-json` does via total_cost_usd.
// Consequently --llm-max-cost is unenforced for the codex executor — the
// cost-cap branch in postProcessGrounded never fires (0 is never > a
// positive cap). This is the one deliberate parity gap vs claude; it is
// documented and surfaced to the user, never a silent nil-deref.
func (g *groundedCodexStreamer) TotalCostUSD() float64 { return 0 }
