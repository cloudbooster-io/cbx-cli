package plan

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// Progress receives progress updates from Runner.
type Progress interface {
	PhaseStart(phase int, total int, label string)
	SetStatus(left, right string)
	Token(token string)
	Candidate(name, description string)
	Commit()
}

// Runner executes the propose → LLM → resolve flow synchronously.
type Runner struct {
	cfg            *config.Config
	activeProvider string
	// token is the CloudBooster bearer token used for compose API calls.
	// It is injected by the caller (resolved at the CLI composition root via
	// auth.AccessToken()); an empty token falls back to mock/anonymous mode.
	token string
	// llmToken resolves the LLM provider credential for a given provider name.
	// It too is injected by the composition root, as a resolver (not a fixed
	// string) so the active provider can change mid-session — e.g. via the
	// REPL's /llm command — and still resolve the right credential. A nil
	// resolver yields an empty token: fine for offline providers, and the rest
	// degrade to the "stream unavailable" path. Together with token, this is
	// what keeps the runner from ever reading the OS keyring itself.
	llmToken func(provider string) string
}

// NewRunner creates a new runner. token is the CloudBooster bearer token
// (empty = anonymous/mock) and llmToken resolves the per-provider LLM
// credential; both are resolved at the composition root rather than having the
// runner reach into the OS keyring. A nil llmToken resolves to an empty token.
func NewRunner(cfg *config.Config, activeProvider, token string, llmToken func(provider string) string) *Runner {
	return &Runner{cfg: cfg, activeProvider: activeProvider, token: token, llmToken: llmToken}
}

// Run executes the full pipeline once and returns the resulting plan.
func (r *Runner) Run(ctx context.Context, intent string, progress Progress) (*Plan, error) {
	provider := r.activeProvider
	if provider == "" {
		provider = r.cfg.LLM.Default
	}
	provCfg, ok := r.cfg.LLM.Providers[provider]
	if !ok {
		return nil, fmt.Errorf("provider %s not configured", provider)
	}

	// Phase 1: Propose
	progress.PhaseStart(1, 3, "Proposing components")
	progress.SetStatus(fmt.Sprintf("proposing | %s", provider), "")
	progress.Token("**Proposing components...**\n\n")
	progress.Commit()

	proposer := NewComposeClient(r.cfg.APIURL, r.token)
	components, err := proposer.Propose(ctx, intent)
	if err != nil {
		components = defaultComponents()
		components = applyRefinements(components, intent)
	}

	for _, c := range components {
		progress.Candidate(c.Name, c.Description)
	}
	progress.Commit()

	// Phase 2: LLM
	progress.PhaseStart(2, 3, "Thinking")
	progress.SetStatus(fmt.Sprintf("thinking | %s", provider), "")

	var llmToken string
	if r.llmToken != nil {
		llmToken = r.llmToken(provider)
	}
	llm := NewLLMCaller(provCfg, llmToken)
	prompt := buildLLMPrompt(intent, components)

	if err := llm.Stream(ctx, prompt, func(token string) {
		progress.Token(token)
	}); err != nil {
		progress.Token(fmt.Sprintf("\n\n*LLM stream unavailable (%v); continuing with proposed components.*\n\n", err))
	}
	progress.Commit()

	// Phase 3: Resolve
	progress.PhaseStart(3, 3, "Resolving plan")
	progress.SetStatus(fmt.Sprintf("resolving | %s", provider), "")

	plan, err := proposer.Resolve(ctx, components)
	if err != nil {
		plan = buildPlan(intent, components, 1)
	}

	return plan, nil
}

// GetProvider returns the active provider from the session or the config default.
func GetProvider(session *Session, cfg *config.Config) string {
	if session.ActiveProvider != "" {
		return session.ActiveProvider
	}
	return cfg.LLM.Default
}

func buildLLMPrompt(intent string, components []Component) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("You are an AWS cloud architect. The user wants: %q\n\n", intent))
	sb.WriteString("Proposed components:\n")
	for _, c := range components {
		sb.WriteString(fmt.Sprintf("- %s: %s\n", c.Name, c.Description))
	}
	sb.WriteString("\nPlease rank these components and suggest any improvements or missing pieces. Be concise.")
	return sb.String()
}
