package plan

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
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
}

// NewRunner creates a new runner.
func NewRunner(cfg *config.Config, activeProvider string) *Runner {
	return &Runner{cfg: cfg, activeProvider: activeProvider}
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

	proposer := NewComposeClient(r.cfg.APIURL, loadCBToken())
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

	llm := NewLLMCaller(provCfg)
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

// loadCBToken returns the user's CloudBooster access token from the keyring,
// or empty string if not authenticated. Empty token falls back to mock mode.
func loadCBToken() string {
	kr, err := auth.NewKeyring()
	if err != nil {
		return ""
	}
	tok, err := auth.LoadToken(kr)
	if err != nil || tok == nil {
		return ""
	}
	return tok.AccessToken
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
