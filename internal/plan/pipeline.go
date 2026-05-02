package plan

import (
	"context"
	"fmt"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/core/auth"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/chat"

	tea "github.com/charmbracelet/bubbletea"
)

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

// MessageSender is the interface consumed by the pipeline to push messages
// into the Bubble Tea program.
type MessageSender interface {
	Send(tea.Msg)
}

// Pipeline orchestrates the propose → LLM → resolve flow.
type Pipeline struct {
	sender  MessageSender
	cfg     *config.Config
	session *Session
	cancel  context.CancelFunc
}

// NewPipeline creates a pipeline bound to a message sender.
func NewPipeline(sender MessageSender, cfg *config.Config, session *Session) *Pipeline {
	return &Pipeline{
		sender:  sender,
		cfg:     cfg,
		session: session,
	}
}

// Start begins the pipeline in a background goroutine.
func (p *Pipeline) Start(intent string) {
	// Send PipelineStartMsg from a goroutine so we don't block the caller
	// (which may be running inside a Bubble Tea Update loop).
	go p.sender.Send(chat.PipelineStartMsg{})
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	go p.run(ctx, intent)
}

// Cancel aborts an in-flight pipeline.
func (p *Pipeline) Cancel() {
	if p.cancel != nil {
		p.cancel()
		p.cancel = nil
	}
	p.sender.Send(chat.StatusMsg{
		Left:  getProvider(p.session, p.cfg),
		Right: "cancelled",
	})
}

func (p *Pipeline) run(ctx context.Context, intent string) {
	provider := getProvider(p.session, p.cfg)
	provCfg, ok := p.cfg.LLM.Providers[provider]
	if !ok {
		p.sendError(fmt.Errorf("provider %s not configured", provider))
		return
	}

	// Phase 1: Propose
	p.sendStatus(fmt.Sprintf("proposing | %s", provider), "")
	p.sendToken("**Proposing components...**\n\n")
	p.sendCommit()

	proposer := NewComposeClient(p.cfg.APIURL, loadCBToken())
	components, err := proposer.Propose(ctx, intent)
	if err != nil {
		// Fallback to mock proposal when the API is unreachable.
		components = p.mockPropose(intent)
	}

	for _, c := range components {
		p.sendCandidate(c.Name, c.Description)
	}
	p.sendCommit()

	// Phase 2: LLM
	p.sendStatus(fmt.Sprintf("thinking | %s", provider), "")

	llm := NewLLMCaller(provCfg)
	prompt := buildLLMPrompt(intent, components)

	if err := llm.Stream(ctx, prompt, func(token string) {
		p.sendToken(token)
	}); err != nil {
		p.sendToken(fmt.Sprintf("\n\n*LLM stream unavailable (%v); continuing with proposed components.*\n\n", err))
	}
	p.sendCommit()

	// Phase 3: Resolve
	p.sendStatus(fmt.Sprintf("resolving | %s", provider), "")

	plan, err := proposer.Resolve(ctx, components)
	if err != nil {
		// Fallback to mock resolve when the API is unreachable.
		plan = p.mockResolve(intent, components)
	}

	p.sendResolve(plan)

	var right string
	if strings.Contains(provCfg.BaseURL, "localhost") || strings.Contains(provCfg.BaseURL, "127.0.0.1") {
		right = "BYO LLM — cost not tracked"
	} else {
		right = "ready"
	}
	p.sendStatus(fmt.Sprintf("%s | %s", provider, provCfg.Model), right)
}

func (p *Pipeline) mockPropose(intent string) []Component {
	components := defaultComponents()
	components = applyRefinements(components, intent)
	return components
}

func (p *Pipeline) mockResolve(intent string, components []Component) *Plan {
	return buildPlan(intent, components, 1)
}

func (p *Pipeline) sendToken(token string) {
	p.sender.Send(chat.StreamTokenMsg(token))
}

func (p *Pipeline) sendCandidate(name, desc string) {
	p.sender.Send(chat.ProposalCandidateMsg{Name: name, Description: desc})
}

func (p *Pipeline) sendCommit() {
	p.sender.Send(chat.CommitStreamMsg{})
}

func (p *Pipeline) sendStatus(left, right string) {
	p.sender.Send(chat.StatusMsg{Left: left, Right: right})
}

func (p *Pipeline) sendResolve(plan *Plan) {
	p.sender.Send(chat.ResolveCompleteMsg{
		Intent:     plan.Intent,
		Components: convertComponents(plan.Components),
		ADR:        plan.ADRContent,
		Mermaid:    plan.MermaidContent,
		D2:         plan.D2Content,
		HTML:       plan.HTMLContent,
		Version:    plan.Version,
	})
}

func (p *Pipeline) sendError(err error) {
	p.sender.Send(chat.PipelineErrorMsg{Err: err})
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

func convertComponents(components []Component) []chat.ComponentInfo {
	out := make([]chat.ComponentInfo, len(components))
	for i, c := range components {
		out[i] = chat.ComponentInfo{Name: c.Name, Description: c.Description, Service: c.Service}
	}
	return out
}

func getProvider(session *Session, cfg *config.Config) string {
	if session.ActiveProvider != "" {
		return session.ActiveProvider
	}
	return cfg.LLM.Default
}
