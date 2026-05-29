package plan

import (
	"context"
	"fmt"
	"strings"

	coreplan "github.com/cloudbooster-io/cbx-cli/core/plan"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/tui/chat"

	tea "github.com/charmbracelet/bubbletea"
)

// MessageSender is the interface consumed by the pipeline to push messages
// into the Bubble Tea program.
type MessageSender interface {
	Send(tea.Msg)
}

// Pipeline orchestrates the propose → LLM → resolve flow.
type Pipeline struct {
	sender   MessageSender
	cfg      *config.Config
	session  *Session
	token    string
	llmToken func(provider string) string
	cancel   context.CancelFunc
}

// NewPipeline creates a pipeline bound to a message sender. token is the
// CloudBooster bearer token (empty = anonymous/mock) and llmToken resolves the
// per-provider LLM credential; both are resolved at the composition root and
// injected here so the pipeline never reads the OS keyring.
func NewPipeline(sender MessageSender, cfg *config.Config, session *Session, token string, llmToken func(provider string) string) *Pipeline {
	return &Pipeline{
		sender:   sender,
		cfg:      cfg,
		session:  session,
		token:    token,
		llmToken: llmToken,
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
		Left:  GetProvider(p.session, p.cfg),
		Right: "cancelled",
	})
}

type pipelineProgress struct {
	sender MessageSender
}

func (pp *pipelineProgress) PhaseStart(phase, total int, label string) {
	// TUI shows phase via status bar, not explicit markers.
}

func (pp *pipelineProgress) SetStatus(left, right string) {
	pp.sender.Send(chat.StatusMsg{Left: left, Right: right})
}

func (pp *pipelineProgress) Token(token string) {
	pp.sender.Send(chat.StreamTokenMsg(token))
}

func (pp *pipelineProgress) Candidate(name, description string) {
	pp.sender.Send(chat.ProposalCandidateMsg{Name: name, Description: description})
}

func (pp *pipelineProgress) Commit() {
	pp.sender.Send(chat.CommitStreamMsg{})
}

func (p *Pipeline) run(ctx context.Context, intent string) {
	runner := coreplan.NewRunner(p.cfg, p.session.ActiveProvider, p.token, p.llmToken)
	plan, err := runner.Run(ctx, intent, &pipelineProgress{sender: p.sender})
	if err != nil {
		p.sendError(err)
		return
	}

	p.sendResolve(plan)

	provider := GetProvider(p.session, p.cfg)
	// CLI executors (claude-code, codex) aren't stored in cfg.LLM.Providers and
	// own their own auth + model selection, so there's no Model to show — render
	// a "local CLI" label instead of an empty model field. They're BYO by
	// definition (the user's own subscription pays; cbx never sees a token).
	if coreplan.IsCLIExecutor(provider) {
		p.sendStatus(fmt.Sprintf("%s | local CLI", provider), "BYO LLM — cost not tracked")
		return
	}

	provCfg, ok := p.cfg.LLM.Providers[provider]
	var right string
	if ok && (strings.Contains(provCfg.BaseURL, "localhost") || strings.Contains(provCfg.BaseURL, "127.0.0.1")) {
		right = "BYO LLM — cost not tracked"
	} else {
		right = "ready"
	}
	p.sendStatus(fmt.Sprintf("%s | %s", provider, provCfg.Model), right)
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

func (p *Pipeline) sendStatus(left, right string) {
	p.sender.Send(chat.StatusMsg{Left: left, Right: right})
}

func convertComponents(components []Component) []chat.ComponentInfo {
	out := make([]chat.ComponentInfo, len(components))
	for i, c := range components {
		out[i] = chat.ComponentInfo{Name: c.Name, Description: c.Description, Service: c.Service}
	}
	return out
}
