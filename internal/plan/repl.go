package plan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/chat"

	tea "github.com/charmbracelet/bubbletea"
)

// REPL runs the interactive planning TUI.
func REPL(session *Session, cfg *config.Config, in io.Reader, out io.Writer, initialIntent string, noTUI bool, token string, llmToken func(provider string) string) error {
	m := chat.NewModel()
	m.SetStreamRenderer(chat.NewStreamRenderer())

	// Status bar
	provider := GetProvider(session, cfg)
	provCfg, ok := cfg.LLM.Providers[provider]
	statusRight := ""
	if ok && (strings.Contains(provCfg.BaseURL, "localhost") || strings.Contains(provCfg.BaseURL, "127.0.0.1")) {
		statusRight = "BYO LLM — cost not tracked"
	}
	m.SetStatusBar(fmt.Sprintf("%s | %s", provider, provCfg.Model), statusRight)

	// Build slash-command registry (uses MockClient for backward compat).
	client := &MockClient{}
	registry := chat.NewRegistry()
	wrap := func(f func([]string) (string, error)) func([]string) (string, error) {
		return func(args []string) (string, error) {
			session.PendingQuit = false
			return f(args)
		}
	}
	registry.Register(chat.Command{
		Name: "save", Args: "[path]", Summary: "Save current plan to files",
		Handler: wrap(func(args []string) (string, error) { return cmdSave(args, session) }),
	})
	registry.Register(chat.Command{
		Name: "regenerate", Summary: "Re-run LLM with same candidates",
		Handler: wrap(func(args []string) (string, error) { return cmdRegenerate(session, client, cfg) }),
	})
	registry.Register(chat.Command{
		Name: "refine", Args: "<text>", Summary: "Add a follow-up refinement",
		Handler: wrap(func(args []string) (string, error) { return cmdRefine(args, session, client, cfg) }),
	})
	registry.Register(chat.Command{
		Name: "variants", Args: "<N>", Summary: fmt.Sprintf("Request N variants (max %d on free tier)", maxFreeVariants),
		Handler: wrap(func(args []string) (string, error) { return cmdVariants(args, session) }),
	})
	registry.Register(chat.Command{
		Name: "llm", Args: "<provider>", Summary: "Switch active LLM provider",
		Handler: wrap(func(args []string) (string, error) { return cmdLLM(args, session, cfg) }),
	})
	registry.Register(chat.Command{
		Name: "diagram", Args: "mermaid|d2", Summary: "Toggle diagram output format",
		Handler: wrap(func(args []string) (string, error) { return cmdDiagram(args, session) }),
	})
	registry.Register(chat.Command{
		Name: "export", Args: "json [path]", Summary: "Export plan as JSON",
		Handler: wrap(func(args []string) (string, error) { return cmdExport(args, session) }),
	})
	registry.Register(chat.Command{
		Name: "help", Summary: "Show this help message",
		Handler: func(args []string) (string, error) { return registry.Help(), nil },
	})
	registry.Register(chat.Command{
		Name: "quit", Summary: "Exit the planner",
		Handler: func(args []string) (string, error) { return cmdQuit(session) },
	})
	m.SetRegistry(registry)

	// Set up viewport content from session history
	var sb strings.Builder
	for _, turn := range session.History {
		sb.WriteString(formatTurn(turn))
		sb.WriteString("\n\n")
	}
	m.SetContent(sb.String())

	var p *tea.Program
	pipeline := NewPipeline(nil, cfg, session, token, llmToken)

	// Submit handler for natural-language input.
	// In TUI mode we run the async streaming pipeline; in pipe mode we fall
	// back to the synchronous MockClient so that scripted input (e2e tests)
	// remains deterministic.
	m.OnSubmit = func(input string) (string, error) {
		if chat.IsTUIAvailable(in, noTUI) {
			pipeline.Start(input)
			return "", nil
		}
		// Pipe mode: synchronous fallback.
		ctx := context.Background()
		provider := GetProvider(session, cfg)
		if session.CurrentPlan == nil {
			plan, err := client.GeneratePlan(ctx, input, provider)
			if err != nil {
				return "", err
			}
			session.SetPlan(plan)
			session.AppendTurn(input, false, plan)
		} else {
			plan, err := client.RefinePlan(ctx, session.CurrentPlan, input, provider)
			if err != nil {
				return "", err
			}
			session.SetPlan(plan)
			session.AppendTurn(input, true, plan)
		}
		return formatTurn(session.History[len(session.History)-1]), nil
	}

	m.OnCancel = func() {
		pipeline.Cancel()
	}

	m.OnBeforeQuit = func() (bool, string) {
		if session.Unsaved && !session.PendingQuit {
			session.PendingQuit = true
			return false, "You have unsaved changes. Use /save first, or /quit to discard."
		}
		return true, ""
	}

	wrapper := newReplModel(m, session, pipeline)

	if chat.IsTUIAvailable(in, noTUI) {
		p = tea.NewProgram(wrapper, tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen())
	} else {
		p = tea.NewProgram(wrapper, tea.WithInput(strings.NewReader("")), tea.WithOutput(out))
		go func() {
			// In pipe mode, send the initial intent before user-provided lines.
			if initialIntent != "" {
				p.Send(chat.InputMsg(initialIntent))
			}
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				p.Send(chat.InputMsg(scanner.Text()))
			}
			p.Send(chat.EOFMsg{})
		}()
	}

	// Bind the real program to the pipeline now that it exists.
	pipeline.sender = p

	// Auto-start if an initial intent was provided in TUI mode.
	if initialIntent != "" && chat.IsTUIAvailable(in, noTUI) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			p.Send(chat.InputMsg(initialIntent))
		}()
	}

	_, err := p.Run()
	return err
}

// replModel wraps chat.Model to handle pipeline-specific messages.
type replModel struct {
	inner    chat.Model
	session  *Session
	pipeline *Pipeline
}

func newReplModel(inner chat.Model, session *Session, pipeline *Pipeline) replModel {
	return replModel{inner: inner, session: session, pipeline: pipeline}
}

func (m replModel) Init() tea.Cmd {
	return m.inner.Init()
}

func (m replModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case chat.PipelineStartMsg:
		m.inner.SetPipelineRunning(true)
		return m, nil
	case chat.StatusMsg:
		m.inner.SetStatusBar(msg.Left, msg.Right)
		return m, nil
	case chat.ProposalCandidateMsg:
		m.inner.AppendContent(fmt.Sprintf("  • %s — %s", msg.Name, msg.Description))
		return m, nil
	case chat.CommitStreamMsg:
		m.inner.CommitStream()
		return m, nil
	case chat.ResolveCompleteMsg:
		m.inner.SetPipelineRunning(false)
		plan := &Plan{
			Intent:     msg.Intent,
			Components: convertComponentInfo(msg.Components),
			Version:    msg.Version,
		}
		plan.ADRContent = msg.ADR
		plan.D2Content = msg.D2
		plan.MermaidContent = msg.Mermaid
		plan.HTMLContent = msg.HTML
		m.session.SetPlan(plan)
		m.session.AppendTurn(msg.Intent, false, plan)
		m.inner.AppendContent(chat.HeaderStyle.Render(fmt.Sprintf("--- Plan v%d ---", plan.Version)))
		m.inner.AppendContent(plan.ADRContent)
		return m, nil
	case chat.PipelineErrorMsg:
		m.inner.SetPipelineRunning(false)
		m.inner.AppendContent(chat.ErrorStyle.Render(fmt.Sprintf("Error: %v", msg.Err)))
		return m, nil
	}

	updated, cmd := m.inner.Update(msg)
	m.inner = updated.(chat.Model)
	return m, cmd
}

func (m replModel) View() string {
	return m.inner.View()
}

func formatTurn(t Turn) string {
	var sb strings.Builder
	ts := t.Timestamp.Format("2006-01-02 15:04:05")
	if t.IsRefine {
		sb.WriteString(chat.HeaderStyle.Render(fmt.Sprintf("[%s] Refine: %s", ts, t.Input)))
	} else {
		sb.WriteString(chat.HeaderStyle.Render(fmt.Sprintf("[%s] Intent: %s", ts, t.Input)))
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("--- Plan v%d ---\n", t.Plan.Version))
	sb.WriteString(t.Plan.ADRContent)
	return sb.String()
}

func convertComponentInfo(infos []chat.ComponentInfo) []Component {
	out := make([]Component, len(infos))
	for i, c := range infos {
		out[i] = Component{Name: c.Name, Description: c.Description, Service: c.Service}
	}
	return out
}
