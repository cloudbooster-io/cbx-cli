package plan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/tui/chat"

	tea "github.com/charmbracelet/bubbletea"
)

// REPL runs the interactive planning TUI.
func REPL(session *Session, client Client, cfg *config.Config, in io.Reader, out io.Writer, initialIntent string, noTUI bool) error {
	if initialIntent != "" {
		plan, err := client.GeneratePlan(context.Background(), initialIntent, getProvider(session, cfg))
		if err != nil {
			return err
		}
		session.SetPlan(plan)
		session.AppendTurn(initialIntent, false, plan)
	}

	m := chat.NewModel()

	// Status bar
	provider := getProvider(session, cfg)
	m.SetStatusBar(fmt.Sprintf("model: %s", provider), "")

	// Build slash-command registry
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

	// Submit handler for natural-language input
	m.OnSubmit = func(input string) (string, error) {
		ctx := context.Background()
		provider := getProvider(session, cfg)
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

	m.OnBeforeQuit = func() (bool, string) {
		if session.Unsaved && !session.PendingQuit {
			session.PendingQuit = true
			return false, "You have unsaved changes. Use /save first, or /quit to discard."
		}
		return true, ""
	}

	var p *tea.Program
	if chat.IsTUIAvailable(in, noTUI) {
		p = tea.NewProgram(m, tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen())
	} else {
		p = tea.NewProgram(m, tea.WithInput(strings.NewReader("")), tea.WithOutput(out))
		go func() {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				p.Send(chat.InputMsg(scanner.Text()))
			}
			p.Send(chat.EOFMsg{})
		}()
	}

	_, err := p.Run()
	return err
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
