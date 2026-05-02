package plan

import (
	"bufio"
	"context"
	"io"
	"os"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"

	tea "github.com/charmbracelet/bubbletea"
)

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == os.ModeCharDevice
}

// REPL runs the interactive planning TUI.
func REPL(session *Session, client Client, cfg *config.Config, in io.Reader, out io.Writer, initialIntent string) error {
	if initialIntent != "" {
		plan, err := client.GeneratePlan(context.Background(), initialIntent, getProvider(session, cfg))
		if err != nil {
			return err
		}
		session.SetPlan(plan)
		session.AppendTurn(initialIntent, false, plan)
	}

	m := newTUIModel(session, client, cfg)

	var p *tea.Program
	if isTerminal(in) {
		p = tea.NewProgram(m, tea.WithInput(in), tea.WithOutput(out), tea.WithAltScreen())
	} else {
		p = tea.NewProgram(m, tea.WithInput(strings.NewReader("")), tea.WithOutput(out))
		go func() {
			scanner := bufio.NewScanner(in)
			for scanner.Scan() {
				p.Send(inputMsg(scanner.Text()))
			}
			p.Send(eofMsg{})
		}()
	}

	_, err := p.Run()
	return err
}
