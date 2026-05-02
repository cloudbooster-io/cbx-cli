package plan

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
)

var (
	headerStyle          = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	paletteStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	paletteSelectedStyle = lipgloss.NewStyle().Background(lipgloss.Color("7")).Foreground(lipgloss.Color("0"))
)

// tuiModel is the Bubble Tea model for the interactive plan TUI.
type tuiModel struct {
	viewport    viewport.Model
	textinput   textinput.Model
	session     *Session
	client      Client
	cfg         *config.Config
	width       int
	height      int
	paletteMode bool
	paletteIdx  int
	outputLines []string
	done        bool
}

// inputMsg is sent when a complete line is read from stdin (pipe mode).
type inputMsg string

// eofMsg is sent when stdin reaches EOF (pipe mode).
type eofMsg struct{}

func newTUIModel(session *Session, client Client, cfg *config.Config) tuiModel {
	ti := textinput.New()
	ti.Placeholder = "Type an intent or /command..."
	ti.Focus()
	ti.CharLimit = 256

	vp := viewport.New(80, 20)

	m := tuiModel{
		viewport:  vp,
		textinput: ti,
		session:   session,
		client:    client,
		cfg:       cfg,
	}
	m.refreshViewport()
	return m
}

func (m tuiModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - 4
		if m.viewport.Height < 5 {
			m.viewport.Height = 5
		}
		m.textinput.Width = msg.Width - 2
		m.refreshViewport()

	case inputMsg:
		m.textinput.SetValue(string(msg))
		m.handleInput(string(msg))
		m.refreshViewport()

	case eofMsg:
		if m.session.Unsaved && !m.session.PendingQuit {
			m.session.PendingQuit = true
			m.appendOutput("You have unsaved changes. Use /save first, or /quit to discard.")
			m.refreshViewport()
			return m, nil
		}
		m.done = true
		return m, tea.Quit

	case tea.KeyMsg:
		quit := m.handleKey(msg)
		if quit {
			m.refreshViewport()
			if m.done {
				return m, tea.Quit
			}
			return m, tea.Batch(cmds...)
		}

		var cmd tea.Cmd
		m.textinput, cmd = m.textinput.Update(msg)
		cmds = append(cmds, cmd)

		val := m.textinput.Value()
		if strings.HasPrefix(val, "/") {
			m.paletteMode = true
			m.paletteIdx = 0
		} else {
			m.paletteMode = false
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *tuiModel) handleKey(msg tea.KeyMsg) bool {
	switch msg.Type {
	case tea.KeyCtrlC, tea.KeyCtrlD:
		if m.session.Unsaved && !m.session.PendingQuit {
			m.session.PendingQuit = true
			m.appendOutput("You have unsaved changes. Use /save first, or /quit to discard.")
			return true
		}
		m.done = true
		return true

	case tea.KeyEsc:
		if m.paletteMode {
			m.paletteMode = false
			m.textinput.SetValue("")
			return true
		}
		if m.session.Unsaved && !m.session.PendingQuit {
			m.session.PendingQuit = true
			m.appendOutput("You have unsaved changes. Use /save first, or /quit to discard.")
			return true
		}
		m.done = true
		return true

	case tea.KeyEnter, tea.KeyCtrlJ:
		input := m.textinput.Value()
		m.textinput.SetValue("")
		m.paletteMode = false
		if input == "" {
			return true
		}
		m.handleInput(input)
		return true

	case tea.KeyUp:
		if m.paletteMode {
			if m.paletteIdx > 0 {
				m.paletteIdx--
			}
			return true
		}

	case tea.KeyDown:
		if m.paletteMode {
			filtered := m.filteredCommands()
			if m.paletteIdx < len(filtered)-1 {
				m.paletteIdx++
			}
			return true
		}
	}

	return false
}

func (m *tuiModel) handleInput(input string) {
	if strings.HasPrefix(input, "/") {
		cmd, parseErr := ParseSlashCommand(input)
		if parseErr != nil {
			if input == "/" {
				m.appendOutput(cmdHelp())
				return
			}
			m.appendOutput(fmt.Sprintf("Error: %v", parseErr))
			return
		}
		result, execErr := ExecuteSlashCommand(cmd, m.session, m.client, m.cfg)
		if execErr == ErrQuit {
			m.appendOutput(result)
			m.done = true
			return
		}
		if execErr != nil {
			m.appendOutput(fmt.Sprintf("Error: %v", execErr))
			return
		}
		m.appendOutput(result)
		return
	}

	ctx := context.Background()
	provider := getProvider(m.session, m.cfg)

	if m.session.CurrentPlan == nil {
		plan, err := m.client.GeneratePlan(ctx, input, provider)
		if err != nil {
			m.appendOutput(fmt.Sprintf("Error generating plan: %v", err))
			return
		}
		m.session.SetPlan(plan)
		m.session.AppendTurn(input, false, plan)
	} else {
		plan, err := m.client.RefinePlan(ctx, m.session.CurrentPlan, input, provider)
		if err != nil {
			m.appendOutput(fmt.Sprintf("Error refining plan: %v", err))
			return
		}
		m.session.SetPlan(plan)
		m.session.AppendTurn(input, true, plan)
	}
}

func (m *tuiModel) appendOutput(text string) {
	m.outputLines = append(m.outputLines, text)
}

func (m *tuiModel) refreshViewport() {
	var sb strings.Builder
	for _, turn := range m.session.History {
		sb.WriteString(m.formatTurn(turn))
		sb.WriteString("\n\n")
	}
	for _, line := range m.outputLines {
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	m.viewport.SetContent(sb.String())
	m.viewport.GotoBottom()
}

func (m *tuiModel) formatTurn(t Turn) string {
	var sb strings.Builder
	ts := t.Timestamp.Format("2006-01-02 15:04:05")
	if t.IsRefine {
		sb.WriteString(headerStyle.Render(fmt.Sprintf("[%s] Refine: %s", ts, t.Input)))
	} else {
		sb.WriteString(headerStyle.Render(fmt.Sprintf("[%s] Intent: %s", ts, t.Input)))
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("--- Plan v%d ---\n", t.Plan.Version))
	sb.WriteString(t.Plan.ADRContent)
	return sb.String()
}

func (m tuiModel) filteredCommands() []struct{ Name, Args, Description string } {
	filter := strings.ToLower(strings.TrimPrefix(m.textinput.Value(), "/"))
	all := AvailableCommands()
	if filter == "" {
		return all
	}
	var filtered []struct{ Name, Args, Description string }
	for _, c := range all {
		if fuzzyMatch(filter, c.Name) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func fuzzyMatch(pattern, text string) bool {
	pattern = strings.ToLower(pattern)
	text = strings.ToLower(text)
	pi := 0
	for ti := 0; ti < len(text) && pi < len(pattern); ti++ {
		if text[ti] == pattern[pi] {
			pi++
		}
	}
	return pi == len(pattern)
}

func (m tuiModel) View() string {
	if m.done {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(m.viewport.View())
	sb.WriteString("\n")

	if m.paletteMode {
		sb.WriteString(m.renderPalette())
	}

	sb.WriteString(m.textinput.View())
	return sb.String()
}

func (m tuiModel) renderPalette() string {
	filtered := m.filteredCommands()
	if len(filtered) == 0 {
		return paletteStyle.Render("  (no matching commands)\n")
	}

	var sb strings.Builder
	sb.WriteString(paletteStyle.Render("Commands:\n"))
	for i, c := range filtered {
		prefix := "  "
		style := paletteStyle
		if i == m.paletteIdx {
			prefix = "> "
			style = paletteSelectedStyle
		}
		line := fmt.Sprintf("%s/%s %s — %s\n", prefix, c.Name, c.Args, c.Description)
		sb.WriteString(style.Render(line))
	}
	return sb.String()
}
