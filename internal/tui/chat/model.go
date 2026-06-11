package chat

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// InputMsg is sent when a complete line is read from stdin (pipe mode).
type InputMsg string

// EOFMsg is sent when stdin reaches EOF (pipe mode).
type EOFMsg struct{}

// StreamTokenMsg carries a single token from the LLM stream.
type StreamTokenMsg string

// PipelineStartMsg signals that the pipeline has started.
type PipelineStartMsg struct{}

// StatusMsg updates the status bar text.
type StatusMsg struct {
	Left  string
	Right string
}

// ProposalCandidateMsg carries a single component candidate from the propose phase.
type ProposalCandidateMsg struct {
	Name        string
	Description string
}

// CommitStreamMsg forces the stream renderer to commit its content.
type CommitStreamMsg struct{}

// ComponentInfo is a plan-component snapshot sent through the TUI.
type ComponentInfo struct {
	Name        string
	Description string
	Service     string
}

// ResolveCompleteMsg carries the final resolved plan.
type ResolveCompleteMsg struct {
	Intent     string
	Components []ComponentInfo
	Version    int
	ADR        string
	Mermaid    string
	D2         string
	HTML       string
}

// PipelineErrorMsg signals a pipeline error.
type PipelineErrorMsg struct {
	Err error
}

// Model is the generic chat TUI Bubble Tea model.
type Model struct {
	viewport viewport.Model
	textarea textarea.Model
	width    int
	height   int

	paletteMode bool
	paletteIdx  int

	history    []string
	historyIdx int

	registry *Registry

	viewportContent string

	streamRenderer *StreamRenderer

	statusLeft  string
	statusRight string

	quitting bool

	// OnSubmit is called when the user submits non-slash input.
	// The returned string is appended to the viewport as an assistant message.
	// An empty response with a nil error is ignored, enabling async pipelines.
	OnSubmit func(input string) (response string, err error)

	// OnBeforeQuit is called before quitting. If it returns false and a
	// warning message, the quit is cancelled and the warning is shown.
	OnBeforeQuit func() (allow bool, warning string)

	// OnCancel is called when Ctrl+C is pressed while a pipeline is running.
	OnCancel func()

	pipelineRunning bool
}

// NewModel creates a new chat TUI model with sensible defaults.
func NewModel() Model {
	ta := textarea.New()
	ta.Placeholder = "Type a message or /command..."
	ta.Focus()
	ta.SetHeight(3)
	ta.CharLimit = 4096
	ta.KeyMap.InsertNewline.SetEnabled(false)

	vp := viewport.New(80, 20)

	return Model{
		viewport: vp,
		textarea: ta,
		registry: NewRegistry(),
	}
}

// Init is the Bubble Tea initialization command.
func (m Model) Init() tea.Cmd {
	return textarea.Blink
}

// SetSize updates the model and its components to the given dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.viewport.Width = width
	m.viewport.Height = height - 5 // 3 textarea + 1 status + 1 padding
	if m.viewport.Height < 5 {
		m.viewport.Height = 5
	}
	m.textarea.SetWidth(width)
}

// AppendContent adds text to the viewport, preserving existing content.
func (m *Model) AppendContent(text string) {
	if m.viewportContent != "" {
		m.viewportContent += "\n"
	}
	m.viewportContent += text
	m.viewport.SetContent(m.composeViewportContent())
	m.viewport.GotoBottom()
}

// SetContent replaces the viewport content entirely.
func (m *Model) SetContent(text string) {
	m.viewportContent = text
	if m.streamRenderer != nil {
		m.streamRenderer.Reset()
	}
	m.viewport.SetContent(m.composeViewportContent())
	m.viewport.GotoBottom()
}

// SetStatusBar updates the status bar text.
func (m *Model) SetStatusBar(left, right string) {
	m.statusLeft = left
	m.statusRight = right
}

// SetRegistry assigns the slash-command registry.
func (m *Model) SetRegistry(r *Registry) {
	m.registry = r
}

// SetStreamRenderer assigns the stream renderer used for incremental output.
func (m *Model) SetStreamRenderer(r *StreamRenderer) {
	m.streamRenderer = r
}

// SetOnCancel assigns the cancellation callback.
func (m *Model) SetOnCancel(fn func()) {
	m.OnCancel = fn
}

// SetPipelineRunning updates the pipeline-running flag.
func (m *Model) SetPipelineRunning(running bool) {
	m.pipelineRunning = running
}

// CommitStream finalizes the current stream content into the permanent viewport
// buffer and resets the stream renderer.
func (m *Model) CommitStream() {
	if m.streamRenderer != nil && m.streamRenderer.Content() != "" {
		if m.viewportContent != "" {
			m.viewportContent += "\n"
		}
		m.viewportContent += m.streamRenderer.Content()
		m.streamRenderer.Reset()
	}
	m.viewport.SetContent(m.viewportContent)
	m.viewport.GotoBottom()
}

// composeViewportContent returns the full viewport text, combining the base
// content with any active stream renderer output.
func (m *Model) composeViewportContent() string {
	content := m.viewportContent
	if m.streamRenderer != nil && m.streamRenderer.Content() != "" {
		if content != "" {
			content += "\n"
		}
		content += m.streamRenderer.Content()
	}
	return content
}

// Update is the Bubble Tea update loop.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)

	case InputMsg:
		m.textarea.SetValue(string(msg))
		m.handleSubmit()

	case StreamTokenMsg:
		if m.streamRenderer != nil {
			m.streamRenderer.AppendToken(string(msg))
			m.viewport.SetContent(m.composeViewportContent())
			if m.streamRenderer.AutoScroll() {
				m.viewport.GotoBottom()
			}
		}

	case EOFMsg:
		if m.OnBeforeQuit != nil {
			allow, warning := m.OnBeforeQuit()
			if !allow {
				m.AppendContent(warning)
				return m, nil
			}
		}
		m.quitting = true
		return m, tea.Quit

	case tea.KeyMsg:
		handled := m.handleKey(msg)
		if handled && m.quitting {
			return m, tea.Quit
		}
		if handled {
			return m, tea.Batch(cmds...)
		}

		// Let textarea handle the key.
		var cmd tea.Cmd
		m.textarea, cmd = m.textarea.Update(msg)
		cmds = append(cmds, cmd)

		// Toggle palette mode based on current input.
		val := strings.TrimSpace(m.textarea.Value())
		if strings.HasPrefix(val, "/") && !strings.Contains(val, "\n") {
			m.paletteMode = true
			m.paletteIdx = 0
		} else {
			m.paletteMode = false
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) handleKey(msg tea.KeyMsg) bool {
	switch msg.String() {
	case "enter":
		m.handleSubmit()
		return true

	case "shift+enter", "alt+enter":
		m.textarea.InsertString("\n")
		m.paletteMode = false
		return true

	case "ctrl+c":
		if m.pipelineRunning && m.OnCancel != nil {
			m.OnCancel()
			return true
		}
		m.textarea.SetValue("")
		m.paletteMode = false
		return true

	case "ctrl+d":
		if m.OnBeforeQuit != nil {
			allow, warning := m.OnBeforeQuit()
			if !allow {
				m.AppendContent(warning)
				return true
			}
		}
		m.quitting = true
		return true

	case "esc":
		if m.paletteMode {
			m.paletteMode = false
			m.textarea.SetValue("")
			return true
		}
		if m.OnBeforeQuit != nil {
			allow, warning := m.OnBeforeQuit()
			if !allow {
				m.AppendContent(warning)
				return true
			}
		}
		m.quitting = true
		return true

	case "up":
		if m.paletteMode {
			if m.paletteIdx > 0 {
				m.paletteIdx--
			}
			return true
		}
		if len(m.history) > 0 {
			if m.historyIdx < 0 {
				m.historyIdx = len(m.history) - 1
			} else if m.historyIdx > 0 {
				m.historyIdx--
			}
			m.textarea.SetValue(m.history[m.historyIdx])
			return true
		}

	case "down":
		if m.paletteMode {
			filtered := m.filteredCommands()
			if m.paletteIdx < len(filtered)-1 {
				m.paletteIdx++
			}
			return true
		}
		if m.historyIdx >= 0 && m.historyIdx < len(m.history)-1 {
			m.historyIdx++
			m.textarea.SetValue(m.history[m.historyIdx])
			return true
		}
		if m.historyIdx >= len(m.history)-1 {
			m.historyIdx = -1
			m.textarea.SetValue("")
			return true
		}

	case "pgup":
		m.viewport.ScrollUp(3)
		if m.streamRenderer != nil {
			m.streamRenderer.SetAutoScroll(false)
		}
		return true

	case "pgdown":
		m.viewport.ScrollDown(3)
		if m.streamRenderer != nil {
			m.streamRenderer.SetAutoScroll(true)
			m.viewport.GotoBottom()
		}
		return true
	}

	return false
}

func (m *Model) handleSubmit() {
	input := strings.TrimSpace(m.textarea.Value())
	m.textarea.SetValue("")
	m.historyIdx = -1
	m.paletteMode = false

	if input == "" {
		return
	}

	// Add to history.
	m.history = append(m.history, input)

	// Show user message.
	m.AppendContent(UserMessageStyle.Render("> " + input))

	if strings.HasPrefix(input, "/") {
		cmd, parseErr := ParseSlashCommand(input)
		if parseErr != nil {
			if input == "/" {
				m.AppendContent(m.registry.Help())
				return
			}
			m.AppendContent(ErrorStyle.Render(fmt.Sprintf("Error: %v", parseErr)))
			return
		}
		result, execErr := m.registry.Execute(cmd.Name, cmd.Args)
		if execErr == ErrQuit {
			m.AppendContent(result)
			m.quitting = true
			return
		}
		if execErr != nil {
			m.AppendContent(ErrorStyle.Render(fmt.Sprintf("Error: %v", execErr)))
			return
		}
		m.AppendContent(result)
		return
	}

	if m.OnSubmit != nil {
		response, err := m.OnSubmit(input)
		if err != nil {
			m.AppendContent(ErrorStyle.Render(fmt.Sprintf("Error: %v", err)))
			return
		}
		if response != "" {
			m.AppendContent(response)
		}
	}
}

func (m Model) filteredCommands() []Command {
	filter := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(m.textarea.Value()), "/"))
	if m.registry == nil {
		return nil
	}
	all := m.registry.Commands()
	if filter == "" {
		return all
	}
	var filtered []Command
	for _, c := range all {
		if fuzzyMatch(filter, c.Name) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// View renders the chat TUI.
func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(m.viewport.View())
	sb.WriteString("\n")

	if m.paletteMode {
		sb.WriteString(m.renderPalette())
	}

	sb.WriteString(m.renderStatusBar())
	sb.WriteString("\n")

	sb.WriteString(m.textarea.View())
	return sb.String()
}

func (m Model) renderStatusBar() string {
	left := m.statusLeft
	right := m.statusRight
	if left == "" && right == "" {
		return ""
	}
	width := m.width
	if width <= 0 {
		width = 80
	}
	content := left
	if right != "" {
		padding := width - len(left) - len(right)
		if padding < 1 {
			padding = 1
		}
		content += strings.Repeat(" ", padding) + right
	}
	return StatusBarStyle.Render(content)
}

func (m Model) renderPalette() string {
	filtered := m.filteredCommands()
	if len(filtered) == 0 {
		return PaletteStyle.Render("  (no matching commands)\n")
	}

	var sb strings.Builder
	sb.WriteString(PaletteStyle.Render("Commands:\n"))
	for i, c := range filtered {
		prefix := "  "
		style := PaletteStyle
		if i == m.paletteIdx {
			prefix = "> "
			style = PaletteSelectedStyle
		}
		line := fmt.Sprintf("%s/%s %s — %s\n", prefix, c.Name, c.Args, c.Summary)
		sb.WriteString(style.Render(line))
	}
	return sb.String()
}
