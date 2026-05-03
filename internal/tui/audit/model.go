package audit

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	auditcore "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
)

type viewMode int

const (
	listMode viewMode = iota
	detailMode
)

// Model is the Bubble Tea model for the interactive audit TUI.
type Model struct {
	findings []auditcore.Finding
	filtered []int
	cursor   int
	offset   int
	mode     viewMode
	filter   FilterState
	keymap   KeyMap

	// Search mode
	searchMode   bool
	searchBuffer string

	width  int
	height int

	quitting bool
}

// NewModel creates a new audit TUI model with the given findings.
// Findings are sorted by severity before display.
func NewModel(findings []auditcore.Finding) Model {
	SortFindings(findings)
	m := Model{
		findings: findings,
		filtered: make([]int, len(findings)),
		keymap:   DefaultKeyMap(),
		mode:     listMode,
	}
	for i := range findings {
		m.filtered[i] = i
	}
	return m
}

// Init is the Bubble Tea initialization command.
func (m Model) Init() tea.Cmd {
	return nil
}

// SetSize updates the model dimensions.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// SelectedFinding returns the currently selected finding, or nil.
func (m *Model) SelectedFinding() *auditcore.Finding {
	if m.cursor < 0 || m.cursor >= len(m.filtered) {
		return nil
	}
	idx := m.filtered[m.cursor]
	if idx < 0 || idx >= len(m.findings) {
		return nil
	}
	f := m.findings[idx]
	return &f
}

// Update is the Bubble Tea update loop.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.SetSize(msg.Width, msg.Height)
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Global quit
	if key.Matches(msg, m.keymap.Quit) {
		m.quitting = true
		return m, tea.Quit
	}

	switch m.mode {
	case detailMode:
		return m.handleDetailKey(msg)
	case listMode:
		return m.handleListKey(msg)
	}

	return m, nil
}

func (m Model) handleDetailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keymap.Back):
		m.mode = listMode
		return m, nil
	case key.Matches(msg, m.keymap.Up), key.Matches(msg, m.keymap.PageUp):
		if m.offset > 0 {
			m.offset--
		}
		return m, nil
	case key.Matches(msg, m.keymap.Down), key.Matches(msg, m.keymap.PageDown):
		m.offset++
		return m, nil
	}
	return m, nil
}

func (m Model) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.searchMode {
		return m.handleSearchKey(msg)
	}

	switch {
	case key.Matches(msg, m.keymap.Enter):
		if len(m.filtered) > 0 {
			m.mode = detailMode
			m.offset = 0
		}
		return m, nil

	case key.Matches(msg, m.keymap.Back):
		m.quitting = true
		return m, tea.Quit

	case key.Matches(msg, m.keymap.Up):
		if m.cursor > 0 {
			m.cursor--
			m.ensureCursorVisible()
		}
		return m, nil

	case key.Matches(msg, m.keymap.Down):
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
			m.ensureCursorVisible()
		}
		return m, nil

	case key.Matches(msg, m.keymap.PageUp):
		m.cursor -= m.visibleCount()
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.ensureCursorVisible()
		return m, nil

	case key.Matches(msg, m.keymap.PageDown):
		m.cursor += m.visibleCount()
		if m.cursor >= len(m.filtered) {
			m.cursor = len(m.filtered) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.ensureCursorVisible()
		return m, nil

	case key.Matches(msg, m.keymap.Filter):
		m.searchMode = true
		m.searchBuffer = ""
		return m, nil

	case key.Matches(msg, m.keymap.CycleSev):
		m.cycleSeverityFilter()
		return m, nil

	case key.Matches(msg, m.keymap.CycleSvc):
		m.cycleServiceFilter()
		return m, nil

	case key.Matches(msg, m.keymap.Reset):
		m.filter = FilterState{}
		m.applyFilter()
		return m, nil
	}

	return m, nil
}

func (m Model) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filter.Search = m.searchBuffer
		m.applyFilter()
		m.searchMode = false
		return m, nil
	case tea.KeyEsc:
		m.searchMode = false
		m.searchBuffer = ""
		return m, nil
	case tea.KeyBackspace:
		if len(m.searchBuffer) > 0 {
			m.searchBuffer = m.searchBuffer[:len(m.searchBuffer)-1]
		}
		return m, nil
	}

	// Append runes to search buffer
	if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
		m.searchBuffer += string(msg.Runes)
	}

	return m, nil
}

func (m *Model) visibleCount() int {
	// Header = 1 line, footer = 1 line, each item = 2 lines
	available := m.height - 2
	if available < 2 {
		return 1
	}
	return available / 2
}

func (m *Model) ensureCursorVisible() {
	vc := m.visibleCount()
	if m.cursor < m.offset {
		m.offset = m.cursor
	} else if m.cursor >= m.offset+vc {
		m.offset = m.cursor - vc + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m *Model) cycleSeverityFilter() {
	order := []string{"", auditcore.SeverityCritical, auditcore.SeverityHigh, auditcore.SeverityWarning, auditcore.SeverityInfo}
	current := m.filter.Severity
	idx := 0
	for i, s := range order {
		if s == current {
			idx = i
			break
		}
	}
	m.filter.Severity = order[(idx+1)%len(order)]
	m.applyFilter()
}

func (m *Model) cycleServiceFilter() {
	services := UniqueServices(m.findings)
	if len(services) == 0 {
		m.filter.Service = ""
		m.applyFilter()
		return
	}
	current := m.filter.Service
	idx := -1
	for i, s := range services {
		if s == current {
			idx = i
			break
		}
	}
	if idx < 0 {
		// currently no service filter; set to first
		m.filter.Service = services[0]
	} else {
		// cycle to next, or back to "" if at last
		nextIdx := idx + 1
		if nextIdx >= len(services) {
			m.filter.Service = ""
		} else {
			m.filter.Service = services[nextIdx]
		}
	}
	m.applyFilter()
}

func (m *Model) applyFilter() {
	m.filtered = ApplyFilters(m.findings, m.filter)
	if m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.offset = 0
}

// View renders the TUI.
func (m Model) View() string {
	if m.quitting {
		return ""
	}
	switch m.mode {
	case detailMode:
		return m.viewDetail()
	default:
		return m.viewList()
	}
}

func (m Model) viewList() string {
	var sb strings.Builder

	// Header
	sb.WriteString(m.renderHeader())
	sb.WriteString("\n")

	// List content
	if len(m.filtered) == 0 {
		sb.WriteString("No findings match the current filters.\n")
	} else {
		sb.WriteString(m.renderListContent())
	}

	// Footer
	sb.WriteString(m.renderFooter())

	return sb.String()
}

func (m Model) renderHeader() string {
	title := HeaderStyle.Render("CloudBooster Audit — Interactive")
	count := fmt.Sprintf("%d/%d findings", len(m.filtered), len(m.findings))
	if m.searchMode {
		count = "search: " + m.searchBuffer + "_"
	} else if !m.filter.IsZero() {
		parts := []string{}
		if m.filter.Severity != "" {
			parts = append(parts, "sev="+m.filter.Severity)
		}
		if m.filter.Service != "" {
			parts = append(parts, "svc="+m.filter.Service)
		}
		if m.filter.Search != "" {
			parts = append(parts, "q="+m.filter.Search)
		}
		count += " [" + strings.Join(parts, " ") + "]"
	}
	padding := m.width - lipgloss.Width(title) - len(count)
	if padding < 1 {
		padding = 1
	}
	return title + strings.Repeat(" ", padding) + count
}

func (m Model) renderListContent() string {
	var sb strings.Builder
	vc := m.visibleCount()
	end := m.offset + vc
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	for i := m.offset; i < end; i++ {
		idx := m.filtered[i]
		f := m.findings[idx]
		sb.WriteString(m.renderFindingLine(i, f))
		if i < end-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func (m Model) renderFindingLine(idx int, f auditcore.Finding) string {
	badge := SeverityBadge(f.Severity)
	line := fmt.Sprintf("%s %s — %s", badge, f.RuleID, f.Title)
	dim := fmt.Sprintf("   %s (%s)", f.Resource, f.Service)
	if idx == m.cursor {
		line = SelectedStyle.Render("▸ " + line)
		dim = SelectedStyle.Render("  " + dim)
	} else {
		line = "  " + line
	}
	return line + "\n" + dim
}

func (m Model) renderFooter() string {
	if m.searchMode {
		help := "enter apply • esc cancel"
		return HelpStyle.Render(help)
	}
	help := "↑/↓ navigate • enter drilldown • s severity • v service • / search • r reset • q quit"
	if m.width > 0 && len(help) > m.width {
		help = help[:m.width]
	}
	return HelpStyle.Render(help)
}

func (m Model) viewDetail() string {
	f := m.SelectedFinding()
	if f == nil {
		return ""
	}

	var lines []string
	lines = append(lines, HeaderStyle.Render("Finding Detail"))
	lines = append(lines, "")

	lines = append(lines, DetailLabelStyle.Render("Rule: ")+f.RuleID)
	lines = append(lines, "")
	lines = append(lines, DetailLabelStyle.Render("Title: ")+f.Title)
	lines = append(lines, "")
	lines = append(lines, DetailLabelStyle.Render("Severity: ")+SeverityStyle(f.Severity).Render(f.Severity))
	lines = append(lines, "")
	lines = append(lines, DetailLabelStyle.Render("Resource: ")+f.Resource)
	lines = append(lines, "")
	lines = append(lines, DetailLabelStyle.Render("Service: ")+f.Service)
	lines = append(lines, "")
	lines = append(lines, DetailLabelStyle.Render("Description:"))
	lines = append(lines, wrapText(f.Description, m.width))
	lines = append(lines, "")
	lines = append(lines, DetailLabelStyle.Render("Remediation:"))
	lines = append(lines, wrapText(f.Remediation, m.width))
	if f.File != "" {
		lines = append(lines, "")
		lines = append(lines, DetailLabelStyle.Render("File: ")+fmt.Sprintf("%s:%d", f.File, f.Line))
	}
	lines = append(lines, "")
	lines = append(lines, HelpStyle.Render("esc/q back to list • ↑/↓ scroll"))

	// Apply offset for scrolling in detail view
	content := strings.Join(lines, "\n")
	if m.offset > 0 {
		allLines := strings.Split(content, "\n")
		if m.offset < len(allLines) {
			content = strings.Join(allLines[m.offset:], "\n")
		}
	}

	return content
}

func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}
	var sb strings.Builder
	words := strings.Fields(text)
	lineLen := 0
	for _, word := range words {
		wlen := len(word)
		if lineLen > 0 && lineLen+1+wlen > width {
			sb.WriteString("\n")
			lineLen = 0
		}
		if lineLen > 0 {
			sb.WriteString(" ")
			lineLen++
		}
		sb.WriteString(word)
		lineLen += wlen
	}
	return sb.String()
}
