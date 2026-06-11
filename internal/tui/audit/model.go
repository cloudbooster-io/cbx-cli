package audit

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	auditcore "github.com/cloudbooster-io/cbx-cli/internal/audit"
)

// focusedPane controls which pane receives navigation keys when both
// panes are visible. In narrow mode only one pane is shown.
type focusedPane int

const (
	focusList focusedPane = iota
	focusDetail
)

// viewMode tracks the current top-level screen. In wide mode we stay
// in listMode and toggle pane focus; in narrow mode `enter` flips to
// detailMode so the user can read the full finding without splitting
// 80 cols across two panels.
type viewMode int

const (
	listMode viewMode = iota
	detailMode
	helpMode
	openMode
)

// Model is the Bubble Tea model for the interactive audit TUI.
type Model struct {
	// Immutable inputs
	findings       []auditcore.Finding
	contextLine    string
	reportPath     string // markdown report (.md)
	htmlReportPath string // browser report (.html), optional

	// Derived view state
	filtered []int
	cursor   int
	offset   int

	// Layout
	width     int
	height    int
	wideMode  bool
	listWidth int

	// Components
	keymap     KeyMap
	filter     FilterState
	searchMode bool
	searchIn   textinput.Model
	detail     viewport.Model
	focus      focusedPane
	mode       viewMode

	// Transient UI
	flash    string // toast message (e.g. "rule copied")
	flashTTL int    // remaining frames before flash clears

	quitting bool
}

// NewModel creates a new audit TUI model with the given findings.
// Findings are sorted by severity before display.
func NewModel(findings []auditcore.Finding) Model {
	// Copy so we don't mutate the caller's slice ordering when callers
	// reuse findings for other output.
	cp := make([]auditcore.Finding, len(findings))
	copy(cp, findings)
	SortFindings(cp)

	ti := textinput.New()
	ti.Prompt = ""
	ti.Placeholder = "type to filter findings"
	ti.CharLimit = 80

	vp := viewport.New(0, 0)

	m := Model{
		findings: cp,
		filtered: make([]int, len(cp)),
		keymap:   DefaultKeyMap(),
		searchIn: ti,
		detail:   vp,
	}
	for i := range cp {
		m.filtered[i] = i
	}
	return m
}

// WithContext sets the header line (e.g. "AWS · 123456789012 · eu-central-1").
func (m Model) WithContext(line string) Model {
	m.contextLine = line
	return m
}

// WithReportPath sets the markdown report path opened by the `o` key.
func (m Model) WithReportPath(p string) Model {
	m.reportPath = p
	return m
}

// WithHTMLReportPath sets the optional HTML report path. When both
// paths are present, `o` opens a small modal that lets the user pick
// markdown or browser.
func (m Model) WithHTMLReportPath(p string) Model {
	m.htmlReportPath = p
	return m
}

// Init is the Bubble Tea initialization command.
func (m Model) Init() tea.Cmd {
	return nil
}

// SetSize updates the model dimensions and reflows panes.
func (m *Model) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.wideMode = width >= 110

	if m.wideMode {
		// Split 45 / 55 favouring the detail pane — the list compresses
		// gracefully while the detail body benefits from extra width.
		m.listWidth = width * 45 / 100
		if m.listWidth < 36 {
			m.listWidth = 36
		}
	} else {
		m.listWidth = width
	}

	mainH := m.mainHeight()
	var detailContentW int
	switch {
	case m.mode == detailMode:
		// Narrow-screen drilldown takes the full width.
		detailContentW = width - 4 // panel border + a little margin
	case m.wideMode:
		detailContentW = width - m.listWidth - 5 // panel borders + spacer
	default:
		detailContentW = width - 4
	}
	if detailContentW < 20 {
		detailContentW = 20
	}
	m.detail.Width = detailContentW
	m.detail.Height = mainH - 2 // border lines
	m.refreshDetail()
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
	if m.flashTTL > 0 {
		m.flashTTL--
		if m.flashTTL == 0 {
			m.flash = ""
		}
	}

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
	// Search input owns the keyboard while open.
	if m.searchMode {
		return m.handleSearchKey(msg)
	}

	// Ctrl+C always exits, regardless of mode.
	if msg.Type == tea.KeyCtrlC {
		m.quitting = true
		return m, tea.Quit
	}

	// Open-report modal: only m / b / esc / q matter.
	if m.mode == openMode {
		switch {
		case key.Matches(msg, m.keymap.Quit):
			m.quitting = true
			return m, tea.Quit
		case key.Matches(msg, m.keymap.Back):
			m.mode = listMode
			return m, nil
		case msg.Type == tea.KeyRunes && len(msg.Runes) == 1 && msg.Runes[0] == 'm':
			m.openReport(m.reportPath, "markdown")
			m.mode = listMode
			return m, nil
		case msg.Type == tea.KeyRunes && len(msg.Runes) == 1 && msg.Runes[0] == 'b':
			m.openReport(m.htmlReportPath, "browser")
			m.mode = listMode
			return m, nil
		}
		return m, nil
	}

	// Help overlay: any key dismisses, except help-toggle itself.
	if m.mode == helpMode {
		if key.Matches(msg, m.keymap.Help) {
			m.mode = listMode
			return m, nil
		}
		// `q` and `ctrl+c` still quit from help.
		if key.Matches(msg, m.keymap.Quit) {
			m.quitting = true
			return m, tea.Quit
		}
		// Anything else closes help.
		m.mode = listMode
		return m, nil
	}

	// Help-toggle works from list and detail modes.
	if key.Matches(msg, m.keymap.Help) {
		m.mode = helpMode
		return m, nil
	}

	// Detail mode (narrow-screen drilldown): a focused, fullscreen
	// view of one finding with scrolling.
	if m.mode == detailMode {
		switch {
		case key.Matches(msg, m.keymap.Back):
			m.mode = listMode
			m.SetSize(m.width, m.height) // resize detail back to pane width
			return m, nil
		case key.Matches(msg, m.keymap.Quit):
			m.quitting = true
			return m, tea.Quit
		case key.Matches(msg, m.keymap.Up):
			m.detail.ScrollUp(1)
		case key.Matches(msg, m.keymap.Down):
			m.detail.ScrollDown(1)
		case key.Matches(msg, m.keymap.PageUp):
			m.detail.PageUp()
		case key.Matches(msg, m.keymap.PageDown):
			m.detail.PageDown()
		case key.Matches(msg, m.keymap.Open):
			if m.reportPath != "" {
				if err := openInOS(m.reportPath); err == nil {
					m.setFlash("opened " + m.reportPath)
				} else {
					m.setFlash("could not open report")
				}
			}
		}
		return m, nil
	}

	// List mode dispatches.
	switch {
	case key.Matches(msg, m.keymap.Quit):
		m.quitting = true
		return m, tea.Quit

	case key.Matches(msg, m.keymap.Enter):
		// In wide mode the detail pane is already visible; enter just
		// focuses it for scrolling. In narrow mode it pops a fullscreen
		// detail view so the user can actually read the body.
		if m.SelectedFinding() == nil {
			return m, nil
		}
		if m.wideMode {
			m.focus = focusDetail
		} else {
			m.mode = detailMode
			m.SetSize(m.width, m.height) // expand detail to full width
		}
		return m, nil

	case key.Matches(msg, m.keymap.Back):
		if m.wideMode && m.focus == focusDetail {
			m.focus = focusList
			return m, nil
		}
		m.quitting = true
		return m, tea.Quit

	case key.Matches(msg, m.keymap.Tab):
		if m.wideMode {
			if m.focus == focusList {
				m.focus = focusDetail
			} else {
				m.focus = focusList
			}
		}
		return m, nil

	case key.Matches(msg, m.keymap.Up):
		if m.focus == focusDetail && m.wideMode {
			m.detail.ScrollUp(1)
		} else {
			m.moveCursor(-1)
		}
		return m, nil

	case key.Matches(msg, m.keymap.Down):
		if m.focus == focusDetail && m.wideMode {
			m.detail.ScrollDown(1)
		} else {
			m.moveCursor(1)
		}
		return m, nil

	case key.Matches(msg, m.keymap.PageUp):
		if m.focus == focusDetail && m.wideMode {
			m.detail.PageUp()
		} else {
			m.moveCursor(-m.visibleCount())
		}
		return m, nil

	case key.Matches(msg, m.keymap.PageDown):
		if m.focus == focusDetail && m.wideMode {
			m.detail.PageDown()
		} else {
			m.moveCursor(m.visibleCount())
		}
		return m, nil

	case key.Matches(msg, m.keymap.Top):
		m.cursor = 0
		m.offset = 0
		m.refreshDetail()
		return m, nil

	case key.Matches(msg, m.keymap.Bottom):
		m.cursor = len(m.filtered) - 1
		if m.cursor < 0 {
			m.cursor = 0
		}
		m.ensureCursorVisible()
		m.refreshDetail()
		return m, nil

	case key.Matches(msg, m.keymap.Filter):
		m.searchMode = true
		m.searchIn.SetValue(m.filter.Search)
		m.searchIn.Focus()
		return m, textinput.Blink

	case key.Matches(msg, m.keymap.CycleSev):
		m.cycleSeverityFilter()
		return m, nil

	case key.Matches(msg, m.keymap.CycleSvc):
		m.cycleServiceFilter()
		return m, nil

	case key.Matches(msg, m.keymap.Reset):
		m.filter = FilterState{}
		m.searchIn.SetValue("")
		m.applyFilter()
		return m, nil

	case key.Matches(msg, m.keymap.Open):
		m = m.handleOpenKey()
		return m, nil
	}

	return m, nil
}

func (m Model) handleSearchKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.filter.Search = m.searchIn.Value()
		m.applyFilter()
		m.searchMode = false
		m.searchIn.Blur()
		return m, nil
	case tea.KeyEsc:
		m.searchMode = false
		m.searchIn.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.searchIn, cmd = m.searchIn.Update(msg)
	// Live-filter as the user types so the list narrows on every keystroke.
	m.filter.Search = m.searchIn.Value()
	m.applyFilter()
	return m, cmd
}

// ---- selection / scrolling helpers ----

func (m *Model) moveCursor(delta int) {
	m.cursor += delta
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.ensureCursorVisible()
	m.refreshDetail()
}

func (m *Model) visibleCount() int {
	// Every row is one line; severity dividers add a handful of extras
	// across the pane. Approximate (-3) is fine for PageUp/PageDown
	// arithmetic — the renderer clips anyway.
	mainH := m.mainHeight() - 2 // panel borders
	if mainH < 4 {
		return 1
	}
	return mainH - 3
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

func (m *Model) refreshDetail() {
	body := renderDetailBody(m.SelectedFinding(), m.detail.Width)
	m.detail.SetContent(body)
	m.detail.GotoTop()
}

func (m *Model) setFlash(s string) {
	m.flash = s
	m.flashTTL = 12 // ~clear after a handful of key presses
}

// handleOpenKey decides what happens when `o` is pressed. When both
// the markdown and the HTML reports exist, pop a small modal so the
// user can pick. When only one is available, open it directly without
// the extra keystroke.
func (m Model) handleOpenKey() Model {
	hasMD := m.reportPath != ""
	hasHTML := m.htmlReportPath != ""
	switch {
	case hasMD && hasHTML:
		m.mode = openMode
	case hasMD:
		m.openReport(m.reportPath, "markdown")
	case hasHTML:
		m.openReport(m.htmlReportPath, "browser")
	default:
		m.setFlash("no saved report to open")
	}
	return m
}

// openReport hands a path off to the OS opener and flashes the user
// either way so the action feels responded-to even when the launched
// app takes a beat.
func (m *Model) openReport(path, label string) {
	if path == "" {
		m.setFlash("no " + label + " report to open")
		return
	}
	if err := openInOS(path); err == nil {
		m.setFlash("opened " + label + " · " + path)
	} else {
		m.setFlash("could not open " + label + ": " + err.Error())
	}
}

// ---- filter wiring ----

func (m *Model) cycleSeverityFilter() {
	order := []string{"", auditcore.SeverityCritical, auditcore.SeverityHigh, auditcore.SeverityWarning, auditcore.SeverityInfo}
	idx := 0
	for i, s := range order {
		if s == m.filter.Severity {
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
		m.filter.Service = services[0]
	} else {
		next := idx + 1
		if next >= len(services) {
			m.filter.Service = ""
		} else {
			m.filter.Service = services[next]
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
	m.refreshDetail()
}

// ---- view ----

// View renders the TUI.
func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if m.width == 0 || m.height == 0 {
		return ""
	}
	header := m.renderHeader()
	var main string
	switch m.mode {
	case helpMode:
		main = m.renderHelpOverlay()
	case openMode:
		main = m.renderOpenModal()
	case detailMode:
		main = m.renderDetailFullscreen()
	default:
		main = m.renderMain()
	}
	footer := m.renderFooter()
	return lipgloss.JoinVertical(lipgloss.Left, header, main, footer)
}

// renderDetailFullscreen draws the selected finding's detail viewport
// taking the full main area, used in narrow-screen drilldown.
func (m Model) renderDetailFullscreen() string {
	w := m.width - 2
	h := m.mainHeight() - 2
	if w < 20 {
		w = 20
	}
	style := panelBorder.Width(w).Height(h).BorderForeground(colAccent)
	if m.SelectedFinding() == nil {
		return style.Render(emptyHintStyle.Render("no finding selected"))
	}
	return style.Render(m.detail.View())
}

// renderHelpOverlay draws a centered help box listing every binding.
func (m Model) renderHelpOverlay() string {
	rows := []struct{ k, d string }{
		{"↑/↓ · j/k", "move selection"},
		{"g · G", "jump to top / bottom"},
		{"pgup · pgdn", "page in the focused pane"},
		{"tab", "toggle list / detail focus (wide mode)"},
		{"enter", "drill into the selected finding"},
		{"esc", "back from detail to list (then quit)"},
		{"/", "live-filter findings as you type"},
		{"s", "cycle severity filter"},
		{"v", "cycle service filter"},
		{"r", "reset all filters"},
		{"o", "open the saved report.md in your OS"},
		{"?", "toggle this help"},
		{"q · ctrl+c", "quit"},
	}
	var sb strings.Builder
	sb.WriteString(detailHeading.Render("Keyboard"))
	sb.WriteString("\n\n")
	for _, r := range rows {
		k := footerKeyStyle.Render(padRightVisual(r.k, 14))
		d := detailBody.Render(r.d)
		sb.WriteString(k + "  " + d + "\n")
	}
	body := sb.String()
	w := minInt(72, m.width-4)
	h := m.mainHeight() - 2
	if h < 4 {
		h = 4
	}
	box := panelBorder.
		Width(w).
		Height(h).
		BorderForeground(colAccent).
		Padding(1, 2).
		Render(body)
	return lipgloss.Place(m.width, m.mainHeight(), lipgloss.Center, lipgloss.Center, box)
}

// renderOpenModal draws the centered "open as…" picker shown when both
// the markdown and HTML reports exist for an audit.
func (m Model) renderOpenModal() string {
	var sb strings.Builder
	sb.WriteString(detailHeading.Render("Open audit report"))
	sb.WriteString("\n\n")

	option := func(k, label, path string) string {
		keyChip := footerKeyStyle.Render("  " + k + "  ")
		ln := keyChip + "  " + detailBody.Render(label)
		if path != "" {
			ln += "\n" + strings.Repeat(" ", 9) + footerStyle.Render(path)
		}
		return ln
	}
	sb.WriteString(option("m", "Markdown (.md)", m.reportPath))
	sb.WriteString("\n\n")
	sb.WriteString(option("b", "Browser (.html)", m.htmlReportPath))
	sb.WriteString("\n\n")
	sb.WriteString(footerStyle.Render("esc cancel"))

	w := minInt(78, m.width-4)
	box := panelBorder.
		Width(w).
		BorderForeground(colAccent).
		Padding(1, 2).
		Render(sb.String())
	return lipgloss.Place(m.width, m.mainHeight(), lipgloss.Center, lipgloss.Center, box)
}

// padRightVisual right-pads s to n display columns, counting runes via
// lipgloss.Width so multi-byte UTF-8 (↑ ↓ →) doesn't break alignment.
func padRightVisual(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m Model) renderHeader() string {
	title := titleStyle.Render("CloudBooster Audit")
	ctx := subtitleStyle.Render(m.contextLine)
	chips := m.renderSeverityChips()

	left := title
	if m.contextLine != "" {
		left = title + "  " + ctx
	}
	rule := headerRule.Render(strings.Repeat("─", m.width))

	// If everything fits on one line, render it as title + spacer + chips.
	if lipgloss.Width(left)+lipgloss.Width(chips)+2 <= m.width {
		pad := m.width - lipgloss.Width(left) - lipgloss.Width(chips)
		if pad < 1 {
			pad = 1
		}
		return left + strings.Repeat(" ", pad) + chips + "\n" + rule
	}

	// Doesn't fit. Drop the context line on narrow terminals — the
	// account ID was already printed in the static discovery card just
	// above. Try title + chips with a single space of padding; if that
	// still overflows, fall back to chips on their own row.
	if lipgloss.Width(title)+lipgloss.Width(chips)+1 <= m.width {
		pad := m.width - lipgloss.Width(title) - lipgloss.Width(chips)
		if pad < 1 {
			pad = 1
		}
		return title + strings.Repeat(" ", pad) + chips + "\n" + rule
	}
	// Last resort: stack title above chips on two header lines.
	return title + "\n" + chips + "\n" + rule
}

func (m Model) renderSeverityChips() string {
	counts := severityCounts(m.findings)
	parts := []string{}
	for _, sev := range []string{auditcore.SeverityCritical, auditcore.SeverityHigh, auditcore.SeverityWarning, auditcore.SeverityInfo} {
		n := counts[sev]
		if n == 0 {
			continue
		}
		c := severityColor(sev)
		num := lipgloss.NewStyle().Foreground(c).Bold(true).Render(fmt.Sprintf("%d", n))
		label := lipgloss.NewStyle().Foreground(colMuted).Render(strings.ToLower(sev))
		parts = append(parts, num+" "+label)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, footerStyle.Render("  ·  "))
}

func (m Model) mainHeight() int {
	// 2 lines header + 2 lines footer (counts/keys + search line when active)
	h := m.height - 4
	if h < 4 {
		h = 4
	}
	return h
}

func (m Model) renderMain() string {
	listView := m.renderListPanel()
	if !m.wideMode {
		return listView
	}
	detailView := m.renderDetailPanel()
	return lipgloss.JoinHorizontal(lipgloss.Top, listView, " ", detailView)
}

func (m Model) renderListPanel() string {
	w := m.listWidth
	if !m.wideMode {
		w = m.width
	}
	h := m.mainHeight()
	body := m.renderListBody(w-2, h-2)
	style := panelBorder.Width(w - 2).Height(h - 2)
	if m.focus == focusList && m.wideMode {
		style = style.BorderForeground(colAccent)
	}
	return style.Render(body)
}

func (m Model) renderDetailPanel() string {
	w := m.width - m.listWidth - 3
	if w < 20 {
		w = 20
	}
	h := m.mainHeight()
	style := panelBorder.Width(w).Height(h - 2)
	if m.focus == focusDetail {
		style = style.BorderForeground(colAccent)
	}
	if m.SelectedFinding() == nil {
		return style.Render(emptyHintStyle.Render("no finding selected"))
	}
	return style.Render(m.detail.View())
}

func (m Model) renderFooter() string {
	keymap := m.renderKeymap()
	left := m.renderFilterState()
	if m.flash != "" {
		left = flashStyle.Render(m.flash) + "  " + left
	}
	pad := m.width - lipgloss.Width(left) - lipgloss.Width(keymap)
	if pad < 1 {
		pad = 1
	}
	statusLine := left + strings.Repeat(" ", pad) + keymap

	// Second line: search prompt when active, otherwise empty.
	var second string
	if m.searchMode {
		second = searchPromptSty.Render("/") + " " + m.searchIn.View() + footerStyle.Render("    enter apply · esc cancel")
	}
	if second == "" {
		return statusLine
	}
	return statusLine + "\n" + second
}

func (m Model) renderFilterState() string {
	total := len(m.findings)
	shown := len(m.filtered)
	base := fmt.Sprintf("%d/%d findings", shown, total)
	parts := []string{base}
	if m.filter.Severity != "" {
		parts = append(parts, "sev="+m.filter.Severity)
	}
	if m.filter.Service != "" {
		parts = append(parts, "svc="+m.filter.Service)
	}
	if m.filter.Search != "" {
		parts = append(parts, "q="+m.filter.Search)
	}
	return footerStyle.Render(strings.Join(parts, "  ·  "))
}

func (m Model) renderKeymap() string {
	binds := []key.Binding{
		m.keymap.Up,
		m.keymap.Filter,
		m.keymap.CycleSev,
		m.keymap.CycleSvc,
		m.keymap.Reset,
	}
	if m.reportPath != "" {
		binds = append(binds, m.keymap.Open)
	}
	if m.wideMode {
		binds = append(binds, m.keymap.Tab)
	}
	binds = append(binds, m.keymap.Quit)

	parts := make([]string, 0, len(binds))
	for _, b := range binds {
		k, hlp := b.Help().Key, b.Help().Desc
		parts = append(parts, footerKeyStyle.Render(k)+" "+footerStyle.Render(hlp))
	}
	return strings.Join(parts, footerStyle.Render("  "))
}

// ---- platform shims ----

func openInOS(path string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "linux":
		cmd = exec.Command("xdg-open", path)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", path)
	default:
		return fmt.Errorf("open not supported on %s", runtime.GOOS)
	}
	return cmd.Start()
}

// severityCounts tallies findings per severity for the header chips.
func severityCounts(findings []auditcore.Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[f.Severity]++
	}
	return out
}
