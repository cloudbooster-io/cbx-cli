package audit

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	auditcore "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
)

// renderListBody returns the inner contents of the list panel, sized to
// fit within (width, height). Each finding renders as two lines: a title
// line with severity bar + chip + rule ID + title, then a dim resource·
// service sub-line.
func (m Model) renderListBody(width, height int) string {
	if len(m.filtered) == 0 {
		return emptyHintStyle.Render("No findings match the current filters. Press r to reset.")
	}
	vc := height / 2
	if vc < 1 {
		vc = 1
	}
	end := m.offset + vc
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	var sb strings.Builder
	for i := m.offset; i < end; i++ {
		idx := m.filtered[i]
		f := m.findings[idx]
		selected := i == m.cursor && m.focus == focusList
		sb.WriteString(renderListItem(f, selected, width))
		if i < end-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func renderListItem(f auditcore.Finding, selected bool, width int) string {
	bar := severityBar(f.Severity, selected)
	chip := severityChipShort(f.Severity)

	// Title line: "▎ CRIT  Title text…" — the rule ID lives in the
	// detail pane; in the list every column is for the title.
	titleRoom := width - lipgloss.Width(bar) - lipgloss.Width(chip) - 3
	if titleRoom < 8 {
		titleRoom = 8
	}
	title := truncate(f.Title, titleRoom)
	titleRendered := listItemTitle.Render(title)
	if selected {
		titleRendered = lipgloss.NewStyle().Foreground(colTextHi).Bold(true).Render(title)
	}
	titleLine := bar + " " + chip + "  " + titleRendered

	// Sub line: "    kind · name · region" parsed from the URN so we
	// drop the redundant `aws://region/AWS::Service::Type/` prefix.
	subRoom := width - 5
	if subRoom < 8 {
		subRoom = 8
	}
	subLine := "    " + listItemDim.Render(compactResource(f, subRoom))

	combined := titleLine + "\n" + subLine
	if selected {
		combined = listItemSelBG.Width(width).Render(combined)
	}
	return combined
}

// compactResource turns a raw URN into a short, scannable description
// for the list sub-line. Falls back to the raw resource string for any
// shape the URN parser doesn't recognise.
func compactResource(f auditcore.Finding, width int) string {
	p := output.ParseURN(f.Resource)
	if p.Service == "" && p.Kind == "" && p.Name == "" {
		return truncate(f.Resource, width)
	}
	bits := []string{}
	if p.Kind != "" {
		bits = append(bits, p.Kind)
	}
	if p.Name != "" {
		bits = append(bits, p.Name)
	}
	if p.Region != "" {
		bits = append(bits, p.Region)
	}
	return truncate(strings.Join(bits, " · "), width)
}

func truncate(s string, max int) string {
	if max <= 1 {
		return ""
	}
	if lipgloss.Width(s) <= max {
		return s
	}
	// Cheap rune-aware truncate with ellipsis.
	runes := []rune(s)
	if len(runes) <= max-1 {
		return s
	}
	return string(runes[:max-1]) + "…"
}
