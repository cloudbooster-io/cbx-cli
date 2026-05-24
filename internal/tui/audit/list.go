package audit

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	auditcore "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
)

// renderListBody returns the inner contents of the list panel, sized
// to fit within (width, height). Unselected rows render as a single
// title line so the user can scan twice as many findings at once; the
// selected row expands to show the resource sub-line in place. The
// full finding (description, remediation, citations) is always one
// drilldown away in the detail pane.
func (m Model) renderListBody(width, height int) string {
	if len(m.filtered) == 0 {
		return emptyHintStyle.Render("No findings match the current filters. Press r to reset.")
	}

	var sb strings.Builder
	used := 0
	for i := m.offset; i < len(m.filtered); i++ {
		idx := m.filtered[i]
		f := m.findings[idx]
		selected := i == m.cursor && m.focus == focusList
		item := renderListItem(f, selected, width)
		rows := strings.Count(item, "\n") + 1
		if used+rows > height {
			break
		}
		if used > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(item)
		used += rows
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

	if !selected {
		return titleLine
	}

	// Selected only: append the resource sub-line and paint the whole
	// row with the selection background.
	subRoom := width - 5
	if subRoom < 8 {
		subRoom = 8
	}
	subLine := "    " + listItemDim.Render(compactResource(f, subRoom))
	return listItemSelBG.Width(width).Render(titleLine + "\n" + subLine)
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
