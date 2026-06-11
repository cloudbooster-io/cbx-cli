package audit

import (
	"strings"

	"github.com/charmbracelet/lipgloss"

	auditcore "github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// renderListBody returns the inner contents of the list panel. Every
// finding renders as a single line with a right-aligned context column
// (`kind · short-name`) so duplicates with identical titles ("EBS
// volume not encrypted at rest" × N) are immediately distinguishable.
// Severity transitions get a thin divider so the user can scan tiers
// at a glance.
func (m Model) renderListBody(width, height int) string {
	if len(m.filtered) == 0 {
		return emptyHintStyle.Render("No findings match the current filters. Press r to reset.")
	}

	var sb strings.Builder
	used := 0
	prevSev := ""
	for i := m.offset; i < len(m.filtered); i++ {
		idx := m.filtered[i]
		f := m.findings[idx]
		selected := i == m.cursor && m.focus == focusList

		// Insert a section divider on severity change (skipped at the
		// very top of the visible window since the row itself already
		// carries the severity chip).
		if f.Severity != prevSev && used > 0 {
			divider := renderSeverityDivider(f.Severity, width)
			if used+1 > height {
				break
			}
			sb.WriteString("\n")
			sb.WriteString(divider)
			used++
		}
		prevSev = f.Severity

		item := renderListItem(f, selected, width)
		if used+1 > height {
			break
		}
		if used > 0 {
			sb.WriteString("\n")
		}
		sb.WriteString(item)
		used++
	}
	return sb.String()
}

func renderListItem(f auditcore.Finding, selected bool, width int) string {
	bar := severityBar(f.Severity, selected)
	chip := severityChipShort(f.Severity)

	// Reserve room for the right-aligned context column. Keep it to
	// ~30 chars so the title stays the dominant element. Drop the
	// column entirely on very narrow lists so the title isn't crushed.
	ctxMax := 30
	if width < 60 {
		ctxMax = 0
	} else if width < 90 {
		ctxMax = 22
	}
	ctxRendered := ""
	if ctxMax > 0 {
		ctxRendered = listItemDim.Render(compactResource(f, ctxMax))
	}

	// Title takes whatever's left after bar + chip + padding + ctx.
	prefix := bar + " " + chip + "  "
	titleRoom := width - lipgloss.Width(prefix) - lipgloss.Width(ctxRendered) - 2
	if titleRoom < 12 {
		titleRoom = 12
	}
	title := truncate(f.Title, titleRoom)
	titleStyled := listItemTitle.Render(title)
	if selected {
		titleStyled = lipgloss.NewStyle().Foreground(colTextHi).Bold(true).Render(title)
	}

	// Pad between the title and the right-aligned context column.
	mid := width - lipgloss.Width(prefix) - lipgloss.Width(titleStyled) - lipgloss.Width(ctxRendered)
	if mid < 1 {
		mid = 1
	}
	row := prefix + titleStyled + strings.Repeat(" ", mid) + ctxRendered

	if selected {
		row = listItemSelBG.Width(width).Render(row)
	}
	return row
}

// renderSeverityDivider produces a thin tier-label line shown when the
// list crosses from one severity to the next. The label uses the
// severity colour at low intensity so the divider reads as structure,
// not as another finding.
func renderSeverityDivider(sev string, width int) string {
	label := strings.ToUpper(sev)
	if label == "" {
		return ""
	}
	c := severityColor(sev)
	lbl := lipgloss.NewStyle().Foreground(c).Bold(true).Render(" " + label + " ")
	dashRoom := width - lipgloss.Width(lbl) - 2
	if dashRoom < 0 {
		dashRoom = 0
	}
	dash := lipgloss.NewStyle().Foreground(colDim).Render(strings.Repeat("─", dashRoom))
	return lbl + " " + dash
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
