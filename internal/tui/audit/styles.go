package audit

import (
	"github.com/charmbracelet/lipgloss"

	auditcore "github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// Severity palette mirrors internal/output/chip.go so the TUI and the
// static printed report read like the same product.
var (
	colCritical = lipgloss.Color("124") // deep red
	colHigh     = lipgloss.Color("166") // burnt orange
	colWarning  = lipgloss.Color("220") // yellow
	colInfo     = lipgloss.Color("39")  // bright blue
	colAccent   = lipgloss.Color("86")  // teal — chrome accent
	colMuted    = lipgloss.Color("245")
	colSubtle   = lipgloss.Color("240")
	colDim      = lipgloss.Color("239")
	colTextHi   = lipgloss.Color("231")
	colTextLo   = lipgloss.Color("250")
	colSelBG    = lipgloss.Color("236")
)

var (
	titleStyle      = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	subtitleStyle   = lipgloss.NewStyle().Foreground(colMuted)
	headerRule      = lipgloss.NewStyle().Foreground(colDim)
	listItemTitle   = lipgloss.NewStyle().Foreground(colTextLo)
	listItemDim     = lipgloss.NewStyle().Foreground(colMuted).Italic(true)
	listItemSelBG   = lipgloss.NewStyle().Background(colSelBG)
	detailLabel     = lipgloss.NewStyle().Foreground(colMuted).Bold(true)
	detailBody      = lipgloss.NewStyle().Foreground(colTextLo)
	detailHeading   = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	footerStyle     = lipgloss.NewStyle().Foreground(colMuted)
	footerKeyStyle  = lipgloss.NewStyle().Foreground(colTextLo).Bold(true)
	searchPromptSty = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	flashStyle      = lipgloss.NewStyle().Foreground(colTextHi).Background(colAccent).Bold(true).Padding(0, 1)
	panelBorder     = lipgloss.NewStyle().BorderStyle(lipgloss.RoundedBorder()).BorderForeground(colSubtle)
	emptyHintStyle  = lipgloss.NewStyle().Foreground(colMuted).Italic(true).Padding(1, 2)
)

// severityColor returns the bar / chip colour for a severity string.
func severityColor(sev string) lipgloss.Color {
	switch sev {
	case auditcore.SeverityCritical:
		return colCritical
	case auditcore.SeverityHigh:
		return colHigh
	case auditcore.SeverityWarning:
		return colWarning
	case auditcore.SeverityInfo:
		return colInfo
	default:
		return colMuted
	}
}

// severityChip renders a compact filled pill for a severity, reusing the
// global output palette so colours stay consistent across CLI and TUI.
func severityChip(sev string) string {
	return output.SeverityChip(sev)
}

// severityChipShort is the 4-char variant used in the list rows so each
// finding has room for the title rather than the chip. Same colour
// palette as the full chip — just compressed.
func severityChipShort(sev string) string {
	short := "INFO"
	switch sev {
	case auditcore.SeverityCritical:
		short = "CRIT"
	case auditcore.SeverityHigh:
		short = "HIGH"
	case auditcore.SeverityWarning:
		short = "WARN"
	case auditcore.SeverityInfo:
		short = "INFO"
	}
	bg := severityColor(sev)
	fg := colTextHi
	if sev == auditcore.SeverityWarning {
		fg = lipgloss.Color("16")
	}
	return lipgloss.NewStyle().Foreground(fg).Background(bg).Bold(true).Render(" " + short + " ")
}

// severityBar renders the left gutter glyph for a finding row.
func severityBar(sev string, selected bool) string {
	c := severityColor(sev)
	bar := "▎"
	if selected {
		bar = "▌"
	}
	return lipgloss.NewStyle().Foreground(c).Bold(true).Render(bar)
}
