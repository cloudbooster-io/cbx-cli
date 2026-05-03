package audit

import (
	auditcore "gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit"

	"github.com/charmbracelet/lipgloss"
)

var (
	// SeverityCriticalStyle styles critical severity findings.
	SeverityCriticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	// SeverityHighStyle styles high severity findings.
	SeverityHighStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	// SeverityWarningStyle styles warning severity findings.
	SeverityWarningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	// SeverityInfoStyle styles info severity findings.
	SeverityInfoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))

	// SelectedStyle highlights the current list item.
	SelectedStyle = lipgloss.NewStyle().Background(lipgloss.Color("7")).Foreground(lipgloss.Color("0"))

	// HeaderStyle styles the top header bar.
	HeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))

	// DimStyle styles low-emphasis text.
	DimStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))

	// HelpStyle styles the help text.
	HelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))

	// DetailLabelStyle styles labels in the detail view.
	DetailLabelStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("250"))
)

// SeverityStyle returns the lipgloss.Style for the given severity string.
func SeverityStyle(sev string) lipgloss.Style {
	switch sev {
	case auditcore.SeverityCritical:
		return SeverityCriticalStyle
	case auditcore.SeverityHigh:
		return SeverityHighStyle
	case auditcore.SeverityWarning:
		return SeverityWarningStyle
	case auditcore.SeverityInfo:
		return SeverityInfoStyle
	default:
		return DimStyle
	}
}

// SeverityBadge returns a styled severity badge string.
func SeverityBadge(sev string) string {
	return SeverityStyle(sev).Render(" " + sev + " ")
}
