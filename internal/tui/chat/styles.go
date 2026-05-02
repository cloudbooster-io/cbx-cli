package chat

import "github.com/charmbracelet/lipgloss"

var (
	// HeaderStyle is used for turn headers and section titles.
	HeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))

	// UserMessageStyle styles user inputs in the viewport.
	UserMessageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))

	// AssistantMessageStyle styles assistant responses.
	AssistantMessageStyle = lipgloss.NewStyle()

	// PaletteStyle styles the slash-command palette.
	PaletteStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))

	// PaletteSelectedStyle highlights the selected palette item.
	PaletteSelectedStyle = lipgloss.NewStyle().Background(lipgloss.Color("7")).Foreground(lipgloss.Color("0"))

	// StatusBarStyle styles the bottom status bar.
	StatusBarStyle = lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("250"))

	// ErrorStyle styles error messages.
	ErrorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)
