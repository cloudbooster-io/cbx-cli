package output

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Chip renders a short label with a coloured background. Used for severity
// pills, status flags, and resource-type tags. The label is uppercased
// because chips read like badges; use RawChip when the caller wants to
// preserve case (e.g. a version string). On plain output the chip
// degrades to `[LABEL]` so it still parses visually in logs.
func Chip(label string, fg, bg lipgloss.Color) string {
	return chipWith(strings.ToUpper(label), fg, bg)
}

// RawChip is Chip but preserves the caller's casing. Useful for version
// strings, model identifiers, and other content where uppercase would
// distort meaning.
func RawChip(label string, fg, bg lipgloss.Color) string {
	return chipWith(label, fg, bg)
}

func chipWith(label string, fg, bg lipgloss.Color) string {
	label = " " + label + " "
	if !Enabled() {
		return "[" + strings.TrimSpace(label) + "]"
	}
	return lipgloss.NewStyle().
		Foreground(fg).
		Background(bg).
		Bold(true).
		Render(label)
}

// Severity chip colours. Background-only chips read at a glance the way
// a fire-alarm sticker does — critical jumps out before the title is parsed.
var (
	chipCriticalFG = lipgloss.Color("231") // near-white
	chipCriticalBG = lipgloss.Color("124") // deep red
	chipHighFG     = lipgloss.Color("231")
	chipHighBG     = lipgloss.Color("166") // burnt orange
	chipWarningFG  = lipgloss.Color("16")  // near-black, for contrast on yellow
	chipWarningBG  = lipgloss.Color("220") // yellow
	chipInfoFG     = lipgloss.Color("231")
	chipInfoBG     = lipgloss.Color("39") // bright blue
)

// SeverityChip returns a coloured pill for the canonical severity strings
// (critical / high / warning / info). Unknown values fall through to the
// info palette so the caller never crashes on a typo.
func SeverityChip(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return Chip("CRITICAL", chipCriticalFG, chipCriticalBG)
	case "high":
		return Chip("HIGH", chipHighFG, chipHighBG)
	case "warning", "warn", "medium":
		return Chip("WARNING", chipWarningFG, chipWarningBG)
	default:
		return Chip("INFO", chipInfoFG, chipInfoBG)
	}
}

// SeverityBarStyle returns a lipgloss style preloaded with the gutter colour
// for a severity. Used by Card to paint the left rule beside a finding.
func SeverityBarStyle(sev string) lipgloss.Style {
	if !Enabled() {
		return lipgloss.NewStyle()
	}
	switch strings.ToLower(sev) {
	case "critical":
		return lipgloss.NewStyle().Foreground(chipCriticalBG)
	case "high":
		return lipgloss.NewStyle().Foreground(chipHighBG)
	case "warning", "warn", "medium":
		return lipgloss.NewStyle().Foreground(chipWarningBG)
	default:
		return lipgloss.NewStyle().Foreground(chipInfoBG)
	}
}
