package output

import (
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-isatty"
)

var (
	// Success styles positive feedback.
	Success = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	// Warning styles cautionary feedback.
	Warning = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	// Error styles failure feedback.
	Error = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	// Info styles neutral informational feedback.
	Info = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	// Dim styles low-emphasis text.
	Dim = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

var (
	cfgNoColor   bool
	cfgQuiet     bool
	isTerminalFn = func() bool { return isatty.IsTerminal(os.Stdout.Fd()) }
)

// Configure sets the global output mode. Call once at program startup.
func Configure(noColor, quiet bool) {
	cfgNoColor = noColor
	cfgQuiet = quiet
	refreshStyles()
}

// ForceStyledForTesting bypasses TTY detection and pretends stdout is a
// terminal so styled output renders even from go test. Reserved for the
// design showcase and a handful of golden tests — production code paths
// must not call it.
func ForceStyledForTesting() {
	isTerminalFn = func() bool { return true }
	cfgNoColor = false
	cfgQuiet = false
	refreshStyles()
}

// Enabled reports whether styled (color/ANSI) output should be emitted.
// It returns false when any of the following are true:
//   - --no-color was passed
//   - --quiet/-q was passed
//   - NO_COLOR environment variable is set (non-empty)
//   - stdout is not a terminal (TTY)
func Enabled() bool {
	if cfgQuiet || cfgNoColor {
		return false
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isTerminalFn()
}

// IsQuiet reports whether quiet mode is active.
func IsQuiet() bool {
	return cfgQuiet
}

func refreshStyles() {
	if Enabled() {
		Success = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
		Warning = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
		Error = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
		Info = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
		Dim = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	} else {
		Success = lipgloss.NewStyle()
		Warning = lipgloss.NewStyle()
		Error = lipgloss.NewStyle()
		Info = lipgloss.NewStyle()
		Dim = lipgloss.NewStyle()
	}
}

// symbolMap holds the rich and ASCII fallbacks for common glyphs.
var symbolMap = map[string][2]string{
	"check":   {"✓", "[OK]"},
	"cross":   {"✗", "[FAIL]"},
	"arrow":   {"→", "->"},
	"bullet":  {"▸", ">"},
	"diamond": {"◆", "#"},
	"warning": {"⚠", "[WARN]"},
	"phase":   {"⏵", ">"},
}

// Symbol returns the styled or ASCII version of a named symbol.
// When styles are enabled the rich glyph is returned; otherwise the
// ASCII fallback is used.
func Symbol(name string) string {
	m, ok := symbolMap[name]
	if !ok {
		return name
	}
	if Enabled() {
		return m[0]
	}
	return m[1]
}
