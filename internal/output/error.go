package output

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ErrorDetail holds the pieces of a structured error message.
type ErrorDetail struct {
	What   string // What went wrong (required)
	Why    string // Why it went wrong (required)
	Fix    string // What to do about it (required)
	Code   string // Optional machine-readable error code
	DocURL string // Optional link to documentation
}

// RenderError builds the structured error block: a red left-rule gutter
// + ERROR chip + bold What headline, dim "why" line with arrow, and a
// success-coloured fix line. Mirrors the design language of finding
// cards so users learn one visual pattern across the CLI.
func RenderError(e ErrorDetail) string {
	var sb strings.Builder

	red := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	gutter := red.Render("▎ ")
	if !Enabled() {
		gutter = "  "
	}

	// Title row: gutter + chip + bold "What"
	chip := Chip("ERROR", lipgloss.Color("231"), lipgloss.Color("124"))
	what := e.What
	if Enabled() {
		what = lipgloss.NewStyle().Bold(true).Render(what)
	}
	sb.WriteString(gutter + chip + "  " + what + "\n")

	// Optional code on its own dim row, indented under the title.
	if e.Code != "" {
		sb.WriteString(gutter + "  " + Dim.Render(e.Code) + "\n")
	}

	// Blank separator line keeps the block from feeling crammed.
	sb.WriteString(gutter + "\n")

	if e.Why != "" {
		sb.WriteString(gutter + "  " + Dim.Render(Symbol("arrow")+" ") + e.Why + "\n")
	}
	if e.Fix != "" {
		green := lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
		marker := Symbol("bullet")
		if Enabled() {
			marker = green.Render(marker)
		}
		sb.WriteString(gutter + "  " + marker + " " + e.Fix + "\n")
	}
	if e.DocURL != "" {
		sb.WriteString(gutter + "\n")
		sb.WriteString(gutter + "  " + Dim.Render("learn more · ") + Hyperlink(e.DocURL, e.DocURL) + "\n")
	}

	return sb.String()
}

// RenderErrorCompact returns a single-line error suitable for logs or quiet mode.
func RenderErrorCompact(e ErrorDetail) string {
	var parts []string
	if e.Code != "" {
		parts = append(parts, fmt.Sprintf("[%s]", e.Code))
	}
	parts = append(parts, e.What)
	return strings.Join(parts, " ")
}
