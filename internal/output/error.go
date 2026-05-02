package output

import (
	"fmt"
	"strings"
)

// ErrorDetail holds the pieces of a structured error message.
type ErrorDetail struct {
	What   string // What went wrong (required)
	Why    string // Why it went wrong (required)
	Fix    string // What to do about it (required)
	Code   string // Optional machine-readable error code
	DocURL string // Optional link to documentation
}

// RenderError returns the three-line formatted error string.
//   Line 1: Error: <What>  (with optional code in parens)
//   Line 2:   → <Why>
//   Line 3:   ▸ <Fix>
//   Line 4:   Learn more: <DocURL>  (optional)
func RenderError(e ErrorDetail) string {
	var sb strings.Builder

	prefix := Error.Render("Error")
	if e.Code != "" {
		prefix = fmt.Sprintf("%s %s", prefix, Dim.Render(fmt.Sprintf("(%s)", e.Code)))
	}
	sb.WriteString(fmt.Sprintf("%s: %s\n", prefix, e.What))
	sb.WriteString(fmt.Sprintf("  %s %s\n", Symbol("arrow"), e.Why))
	sb.WriteString(fmt.Sprintf("  %s %s\n", Symbol("bullet"), e.Fix))
	if e.DocURL != "" {
		sb.WriteString(fmt.Sprintf("\n  %s %s\n", Dim.Render("Learn more:"), e.DocURL))
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
