package output

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// TerminalWidth returns the current stdout terminal width clamped to a
// sane minimum/maximum. Used by the card and reflow helpers so a tiny
// 60-col terminal still renders without overflow.
func TerminalWidth() int {
	w, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || w <= 0 {
		return 100
	}
	if w < 60 {
		return 60
	}
	if w > 120 {
		return 120
	}
	return w
}

// Card is a labelled rounded-border box used for the audit header,
// advisories, and similar grouped content. Findings use a lighter-weight
// "rule" layout (see FindingBlock) so they don't each draw a heavy box.
type Card struct {
	Title  string         // optional — printed in the top border slot
	Label  string         // optional — small chip-like tag rendered before Title
	Width  int            // 0 means auto-fit to TerminalWidth
	Rows   []CardRow      // ordered key/value rows
	Footer string         // optional — single dim line under the rows
	Border lipgloss.Color // optional override; defaults to a dim grey
}

// CardRow is a single key/value pair in a Card body. Either side may be
// pre-styled by the caller. Empty keys render as full-width body lines.
type CardRow struct {
	Key   string
	Value string
}

// AddRow is a convenience appender so call sites don't have to assemble
// CardRow literals inline.
func (c *Card) AddRow(key, value string) {
	c.Rows = append(c.Rows, CardRow{Key: key, Value: value})
}

// Render returns the multi-line card as a string. When styled output is
// disabled the card collapses to plain `key: value` lines with a single
// blank line above/below — still readable in logs and CI.
func (c *Card) Render() string {
	width := c.Width
	if width <= 0 {
		width = TerminalWidth()
	}

	if !Enabled() {
		return c.renderPlain()
	}

	border := c.Border
	if border == "" {
		border = lipgloss.Color("240")
	}
	bs := lipgloss.NewStyle().Foreground(border)

	// Compute the key column width so all values line up.
	keyW := 0
	for _, r := range c.Rows {
		if r.Key == "" {
			continue
		}
		if w := lipgloss.Width(r.Key); w > keyW {
			keyW = w
		}
	}
	if keyW > 0 {
		keyW += 2 // gap between key and value
	}

	// Top border: ╭─ title ─...─╮
	titleSegment := ""
	if c.Title != "" || c.Label != "" {
		parts := []string{}
		if c.Label != "" {
			parts = append(parts, c.Label)
		}
		if c.Title != "" {
			parts = append(parts, lipgloss.NewStyle().Bold(true).Render(c.Title))
		}
		titleSegment = " " + strings.Join(parts, " ") + " "
	}
	titleVisible := lipgloss.Width(titleSegment)
	// 2 chars for ╭─ and ─╮ corners, plus title segment
	fillLen := width - 4 - titleVisible
	if fillLen < 0 {
		fillLen = 0
	}
	top := bs.Render("╭─") + titleSegment + bs.Render(strings.Repeat("─", fillLen)+"─╮")

	var sb strings.Builder
	sb.WriteString(top)
	sb.WriteString("\n")

	// Body rows
	innerW := width - 4 // 2 for left "│ ", 2 for trailing " │"
	for _, r := range c.Rows {
		var line string
		if r.Key == "" {
			line = r.Value
		} else {
			key := Dim.Render(padRight(r.Key, keyW-2))
			line = key + "  " + r.Value
		}
		visible := lipgloss.Width(line)
		pad := innerW - visible
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(bs.Render("│ "))
		sb.WriteString(line)
		sb.WriteString(strings.Repeat(" ", pad))
		sb.WriteString(bs.Render(" │"))
		sb.WriteString("\n")
	}

	if c.Footer != "" {
		// Blank separator + dim footer line
		blankLine := bs.Render("│ ") + strings.Repeat(" ", innerW) + bs.Render(" │")
		sb.WriteString(blankLine)
		sb.WriteString("\n")
		footer := Dim.Render(c.Footer)
		visible := lipgloss.Width(footer)
		pad := innerW - visible
		if pad < 0 {
			pad = 0
		}
		sb.WriteString(bs.Render("│ "))
		sb.WriteString(footer)
		sb.WriteString(strings.Repeat(" ", pad))
		sb.WriteString(bs.Render(" │"))
		sb.WriteString("\n")
	}

	// Bottom border
	sb.WriteString(bs.Render("╰" + strings.Repeat("─", width-2) + "╯"))
	sb.WriteString("\n")
	return sb.String()
}

func (c *Card) renderPlain() string {
	var sb strings.Builder
	if c.Title != "" {
		sb.WriteString(c.Title)
		sb.WriteString("\n")
	}
	for _, r := range c.Rows {
		if r.Key == "" {
			sb.WriteString("  ")
			sb.WriteString(r.Value)
		} else {
			sb.WriteString("  ")
			sb.WriteString(r.Key)
			sb.WriteString(": ")
			sb.WriteString(r.Value)
		}
		sb.WriteString("\n")
	}
	if c.Footer != "" {
		sb.WriteString("  ")
		sb.WriteString(c.Footer)
		sb.WriteString("\n")
	}
	return sb.String()
}

// padRight pads s with spaces on the right to width. width is measured in
// lipgloss visible cells so pre-styled values pad correctly.
func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// ReflowParagraph wraps text to width on word boundaries. Each output line
// is prefixed with `indent`. Width includes the indent — content reflows to
// `width - len(indent)` columns. Empty text returns "".
func ReflowParagraph(text string, width int, indent string) string {
	if text == "" {
		return ""
	}
	if width <= 0 {
		width = TerminalWidth()
	}
	contentW := width - lipgloss.Width(indent)
	if contentW < 20 {
		contentW = 20
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var sb strings.Builder
	line := indent
	lineLen := 0
	first := true
	for _, w := range words {
		ww := lipgloss.Width(w)
		if !first && lineLen+1+ww > contentW {
			sb.WriteString(line)
			sb.WriteString("\n")
			line = indent + w
			lineLen = ww
			continue
		}
		if first {
			line += w
			lineLen = ww
			first = false
		} else {
			line += " " + w
			lineLen += 1 + ww
		}
	}
	if line != indent {
		sb.WriteString(line)
	}
	return sb.String()
}
