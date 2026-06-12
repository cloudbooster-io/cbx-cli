package output

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// FindingBlock renders one audit finding using a coloured left gutter
// (severity colour), a chip + bold title row, a resource chip line, and
// a reflowed remediation paragraph. ruleID and (optional) suggested
// command are rendered dim at the bottom of the block.
type FindingBlock struct {
	Severity    string // "critical" | "high" | "warning" | "info"
	Title       string
	ResourceURN string
	Remediation string
	RuleID      string
	HintCmd     string // optional — a suggested follow-up command
	ReportLink  string // optional — file:// URL or http link
	Width       int    // 0 means TerminalWidth
}

// Render returns the multi-line block. Always ends in a blank line so
// successive findings spaced cleanly.
func (b *FindingBlock) Render() string {
	width := b.Width
	if width <= 0 {
		width = TerminalWidth()
	}

	gutter := SeverityBarStyle(b.Severity).Render("▎ ")
	indent := SeverityBarStyle(b.Severity).Render("▎ ") + "  "
	plainIndent := "      "

	if !Enabled() {
		gutter = "  "
		indent = "    "
		plainIndent = "    "
	}

	titleStyle := lipgloss.NewStyle().Bold(true)
	if !Enabled() {
		titleStyle = lipgloss.NewStyle()
	}

	var sb strings.Builder

	// Title row: gutter + chip + title
	titleLine := gutter + SeverityChip(b.Severity) + "  " + titleStyle.Render(b.Title)
	sb.WriteString(titleLine)
	sb.WriteString("\n")

	// Resource chip
	if b.ResourceURN != "" {
		resChip := RenderResourceChip(b.ResourceURN, width-lipgloss.Width(indent))
		sb.WriteString(indent + resChip)
		sb.WriteString("\n")
	}

	// Blank separator
	sb.WriteString(gutter)
	sb.WriteString("\n")

	// Remediation paragraph (wrapped)
	if b.Remediation != "" {
		para := ReflowParagraph(b.Remediation, width, plainIndent)
		// Replace the plain indent with the styled gutter+indent on each line
		for i, line := range strings.Split(para, "\n") {
			if i > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(gutter + "  " + strings.TrimPrefix(line, plainIndent))
		}
		sb.WriteString("\n")
	}

	// Trailing meta (ruleID + hint)
	if b.RuleID != "" || b.HintCmd != "" || b.ReportLink != "" {
		sb.WriteString(gutter)
		sb.WriteString("\n")
		meta := []string{}
		if b.RuleID != "" {
			meta = append(meta, Dim.Render("rule "+b.RuleID))
		}
		if b.HintCmd != "" {
			meta = append(meta, Dim.Render("→ ")+b.HintCmd)
		}
		if b.ReportLink != "" {
			meta = append(meta, Hyperlink(Dim.Render("open report"), b.ReportLink))
		}
		sep := Dim.Render("  ·  ")
		sb.WriteString(gutter + "  " + strings.Join(meta, sep))
		sb.WriteString("\n")
	}

	return sb.String()
}
