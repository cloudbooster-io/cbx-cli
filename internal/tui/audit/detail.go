package audit

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	auditcore "github.com/cloudbooster-io/cbx-cli/internal/audit"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// renderDetailBody returns the full text shown in the detail viewport
// for the given finding. The viewport handles vertical scrolling so the
// renderer doesn't need to clip — it just lays out the sections.
func renderDetailBody(f *auditcore.Finding, width int) string {
	if f == nil {
		return emptyHintStyle.Render("Select a finding to see details.")
	}
	if width < 20 {
		width = 20
	}

	// Header: severity chip + rule id, title underneath.
	chip := severityChip(f.Severity)
	rule := lipgloss.NewStyle().Foreground(colMuted).Render(f.RuleID)
	header := chip + "  " + rule
	title := detailHeading.Render(wrapWords(f.Title, width))

	rows := []string{header, title, ""}

	rows = append(rows, fieldRow("Resource", prettyResource(*f), width))
	rows = append(rows, fieldRow("Service ", f.Service, width))
	if f.File != "" {
		rows = append(rows, fieldRow("Source  ", fmt.Sprintf("%s:%d", f.File, f.Line), width))
	}
	rows = append(rows, "")

	rows = append(rows, sectionHeading("Description"))
	rows = append(rows, detailBody.Render(wrapWords(f.Description, width)))
	rows = append(rows, "")

	rows = append(rows, sectionHeading("Remediation"))
	rows = append(rows, detailBody.Render(wrapWords(f.Remediation, width)))

	if f.CBSource != nil && (f.CBSource.Tool != "" || f.CBSource.Key != "" || f.CBSource.Snippet != "") {
		rows = append(rows, "")
		rows = append(rows, sectionHeading("CB knowledge"))
		if f.CBSource.Tool != "" {
			rows = append(rows, fieldRow("tool", f.CBSource.Tool, width))
		}
		if f.CBSource.Key != "" {
			rows = append(rows, fieldRow("key ", f.CBSource.Key, width))
		}
		if f.CBSource.Snippet != "" {
			rows = append(rows, detailBody.Render(wrapWords("\""+f.CBSource.Snippet+"\"", width)))
		}
	}

	return strings.Join(rows, "\n")
}

func fieldRow(label, value string, width int) string {
	lbl := detailLabel.Render(label + ": ")
	room := width - lipgloss.Width(lbl)
	if room < 8 {
		room = 8
	}
	return lbl + detailBody.Render(wrapHanging(value, room, len(label)+2))
}

func sectionHeading(label string) string {
	return detailHeading.Render(label)
}

// prettyResource turns a raw URN into the "kind · name · region" form
// used everywhere else in the audit output. Returns the raw resource
// unchanged when the URN isn't recognisable, so non-AWS findings still
// display their identifier verbatim.
func prettyResource(f auditcore.Finding) string {
	p := output.ParseURN(f.Resource)
	if p.Service == "" && p.Kind == "" && p.Name == "" {
		return f.Resource
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
	return strings.Join(bits, " · ")
}

// wrapWords is a small word wrap that respects byte length (we don't
// expect CJK in finding text). Existing newlines are preserved.
func wrapWords(s string, width int) string {
	if width <= 1 {
		return s
	}
	var out []string
	for _, paragraph := range strings.Split(s, "\n") {
		out = append(out, wrapOne(paragraph, width))
	}
	return strings.Join(out, "\n")
}

func wrapOne(s string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		wl := len(w)
		if i == 0 {
			b.WriteString(w)
			lineLen = wl
			continue
		}
		if lineLen+1+wl > width {
			b.WriteString("\n")
			b.WriteString(w)
			lineLen = wl
		} else {
			b.WriteString(" ")
			b.WriteString(w)
			lineLen += 1 + wl
		}
	}
	return b.String()
}

// wrapHanging wraps text with a hanging indent so continuation lines
// align under the value column (past the field label).
func wrapHanging(s string, width, indent int) string {
	wrapped := wrapOne(s, width)
	if !strings.Contains(wrapped, "\n") {
		return wrapped
	}
	pad := strings.Repeat(" ", indent)
	lines := strings.Split(wrapped, "\n")
	for i := 1; i < len(lines); i++ {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}
