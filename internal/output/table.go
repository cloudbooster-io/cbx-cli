package output

import (
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/term"
)

// Default table layout constants.
const (
	defaultMinColWidth = 4
	defaultTableWidth  = 80
	colPadding         = 2
)

// Table renders rows with auto-fitting columns.
type Table struct {
	Headers []string
	Rows    [][]string
}

// NewTable creates a Table with the given headers.
func NewTable(headers []string) *Table {
	return &Table{Headers: headers}
}

// AddRow appends a row to the table.
func (t *Table) AddRow(cells ...string) {
	t.Rows = append(t.Rows, cells)
}

// Render returns the formatted table string.
func (t *Table) Render() string {
	if len(t.Headers) == 0 {
		return ""
	}

	cols := len(t.Headers)
	widths := make([]int, cols)

	// Natural widths from headers.
	for i, h := range t.Headers {
		widths[i] = lipgloss.Width(h)
	}

	// Natural widths from rows.
	for _, row := range t.Rows {
		for i := 0; i < cols && i < len(row); i++ {
			w := lipgloss.Width(row[i])
			if w > widths[i] {
				widths[i] = w
			}
		}
	}

	// Terminal width constraint.
	termW, _, err := term.GetSize(os.Stdout.Fd())
	if err != nil || termW <= 0 {
		termW = defaultTableWidth
	}

	// Account for padding between columns.
	paddingTotal := (cols - 1) * colPadding
	naturalTotal := sum(widths) + paddingTotal

	if naturalTotal > termW {
		// Shrink columns proportionally, respecting minimum width.
		available := termW - paddingTotal
		if available < cols*defaultMinColWidth {
			available = cols * defaultMinColWidth
		}
		scaleCols(widths, available)
	}

	var sb strings.Builder

	// Header row.
	headerStyle := lipgloss.NewStyle().Bold(true)
	if !Enabled() {
		headerStyle = lipgloss.NewStyle()
	}
	for i, h := range t.Headers {
		cell := truncate(h, widths[i])
		if i > 0 {
			sb.WriteString(strings.Repeat(" ", colPadding))
		}
		sb.WriteString(headerStyle.Render(cell))
		// Pad to column width so subsequent columns align.
		pad := widths[i] - lipgloss.Width(cell)
		if pad > 0 {
			sb.WriteString(strings.Repeat(" ", pad))
		}
	}
	sb.WriteString("\n")

	// Separator line.
	for i := 0; i < cols; i++ {
		if i > 0 {
			sb.WriteString(strings.Repeat(" ", colPadding))
		}
		sb.WriteString(strings.Repeat("-", widths[i]))
	}
	sb.WriteString("\n")

	// Data rows.
	for _, row := range t.Rows {
		for i := 0; i < cols; i++ {
			var cell string
			if i < len(row) {
				cell = row[i]
			}
			cell = truncate(cell, widths[i])
			if i > 0 {
				sb.WriteString(strings.Repeat(" ", colPadding))
			}
			sb.WriteString(cell)
			pad := widths[i] - lipgloss.Width(cell)
			if pad > 0 {
				sb.WriteString(strings.Repeat(" ", pad))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func sum(vals []int) int {
	s := 0
	for _, v := range vals {
		s += v
	}
	return s
}

// scaleCols shrinks each column proportionally so the total fits into available.
func scaleCols(widths []int, available int) {
	total := sum(widths)
	cols := len(widths)
	minTotal := cols * defaultMinColWidth

	if total <= available {
		return
	}

	// Save original widths for proportional calculations in the second pass.
	original := make([]int, cols)
	copy(original, widths)

	// First pass: proportional scaling.
	remaining := available
	for i := range widths {
		scaled := int(float64(widths[i]) * float64(available) / float64(total))
		if scaled < defaultMinColWidth {
			scaled = defaultMinColWidth
		}
		widths[i] = scaled
		remaining -= scaled
	}

	// Distribute any leftover space to columns that can grow.
	for remaining > 0 {
		changed := false
		for i := range widths {
			maxW := int(float64(original[i])*float64(available)/float64(total)) + 1
			if widths[i] < maxW {
				widths[i]++
				remaining--
				changed = true
				if remaining == 0 {
					break
				}
			}
		}
		if !changed {
			break
		}
	}

	// If we still overflow, clip from the rightmost columns.
	if sum(widths) > available {
		for i := cols - 1; i >= 0 && sum(widths) > available; i-- {
			for widths[i] > defaultMinColWidth && sum(widths) > available {
				widths[i]--
			}
		}
	}

	// Ensure minimum total is respected if available was too small.
	if sum(widths) < minTotal && available >= minTotal {
		extra := available - sum(widths)
		for i := range widths {
			add := extra / cols
			if i < extra%cols {
				add++
			}
			widths[i] += add
		}
	}
}

// truncate shortens s to fit within maxWidth, adding "..." when truncated.
func truncate(s string, maxWidth int) string {
	if maxWidth <= 0 {
		return ""
	}
	w := lipgloss.Width(s)
	if w <= maxWidth {
		return s
	}
	if maxWidth <= 3 {
		return strings.Repeat(".", maxWidth)
	}
	// Find the byte index where we should cut.
	runes := []rune(s)
	length := 0
	cut := 0
	for i, r := range runes {
		rw := lipgloss.Width(string(r))
		if length+rw > maxWidth-3 {
			cut = i
			break
		}
		length += rw
		cut = i + 1
	}
	return string(runes[:cut]) + "..."
}
