package aws

import (
	"context"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// PromptForRegions runs an interactive region picker. Returns the
// user-selected region list, or an error if the user aborted or the TTY
// is unavailable.
//
// The picker shows enabled regions plus an "all enabled regions" sentinel.
// Caller is responsible for first confirming a TTY is present — this
// function will hang if stdin/stdout aren't terminals.
func PromptForRegions(ctx context.Context, enabled []string, in io.Reader, out io.Writer) ([]string, error) {
	if len(enabled) == 0 {
		return nil, fmt.Errorf("no enabled regions to choose from")
	}

	model := newRegionPicker(enabled)
	prog := tea.NewProgram(model, tea.WithInput(in), tea.WithOutput(out))

	final, err := prog.Run()
	if err != nil {
		return nil, fmt.Errorf("region picker: %w", err)
	}
	picker := final.(regionPicker)
	if picker.aborted {
		return nil, fmt.Errorf("region selection aborted")
	}
	if picker.selectAll {
		return []string{regionsLiteralAll}, nil
	}
	if len(picker.selected) == 0 {
		return nil, fmt.Errorf("no regions selected")
	}
	return picker.selected, nil
}

// regionPicker is a minimal Bubble Tea list with checkbox-style multi-select
// plus a top-of-list "all enabled regions" item. Single-region default
// behaviour: user can press Enter without toggling anything to take the
// first item in the list (the "all" sentinel sits at index 0, so the
// default is "all" — match the user's intent when they explicitly chose
// to be prompted rather than pass --regions).
type regionPicker struct {
	regions   []string
	cursor    int
	selected  []string
	selectAll bool
	aborted   bool
	confirmed bool
}

func newRegionPicker(enabled []string) regionPicker {
	return regionPicker{regions: enabled}
}

func (m regionPicker) Init() tea.Cmd { return nil }

func (m regionPicker) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc", "q":
			m.aborted = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.regions) { // +1 for the "all" row
				m.cursor++
			}
		case " ":
			if m.cursor == 0 {
				m.selectAll = !m.selectAll
				if m.selectAll {
					m.selected = nil
				}
			} else {
				if m.selectAll {
					m.selectAll = false
				}
				m.toggleAt(m.cursor - 1)
			}
		case "a":
			m.selectAll = true
			m.selected = nil
		case "enter":
			m.confirmed = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *regionPicker) toggleAt(i int) {
	region := m.regions[i]
	for idx, r := range m.selected {
		if r == region {
			m.selected = append(m.selected[:idx], m.selected[idx+1:]...)
			return
		}
	}
	m.selected = append(m.selected, region)
}

func (m regionPicker) isSelected(region string) bool {
	for _, r := range m.selected {
		if r == region {
			return true
		}
	}
	return false
}

var (
	pickerHeader = lipgloss.NewStyle().Bold(true).Render
	pickerCursor = lipgloss.NewStyle().Foreground(lipgloss.Color("212")).Render
	pickerDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render
)

func (m regionPicker) View() string {
	var b []byte
	b = append(b, pickerHeader("? Profile has no default region. Select regions to audit:")...)
	b = append(b, '\n')

	// "all" row at index 0
	rowAll := "  [ ] all enabled regions"
	if m.selectAll {
		rowAll = "  [x] all enabled regions"
	}
	if m.cursor == 0 {
		rowAll = pickerCursor("›") + rowAll[1:]
	}
	b = append(b, rowAll...)
	b = append(b, '\n')

	for i, r := range m.regions {
		mark := " "
		if m.isSelected(r) {
			mark = "x"
		}
		row := fmt.Sprintf("  [%s] %s", mark, r)
		if m.cursor == i+1 {
			row = pickerCursor("›") + row[1:]
		}
		b = append(b, row...)
		b = append(b, '\n')
	}

	b = append(b, '\n')
	b = append(b, pickerDim("  ↑/↓ move · space toggle · a select-all · enter confirm · esc cancel")...)
	b = append(b, '\n')
	return string(b)
}
